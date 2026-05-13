#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import socket
import ssl
import statistics
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from rich.console import Console
from rich.table import Table


VALID_DEFAULT_STATUSES = {200, 204, 301, 302, 307, 308, 403}
ERROR_OK = "OK"
ERROR_DNS = "DNS_FAIL"
ERROR_TCP = "TCP_FAIL"
ERROR_TIMEOUT = "TIMEOUT"
ERROR_SSL = "SSL_FAIL"
ERROR_HTTP = "HTTP_FAIL"
IPINFO_SERVICES = (
    "https://ipinfo.io/json",
    "https://ifconfig.co/json",
)


@dataclass(frozen=True)
class Target:
    name: str
    category: str
    url: str
    host: str
    port: int = 443
    method: str = "HEAD"
    expected_statuses: tuple[int, ...] = tuple(VALID_DEFAULT_STATUSES)


@dataclass
class CheckResult:
    category: str
    service: str
    url: str
    host: str
    port: int
    ip_version: str
    dns: bool
    tcp: bool
    http: bool
    status_code: int | None
    response_time_ms: float | None
    error: str
    resolved_ips: list[str]

    @property
    def ok(self) -> bool:
        return self.dns and self.tcp and self.http and self.error == ERROR_OK


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check whether a VPS can reach popular VPN-relevant services."
    )
    parser.add_argument("--targets", default="targets.yaml", help="Path to targets YAML file.")
    parser.add_argument("--json", dest="json_path", help="Save full report to JSON file.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout per network step in seconds.")
    parser.add_argument("--concurrency", type=int, default=25, help="Maximum concurrent target checks.")
    parser.add_argument("--category", help="Check only one category from targets.yaml.")
    parser.add_argument("--ipv4-only", action="store_true", help="Check only IPv4.")
    parser.add_argument("--ipv6-only", action="store_true", help="Check only IPv6.")
    parser.add_argument("--verbose", action="store_true", help="Show extra diagnostics.")
    parser.add_argument("--short", action="store_true", help="Show only VPS info, summary, and failures.")
    parser.add_argument("--fail-only", action="store_true", help="Show only failed checks in the table.")
    return parser.parse_args()


def load_targets(path: Path, category: str | None) -> list[Target]:
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("targets.yaml must contain a list of targets")

    targets: list[Target] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Target #{index} must be a mapping")
        try:
            target = Target(
                name=str(item["name"]),
                category=str(item["category"]),
                url=str(item["url"]),
                host=str(item.get("host") or urlparse(str(item["url"])).hostname),
                port=int(item.get("port", 443)),
                method=str(item.get("method", "HEAD")).upper(),
                expected_statuses=tuple(int(code) for code in item.get("expected_statuses", VALID_DEFAULT_STATUSES)),
            )
        except KeyError as exc:
            raise ValueError(f"Target #{index} is missing required field: {exc}") from exc
        if category is None or target.category == category:
            targets.append(target)
    return targets


async def get_json(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


async def get_text(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        response = await client.get(url)
        response.raise_for_status()
        return response.text.strip()
    except Exception:
        return None


async def get_text_with_local_address(url: str, local_address: str, timeout: float) -> str | None:
    transport = httpx.AsyncHTTPTransport(local_address=local_address, retries=0)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout, connect=timeout),
        headers={"User-Agent": "vpn-vps-checker/1.0"},
    ) as client:
        return await get_text(client, url)


async def collect_vps_info(timeout: float) -> dict[str, Any]:
    info: dict[str, Any] = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "os": platform.platform(),
        "external_ipv4": None,
        "external_ipv6": None,
        "country": None,
        "city": None,
        "asn": None,
        "organization": None,
    }

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=timeout),
        headers={"User-Agent": "vpn-vps-checker/1.0"},
        follow_redirects=True,
    ) as client:
        for url in IPINFO_SERVICES:
            data = await get_json(client, url)
            if not data:
                continue
            ip = data.get("ip")
            info["external_ipv4"] = info["external_ipv4"] or (ip if ip and ":" not in str(ip) else None)
            info["country"] = info["country"] or data.get("country") or data.get("country_name")
            info["city"] = info["city"] or data.get("city")
            info["asn"] = info["asn"] or data.get("asn") or data.get("org")
            info["organization"] = info["organization"] or data.get("org") or data.get("asn_org")
            break

        info["external_ipv4"] = info["external_ipv4"] or await get_text_with_local_address(
            "https://api.ipify.org", "0.0.0.0", timeout
        )
        info["external_ipv6"] = await get_text_with_local_address(
            "https://api64.ipify.org", "::", timeout
        )
        if info["external_ipv6"] and ":" not in str(info["external_ipv6"]):
            info["external_ipv6"] = None

    return info


async def resolve_host(host: str, port: int, family: socket.AddressFamily) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for family_id, _, _, _, sockaddr in infos:
        if family_id == family:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    return ips


async def tcp_connect(ip: str, port: int, family: socket.AddressFamily, timeout: float) -> None:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        connect = asyncio.open_connection(host=ip, port=port, family=family)
        reader, writer = await asyncio.wait_for(connect, timeout=timeout)
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        del reader


async def https_request(target: Target, ip_version: str, timeout: float) -> tuple[int | None, str | None]:
    local_address = "0.0.0.0" if ip_version == "IPv4" else "::"
    transport = httpx.AsyncHTTPTransport(local_address=local_address, retries=0)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout, connect=timeout),
        follow_redirects=False,
        headers={"User-Agent": "vpn-vps-checker/1.0"},
        verify=True,
    ) as client:
        try:
            response = await client.request(target.method, target.url)
            return response.status_code, None
        except httpx.TimeoutException:
            return None, ERROR_TIMEOUT
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            if isinstance(exc.__cause__, ssl.SSLError):
                return None, ERROR_SSL
            message = str(exc).lower()
            if "ssl" in message or "certificate" in message:
                return None, ERROR_SSL
            return None, ERROR_HTTP
        except httpx.HTTPError as exc:
            message = str(exc).lower()
            if "ssl" in message or "certificate" in message:
                return None, ERROR_SSL
            return None, ERROR_HTTP


async def check_target_ip_version(target: Target, ip_version: str, timeout: float) -> CheckResult:
    family = socket.AF_INET if ip_version == "IPv4" else socket.AF_INET6
    started = time.perf_counter()

    try:
        resolved_ips = await asyncio.wait_for(resolve_host(target.host, target.port, family), timeout=timeout)
    except asyncio.TimeoutError:
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, False, False, False, None, None, ERROR_TIMEOUT, [])
    except socket.gaierror:
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, False, False, False, None, None, ERROR_DNS, [])
    except Exception:
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, False, False, False, None, None, ERROR_DNS, [])

    if not resolved_ips:
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, False, False, False, None, None, ERROR_DNS, [])

    tcp_error = ERROR_TCP
    tcp_ok = False
    for ip in resolved_ips[:3]:
        try:
            await tcp_connect(ip, target.port, family, timeout)
            tcp_ok = True
            break
        except asyncio.TimeoutError:
            tcp_error = ERROR_TIMEOUT
        except OSError:
            tcp_error = ERROR_TCP

    if not tcp_ok:
        elapsed = (time.perf_counter() - started) * 1000
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, True, False, False, None, elapsed, tcp_error, resolved_ips)

    status_code, http_error = await https_request(target, ip_version, timeout)
    elapsed = (time.perf_counter() - started) * 1000
    if http_error:
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, True, True, False, status_code, elapsed, http_error, resolved_ips)
    if status_code in target.expected_statuses:
        return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, True, True, True, status_code, elapsed, ERROR_OK, resolved_ips)
    return CheckResult(target.category, target.name, target.url, target.host, target.port, ip_version, True, True, False, status_code, elapsed, ERROR_HTTP, resolved_ips)


async def check_target(
    target: Target,
    versions: list[str],
    timeout: float,
    sem: asyncio.Semaphore,
) -> list[CheckResult]:
    async with sem:
        return await asyncio.gather(
            *(check_target_ip_version(target, version, timeout) for version in versions)
        )


def status_label(ok: bool, label: str) -> str:
    return f"[green]{label}[/green]" if ok else "[red]FAIL[/red]"


def error_label(error: str, status_code: int | None) -> str:
    if error == ERROR_OK:
        return "[green]OK[/green]"
    if error == ERROR_TIMEOUT:
        return "[yellow]TIMEOUT[/yellow]"
    if status_code == 403:
        return "[blue]OK[/blue]"
    return f"[red]{error}[/red]"


def code_label(code: int | None) -> str:
    if code is None:
        return "-"
    if code == 403:
        return "[blue]403[/blue]"
    if 200 <= code < 400:
        return f"[green]{code}[/green]"
    return f"[red]{code}[/red]"


def render_vps_info(console: Console, info: dict[str, Any]) -> None:
    table = Table(title="VPS information", show_header=True, header_style="bold cyan")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("external_ipv4", "external_ipv6", "country", "city", "asn", "organization", "hostname", "kernel", "os", "checked_at"):
        table.add_row(key, str(info.get(key) or "-"))
    console.print(table)


def render_results(console: Console, results: list[CheckResult], short: bool, fail_only: bool) -> None:
    if short:
        return
    visible = [result for result in results if not result.ok] if fail_only else results
    table = Table(title="Connectivity checks", show_header=True, header_style="bold cyan")
    table.add_column("Category")
    table.add_column("Service")
    table.add_column("DNS")
    table.add_column("TCP")
    table.add_column("HTTP")
    table.add_column("Code")
    table.add_column("Time")
    table.add_column("IP version")
    table.add_column("Error")
    for result in visible:
        table.add_row(
            result.category,
            result.service,
            status_label(result.dns, "OK"),
            status_label(result.tcp, "OK"),
            status_label(result.http, "OK"),
            code_label(result.status_code),
            f"{result.response_time_ms:.0f} ms" if result.response_time_ms is not None else "-",
            result.ip_version,
            error_label(result.error, result.status_code),
        )
    console.print(table)


def summarize(results: list[CheckResult]) -> dict[str, Any]:
    response_times = [r.response_time_ms for r in results if r.response_time_ms is not None and r.ok]
    failed = [r for r in results if not r.ok]
    return {
        "total": len(results),
        "ok": sum(1 for r in results if r.ok),
        "failed": len(failed),
        "timeout": sum(1 for r in results if r.error == ERROR_TIMEOUT),
        "dns_failed": sum(1 for r in results if r.error == ERROR_DNS),
        "tcp_failed": sum(1 for r in results if r.error == ERROR_TCP),
        "ssl_failed": sum(1 for r in results if r.error == ERROR_SSL),
        "average_response_time_ms": round(statistics.fmean(response_times), 2) if response_times else None,
        "failed_services": [
            {
                "category": r.category,
                "service": r.service,
                "ip_version": r.ip_version,
                "error": r.error,
                "status_code": r.status_code,
            }
            for r in failed
        ],
    }


def render_summary(console: Console, summary: dict[str, Any]) -> None:
    table = Table(title="Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("Value")
    for key in ("total", "ok", "failed", "timeout", "dns_failed", "tcp_failed", "ssl_failed", "average_response_time_ms"):
        table.add_row(key, str(summary[key] if summary[key] is not None else "-"))
    console.print(table)

    if summary["failed_services"]:
        failed_table = Table(title="Failed services", show_header=True, header_style="bold red")
        failed_table.add_column("Category")
        failed_table.add_column("Service")
        failed_table.add_column("IP version")
        failed_table.add_column("Code")
        failed_table.add_column("Error")
        for item in summary["failed_services"]:
            failed_table.add_row(
                item["category"],
                item["service"],
                item["ip_version"],
                str(item["status_code"] or "-"),
                item["error"],
            )
        console.print(failed_table)


async def run() -> int:
    args = parse_args()
    console = Console()

    if args.ipv4_only and args.ipv6_only:
        console.print("[red]--ipv4-only and --ipv6-only cannot be used together[/red]")
        return 2
    if args.concurrency < 1:
        console.print("[red]--concurrency must be at least 1[/red]")
        return 2

    try:
        targets = load_targets(Path(args.targets), args.category)
    except Exception as exc:
        console.print(f"[red]Failed to load targets: {exc}[/red]")
        return 2

    if not targets:
        console.print("[yellow]No targets matched the requested filters.[/yellow]")
        return 1

    console.print("[bold]Collecting VPS information...[/bold]")
    vps_info = await collect_vps_info(args.timeout)
    render_vps_info(console, vps_info)

    versions: list[str] = []
    if args.ipv6_only:
        versions = ["IPv6"]
    elif args.ipv4_only:
        versions = ["IPv4"]
    else:
        if vps_info.get("external_ipv4"):
            versions.append("IPv4")
        if vps_info.get("external_ipv6"):
            versions.append("IPv6")
        if not versions:
            versions.append("IPv4")

    if "IPv6" not in versions and not args.ipv4_only:
        console.print("[yellow]No external IPv6 detected; skipping IPv6 checks. Use --ipv6-only to force them.[/yellow]")

    console.print(f"[bold]Checking {len(targets)} targets...[/bold]")
    sem = asyncio.Semaphore(args.concurrency)
    nested = await asyncio.gather(*(check_target(target, versions, args.timeout, sem) for target in targets))
    results = [result for group in nested for result in group]
    results.sort(key=lambda r: (r.category, r.service, r.ip_version))

    if args.verbose:
        for result in results:
            console.print(f"[dim]{result.service} {result.ip_version}: {', '.join(result.resolved_ips) or 'no IPs'}[/dim]")

    render_results(console, results, args.short, args.fail_only)
    summary = summarize(results)
    render_summary(console, summary)

    if args.json_path:
        report = {
            "vps": vps_info,
            "summary": summary,
            "results": [asdict(result) for result in results],
        }
        Path(args.json_path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[green]JSON report saved to {args.json_path}[/green]")

    return 0


def main() -> None:
    raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
