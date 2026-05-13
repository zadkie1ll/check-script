# vpn-vps-checker

CLI-скрипт для быстрой проверки новой VPS на пригодность под VPN. Он показывает информацию о сервере и параллельно проверяет доступность популярных сайтов, соцсетей, мессенджеров, AI-сервисов, dev-платформ и стриминговых сервисов.

Проверка не меняет firewall, не требует root и не ставит Python-пакеты глобально.

## Что проверяется

Для каждой цели из `targets.yaml` скрипт отдельно проверяет:

- DNS resolve
- TCP connect к порту `443`
- HTTPS `HEAD` или `GET`
- IPv4 и IPv6, если это возможно
- HTTP status code
- response time
- итоговую ошибку: `DNS_FAIL`, `TCP_FAIL`, `TIMEOUT`, `SSL_FAIL`, `HTTP_FAIL`, `OK`

Статусы `200`, `204`, `301`, `302`, `307`, `308`, `403` считаются валидными. `403` часто означает не сетевую блокировку, а то, что сервис доступен, но не пускает конкретный IP, ASN, страну или дата-центр.

## Быстрый запуск

```bash
curl -fsSL https://raw.githubusercontent.com/zadkie1ll/check-script/main/run.sh | bash
```

Более безопасный вариант:

```bash
curl -fsSL -o run.sh https://raw.githubusercontent.com/zadkie1ll/check-script/main/run.sh
chmod +x run.sh
./run.sh
```

Можно также переопределить URL:

```bash
VPN_VPS_CHECKER_BASE_URL=https://raw.githubusercontent.com/zadkie1ll/check-script/main bash run.sh
```

## Локальный запуск

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 check.py
```

## Примеры команд

Проверить только AI-сервисы:

```bash
python3 check.py --category ai
```

Сохранить JSON-отчет:

```bash
python3 check.py --json report.json
```

Проверить только IPv4:

```bash
python3 check.py --ipv4-only
```

Проверить только IPv6:

```bash
python3 check.py --ipv6-only
```

Увеличить таймаут и снизить параллельность:

```bash
python3 check.py --timeout 12 --concurrency 10
```

Показать только summary и список проблем:

```bash
python3 check.py --short
```

Показать в таблице только недоступные сервисы:

```bash
python3 check.py --fail-only
```

Использовать свой файл целей:

```bash
python3 check.py --targets my_targets.yaml
```

## Как менять targets.yaml

`targets.yaml` - это список целей. У каждой цели есть:

```yaml
- name: Telegram API
  category: messengers
  url: https://api.telegram.org
  host: api.telegram.org
  port: 443
  method: GET
  expected_statuses: [200, 301, 302, 307, 308, 403, 404]
```

Поля:

- `name` - человекочитаемое имя сервиса
- `category` - категория для фильтра `--category`
- `url` - URL для HTTPS-проверки
- `host` - hostname для DNS и TCP
- `port` - обычно `443`
- `method` - `HEAD` или `GET`
- `expected_statuses` - HTTP-коды, которые считаются успешной доступностью

## Интерпретация результатов

`OK` означает, что DNS, TCP и HTTPS-проверка прошли успешно.

`403` считается доступностью: сервис ответил с HTTPS-уровня, но отказал в доступе. Для выбора VPS под VPN это полезный сигнал: маршрут есть, TLS работает, но IP может быть нежелательным для сервиса.

`TIMEOUT` может означать блокировку, плохой маршрут, перегруженный сервис, проблемы провайдера VPS или проблемы с IPv6/IPv4 у конкретной сети. Один timeout не всегда приговор, но массовые timeout по важной категории - плохой признак.

`DNS_FAIL` означает, что hostname не удалось разрешить в IP-адрес нужной версии.

`TCP_FAIL` означает, что DNS сработал, но подключение к `443` не установилось.

`SSL_FAIL` означает проблему TLS/сертификата/SSL-handshake.

`HTTP_FAIL` означает, что HTTPS-запрос дошел до HTTP-уровня, но статус не входит в ожидаемые или произошла HTTP-ошибка.

## Почему не ping

`ping` не используется как главный критерий, потому что ICMP часто отключают или фильтруют. Для VPN важнее практическая доступность сервисов через DNS, TCP `443` и HTTPS, потому что именно так обычно работают сайты, API, мессенджеры и стриминговые платформы.

## Что показывает VPS info

Перед проверкой целей скрипт показывает:

- внешний IPv4
- внешний IPv6, если есть
- country
- city
- ASN
- organization/provider
- hostname
- kernel
- OS
- дату проверки

Для этого используются `ipinfo.io`, `ifconfig.co`, `api.ipify.org` и `api64.ipify.org` с graceful fallback.
