# KVN — MVP коммерческого VPN-сервиса (WireGuard)

Сценарий: регистрация → тестовая оплата 500 ₽ → активная подписка (30 дней) → генерация WireGuard-конфигурации → скачивание `.conf`.

```
frontend/   статический сайт (HTML/CSS/JS, без сборки) + dev-сервер с прокси на /api
backend/    REST API (Node 22, Express, SQLite) — единственное, что знает про ключи и платежи
```

Frontend и backend разделены: API — чистый JSON + Bearer-токены (без cookie), поэтому его так же будут
использовать Android / iOS / desktop-клиенты.

## Запуск (dev)

Нужен Node ≥ 22.13.

```bash
cd backend && npm install && npm start      # API на :3000 (секреты dev генерируются в backend/data/, он в .gitignore)
cd frontend && node serve.js                # сайт на http://localhost:8080, /api проксируется на :3000
cd backend && npm test                      # e2e-тесты всего сценария
```

Все настройки — переменные окружения, см. `backend/.env.example`.

## API (`/api`)

| Метод | Путь | Описание |
|---|---|---|
| POST | `/auth/register`, `/auth/login` | `{email,password}` → `{user, accessToken, refreshToken}` |
| POST | `/auth/refresh`, `/auth/logout` | `{refreshToken}`; refresh-токены ротируются, в БД хранится только хэш |
| POST | `/auth/password/forgot`, `/auth/password/reset` | восстановление пароля (письмо пишется в консоль — `services/mailer.js`) |
| GET | `/plans`, `/me` | тарифы; пользователь + подписка + серверы |
| POST | `/payments` | создать платёж (`{planId}`); GET `/payments` — история |
| POST | `/payments/webhook/:provider` | колбэк платёжного провайдера |
| GET/POST | `/vpn/profiles` | список / создать конфигурацию (нужна активная подписка) |
| GET | `/vpn/profiles/:id/config` | `.conf` (attachment). Единственное место, где отдаётся приватный ключ клиента |
| POST | `/vpn/profiles/:id/revoke` | отозвать |

## Деплой одним сервисом (например, Timeweb Apps)

Бэкенд сам отдаёт `frontend/` (отключить: `SERVE_FRONTEND=false`, другая папка: `FRONTEND_DIR`). Сайт и API на одном домене, CORS не нужен, `frontend/config.js` менять не нужно.
Корень проекта — корень репозитория (чтобы папка `frontend/` была рядом). Сборка: `npm ci --prefix backend`, запуск: `npm start --prefix backend`, проверка: `/api/health`.

## Архитектура

- **Платежи** (`services/payments/`): интерфейс провайдера `createPayment` / `parseWebhook`. Сейчас `mock` (мгновенный успех, запрещён в production без `ALLOW_MOCK_PAYMENTS=true`). `sber.js` — заготовка с описанием шагов. Активация подписки живёт в `settle()`, идемпотентна и от провайдера не зависит: Сбер вернёт `pending` + `redirectUrl`, фронтенд уже умеет редирект, а подтверждение придёт на вебхук.
- **Подписки**: по строке на оплаченный период; доступ до `MAX(ends_at)`, повторная оплата продлевает.
- **VPN** (`services/vpn/`): модель `vpn_servers` + `vpn_profiles` (много серверов, много конфигураций на пользователя; лимит — `VPN_MAX_PROFILES_PER_USER`, сейчас 1). Сервер выбирается по наименьшей нагрузке, адрес берётся из пула подсети сервера. Срок профиля = срок подписки (продлевается при оплате), профиль можно отозвать.
- **Применение к реальному серверу**: `applier.js`. `WG_APPLY_MODE=none` — только БД; `wg` — `wg set` на этой же машине. `reconcile()` раз в минуту добавляет/удаляет peers (истёкшие и отозванные) и повторяет неудавшиеся операции. Для удалённых серверов добавьте реализацию с тем же интерфейсом (SSH/агент).
- **Ключи**: генерируются на backend (X25519, чистый Node). Приватный/preshared ключи клиента шифруются AES-256-GCM (`DATA_ENCRYPTION_KEY`) в БД. **Приватный ключ сервера приложению не нужен** — в БД и env только публичный (`WG_SERVER_PUBLIC_KEY`).

## Безопасность

scrypt-хэши паролей; JWT (15 мин) + ротируемые refresh-токены; zod-валидация всех входов; rate-limit (login: по IP+email, только неудачные; auth: по IP; общий API); helmet; CORS по whitelist; секреты только из env; в production без `JWT_SECRET`/`DATA_ENCRYPTION_KEY` сервис не стартует; ответы reset/forgot не раскрывают существование email.

## Реальный WireGuard-сервер (VPS, Ubuntu/Debian)

Всё на одной машине: API + сайт + WireGuard. Из корня репозитория, под root на чистом VPS:

```bash
# положите свой SSH-ключ в ~/.ssh/authorized_keys ДО запуска (иначе усиление SSH пропустится)
DOMAIN=vpn.example.com sudo -E bash deploy/setup-vps.sh      # DOMAIN необязателен; без него — без HTTPS
```

Скрипт идемпотентен и делает: `wg0` (10.8.0.1/24, UDP 51820, ключи сервера только в `/etc/wireguard`, root 0600); `ip_forward`; nftables (`deploy/nftables.conf.tpl`: input drop, SSH с лимитом на IP, NAT, клиентам запрещены частные сети и связь друг с другом, MSS clamp); fail2ban; усиление SSH (`deploy/sshd-hardening.conf`; применяется только если найден `authorized_keys`, проверяется `sshd -t`); пользователь `kvn`, systemd-сервис `deploy/kvn.service` (только `CAP_NET_ADMIN`, `ProtectSystem=strict`); `/etc/kvn/kvn.env` (root 0600) с новыми секретами и `WG_SERVER_PUBLIC_KEY`; Caddy для HTTPS.

**Peer создаётся** при выдаче профиля: API генерирует пару ключей и preshared key, берёт свободный IP из пула (10.8.0.2…), сохраняет ключи в БД (зашифрованно) и делает `wg set wg0 peer <pub> preshared-key <tmp-file 0600> allowed-ips 10.8.0.X/32`.
**Peer удаляется** (`wg set wg0 peer <pub> remove`) при отзыве, отмене подписки (`POST /api/subscription/cancel`) и по истечении срока. Это делает `reconcile()`: раз в `VPN_RECONCILE_INTERVAL_SEC` (30 с) и сразу после каждого изменения он сверяет желаемое состояние БД с живым `wg show wg0 peers`. Поэтому после перезапуска `wg0` или перезагрузки VPS пиры возвращаются сами. Peers, которых нет в БД, не трогаются.

## VLESS + Reality (Happ, INCY, v2rayN, Hiddify…)

Рядом с WireGuard работает Xray (VLESS + Reality, TCP `XRAY_PORT`, по умолчанию 8443). `setup-vps.sh` сам ставит Xray, генерирует ключи Reality, пишет `/usr/local/etc/xray/config.json` из `deploy/xray-config.json.tpl` (приватный ключ Reality остаётся только там) и дописывает `XRAY_*` в `/etc/kvn/kvn.env`. API знает только **публичный** ключ.

- Пользователи добавляются/удаляются в работающий Xray через его gRPC API (`xray api adu/rmu/inbounduser`, только 127.0.0.1:10085); перезапуск Xray не нужен. `reconcile()` раз в 30 с сверяет БД с `inbounduser`, поэтому после перезапуска Xray пользователи возвращаются сами.
- UUID пользователя хранится в БД зашифрованно; выдаётся только в ссылке `vless://…` (`GET /api/vless/accounts/:id/link`). Срок, отзыв и отмена подписки работают так же, как у WireGuard.
- В выдаваемой ссылке отпечаток TLS `fp=ios` (`XRAY_FINGERPRINT`): ClientHello 517 байт помещается в один TCP-пакет. С `chrome` он 1823 байта и делится на два пакета, а часть мобильных сетей теряет второй, и все соединения зависают (измерено на Xray 26.3.27).
- Клиентам заблокирован доступ к частным сетям (`geoip:private`), логи доступа выключены.
- API: `GET/POST /api/vless/accounts`, `GET /api/vless/accounts/:id/link`, `POST /api/vless/accounts/:id/revoke`; `/api/me` отдаёт `protocols.vless`.

**Как включить VLESS на сервере** (уже установленный VPS):
```bash
cd ~/kvn && git pull
DOMAIN=<ваш-домен> bash deploy/setup-vps.sh      # идемпотентно: ключи/секреты/пользователи не трогает
# если у сервера есть внешний файрвол в панели хостинга — откройте TCP 8443
xray version; systemctl status xray kvn --no-pager
grep ^XRAY /etc/kvn/kvn.env
```
Опционально: `XRAY_PORT=…` и `REALITY_DEST=<сайт с TLS 1.3 и h2>:443` (по умолчанию `www.microsoft.com:443`) задаются переменными окружения при запуске скрипта.

## Проверка реального соединения

`sudo bash deploy/lab/run.sh` — стенд из трёх network namespace (клиент / VPS / «интернет») с настоящими WireGuard-туннелями, NAT и боевым набором правил nftables; API работает в `WG_APPLY_MODE=wg`. Проверяет: регистрация → оплата → `.conf` → импорт в WireGuard-клиент (`wg-quick up`) → handshake → смена внешнего IP → доступ в сеть → отзыв / отмена / истечение → доступ пропал; перезапуск `wg0`; то же для VLESS с настоящими Xray-сервером и Xray-клиентом (ссылка из API превращается в клиентский конфиг); безопасность. Нужен бинарь `xray` (и `geoip.dat` в `XRAY_LOCATION_ASSET`). Нужны root, `iproute2`, `wireguard-tools`, `nftables`, `iputils-ping` и `wireguard-go` (если в ядре нет WireGuard).

## Production-чеклист

- HTTPS: reverse proxy (Caddy/nginx) с TLS перед API и сайтом, `NODE_ENV=production`, `TRUST_PROXY=1`, `CORS_ORIGINS`/`FRONTEND_URL` на боевой домен, в `frontend/config.js` — адрес API.
- SQLite достаточно для MVP; для масштабирования — PostgreSQL (весь доступ к БД сосредоточен в сервисах).
- Сбер Эквайринг: реализовать `services/payments/sber.js`, `PAYMENT_PROVIDER=sber`. Для проверки подписи вебхука понадобится raw body (добавить `express.raw` для этого маршрута).
- Почта: заменить `consoleMailer` на SMTP, иначе восстановление пароля не работает.
- Токены на сайте лежат в localStorage — для production рассмотреть httpOnly-cookie для веб-клиента (API при этом не меняется) и подтверждение email.
