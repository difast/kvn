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

## Подключение реального WireGuard-сервера

1. На VPS: установить WireGuard, `wg0` с подсетью (напр. `10.8.0.1/24`), включить `ip_forward` и NAT (masquerade).
2. `WG_SERVER_PUBLIC_KEY` (из `wg show wg0 public-key`), `WG_ENDPOINT=<домен>:51820`, `WG_SUBNET`, `WG_APPLY_MODE=wg`; процесс API нужны права на `wg set` (CAP_NET_ADMIN).
3. Сид сервера выполняется только на пустой БД; дополнительные серверы — строки в `vpn_servers`.
4. Peers, добавленные через `wg set`, живут до перезапуска интерфейса: для персистентности `reconcile()` нужно вызывать при старте (уже делается) — все активные профили с `peer_applied=0` переприменятся; при перезапуске `wg0` сбросьте флаг (`UPDATE vpn_profiles SET peer_applied=0`).

## Production-чеклист

- HTTPS: reverse proxy (Caddy/nginx) с TLS перед API и сайтом, `NODE_ENV=production`, `TRUST_PROXY=1`, `CORS_ORIGINS`/`FRONTEND_URL` на боевой домен, в `frontend/config.js` — адрес API.
- SQLite достаточно для MVP; для масштабирования — PostgreSQL (весь доступ к БД сосредоточен в сервисах).
- Сбер Эквайринг: реализовать `services/payments/sber.js`, `PAYMENT_PROVIDER=sber`. Для проверки подписи вебхука понадобится raw body (добавить `express.raw` для этого маршрута).
- Почта: заменить `consoleMailer` на SMTP, иначе восстановление пароля не работает.
- Токены на сайте лежат в localStorage — для production рассмотреть httpOnly-cookie для веб-клиента (API при этом не меняется) и подтверждение email.
