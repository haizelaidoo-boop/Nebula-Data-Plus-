# Nebula Data Plus 🪐 v1.12

A production-oriented Ghana data-bundle commerce platform using Node.js, Express, PostgreSQL, Prisma, Paystack InlineJS v2, a PWA frontend, automatic delivery queues, customer wallets, referrals, loyalty points, analytics and audit logs.

## Architecture

`Customer/PWA -> Express API -> Prisma -> PostgreSQL`

Payments: `Paystack -> server initialization -> InlineJS resumeTransaction -> webhook/verify -> payment state -> delivery queue`

Delivery: `Queue -> Provider 1 -> Provider 2 -> retry -> Completed/Failed`

## Included in this version

- PostgreSQL persistence with Prisma
- 90-day bundle validity
- MTN yellow, Telecel red, AirtelTigo blue network branding
- Database-backed bundle catalogue and admin pricing
- Strong order IDs (`NEBULA-<random>`)
- Payment and delivery states separated
- Paystack server-side initialization and InlineJS v2 popup
- Paystack webhook signature verification
- Server-side payment amount/currency verification
- Automatic delivery worker with retry and provider failover
- Delivery attempt history
- Customer order timeline/tracking
- Customer wallet funding with server-side Paystack verification
- Loyalty points
- Referral codes and referral rewards
- In-app notifications
- Optional WhatsApp/SMS notification webhooks
- Admin analytics and daily reconciliation view
- Provider health/priority management API
- Admin audit logs
- PWA manifest/service worker
- Search/filtering for customer/admin transactions
- Ghana phone formatting and validation
- Loading/skeleton/error states
- Accessibility improvements
- SEO metadata, dynamic robots.txt and sitemap.xml

## Setup

Requirements: Node.js 20+, PostgreSQL, a Paystack account for live payments.

1. Copy `.env.example` to `.env`.
2. Set `DATABASE_URL` to your Neon/Supabase/PostgreSQL connection string.
3. Generate a long random `JWT_SECRET` (32+ characters; preferably 64+).
4. Set `ADMIN_EMAIL` and an Argon2id `ADMIN_PASSWORD_HASH`.
5. Set `PAYSTACK_PUBLIC_KEY` and `PAYSTACK_SECRET_KEY`.
6. Configure Paystack's webhook URL as:

`https://YOUR-PRODUCTION-DOMAIN/api/payments/paystack/webhook`

7. Install dependencies:

```bash
npm install
```

8. Generate Prisma client:

```bash
npm run prisma:generate
```

9. Apply migrations:

```bash
npm run prisma:deploy
```

10. Start:

```bash
npm start
```

## Automatic data delivery

The delivery engine is deliberately provider-neutral. It will not pretend that a data bundle was delivered.

Configure one or two real provider endpoints:

```env
DELIVERY_PROVIDER_URL=https://your-provider.example/api/deliver
DELIVERY_PROVIDER_SECRET=server-only-secret
DELIVERY_PROVIDER_URL_2=
DELIVERY_PROVIDER_SECRET_2=
MAX_DELIVERY_ATTEMPTS=5
```

The provider endpoint receives a server-side POST containing the order ID, network, GB, recipient number, validity and amount. Adapt the payload/signature to your chosen Ghana data supplier before going live.

If no provider is configured, paid orders remain queued/processing rather than being falsely marked delivered.

## Notifications

The database stores in-app notifications. Optional webhook adapters can forward notification events to your WhatsApp/SMS provider:

```env
WHATSAPP_WEBHOOK_URL=
SMS_WEBHOOK_URL=
```

These endpoints receive `{ phone, email, type, title, message }`. Put the actual WhatsApp/SMS credentials in the provider system, not in frontend code.

## Paystack security

The secret key is server-only. The browser receives only the public key or a server-generated access code. The server verifies successful transactions, GHS currency and exact amount before marking payment as paid or starting delivery.

The Paystack webhook must be reachable over HTTPS in production.

## Database

The current migrations include the original core schema plus the 3.0 platform upgrade. Never edit production tables manually without a migration. Back up PostgreSQL before major schema changes.

Useful commands:

```bash
npm run prisma:validate
npm run prisma:studio
npm run prisma:deploy
```

## Production checklist

- Production `robots.txt` and `sitemap.xml` are generated from `APP_ORIGIN`; set `APP_ORIGIN` to the exact public HTTPS domain before launch.
- Use HTTPS.
- Set `NODE_ENV=production`.
- Configure the correct `APP_ORIGIN`.
- Configure Paystack live keys only on the server.
- Configure the Paystack webhook.
- Connect a real data delivery provider.
- Test every network and bundle before launch.
- Add server-side TOTP/WebAuthn for admin MFA before exposing admin access publicly.
- Configure database backups and monitoring.
- Run `npm audit` regularly.
- Never commit `.env`.

## Important

Automatic delivery, WhatsApp/SMS notifications and live payment processing require external provider credentials. This code provides the secure server-side integration points; it does not invent or fake third-party credentials or delivery confirmations.


## Idempotent delivery, loyalty and referrals

The production upgrade uses database safeguards to prevent duplicate internal delivery processing and duplicate rewards. Each order has a unique `deliveryRequestKey`; delivery workers atomically claim orders with a short lock before calling a provider. The same idempotency key is sent in the `Idempotency-Key` header and request body so a delivery provider that supports idempotency can safely deduplicate retries.

Important: no application can guarantee exactly-once external delivery if a third-party provider does not support idempotency and the server crashes after the provider accepts a request but before the response is recorded. Use a provider with idempotency/deduplication support for live automatic delivery.

### Loyalty
- 1 GH₵ spent = 1 loyalty point.
- Points are awarded only after successful delivery.
- Fixed redemption tiers: 100→GH₵1, 250→GH₵3, 500→GH₵5, 1,000→GH₵12, 2,500→GH₵30, 5,000→GH₵70 wallet credit.
- Redemptions deduct points and credit the wallet atomically.
- A unique loyalty transaction per order prevents duplicate point awards, and each wallet credit gets a unique redemption reference.

### Referrals
- Referral signup alone earns nothing.
- The referred customer must complete their first successful paid data delivery.
- The referrer then receives a one-time GH₵2 wallet reward.
- A unique referral per referred customer and a unique wallet transaction reference prevent duplicate referral rewards.

After deploying the migration, run `npm run prisma:generate` and `npm run prisma:deploy`.


## v1.4 MTN verification
The MTN checkout includes a server-backed number eligibility checker. Set `MTN_VERIFICATION_URL` and optionally `MTN_VERIFICATION_SECRET` in `.env` to connect your real MTN/data-provider checker. The browser never receives the secret. MTN orders are blocked until the entered number is successfully verified.

## Launch-hardening update
This build applies payment/delivery correctness fixes: Paystack mobile-money checkout is used instead of a broken standalone MTN MoMo handler; Paystack popup verification is followed by server-side verification; wallet funding is verified and webhook-safe; wallet checkout debits atomically; inactive bundles cannot be purchased; Paystack verification cannot re-queue a paid order; webhook signature errors return non-2xx; provider admin settings are preserved across restarts; failed deliveries can issue an account-wallet refund after the configured retry limit; admin cannot mark an unpaid order completed; login limiting uses IP + identifier; analytics profit is based on paid orders rather than the catalogue; reconciliation compares orders with Paystack transactions; production config fails fast on localhost origin/missing Paystack secret.


## v1.10 Automatic WhatsApp/SMS delivery notifications
When an order is atomically finalized as `Delivered`, v1.10 creates an idempotent notification dispatch key and attempts WhatsApp first, then SMS only if WhatsApp fails. A duplicate delivery event cannot send the same channel twice after a successful dispatch.

### WhatsApp Cloud API
Set `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_DELIVERY_TEMPLATE` and `WHATSAPP_TEMPLATE_LANGUAGE`. The delivery message uses a WhatsApp template with four body variables: bundle, recipient number, order ID and amount. The template must be created/approved in Meta Business Manager before production use.

### SMS
Set `HUBTEL_SMS_URL`, `HUBTEL_CLIENT_ID`, `HUBTEL_CLIENT_SECRET` and `HUBTEL_SENDER_ID` for the built-in Hubtel-style adapter, or use `SMS_WEBHOOK_URL` for another SMS provider.

### Important
Provider credentials are server-side only. The website never exposes WhatsApp access tokens or SMS credentials. If neither provider is configured, the in-app notification still works and the order remains delivered; no fake external notification is recorded.

## v1.10 Automatic WhatsApp/SMS delivery notifications
When an order is atomically finalized as `Delivered`, v1.10 creates an idempotent notification dispatch key and attempts WhatsApp first, then SMS only if WhatsApp fails. A duplicate delivery event cannot send the same channel twice after a successful dispatch.

### WhatsApp Cloud API
Set `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_DELIVERY_TEMPLATE` and `WHATSAPP_TEMPLATE_LANGUAGE`. The delivery message uses a WhatsApp template with four body variables: bundle, recipient number, order ID and amount. The template must be created/approved in Meta Business Manager before production use and customers must receive messages in accordance with WhatsApp's messaging/opt-in rules.

### SMS
Set `HUBTEL_SMS_URL`, `HUBTEL_CLIENT_ID`, `HUBTEL_CLIENT_SECRET` and `HUBTEL_SENDER_ID` for the built-in Hubtel-style adapter, or use `SMS_WEBHOOK_URL` for another SMS provider.

### Important
Provider credentials are server-side only. The website never exposes WhatsApp access tokens or SMS credentials. If neither provider is configured, the in-app notification still works and the order remains delivered; no fake external notification is recorded.

## v1.12 Production hardening
- Prisma PostgreSQL migration lock is included.
- `npm run start:prod` runs `prisma migrate deploy` before starting the server.
- Direct dependencies are pinned in `package.json`; generate and commit `package-lock.json` in an environment with registry access before using `npm ci`.
- Provider seeding is non-destructive: existing URLs, secrets, active flags, priorities and performance data are preserved.
- Admin completion now requires explicit manual delivery confirmation plus an audit note. Delivered orders cannot be moved backwards.
- Live delivery health considers the oldest currently processing order, not only historical averages.
- Helmet CSP is enabled with the required Paystack and Google Fonts origins.
- SEO files are generated from `APP_ORIGIN` so placeholder domains are not shipped.
- Active branding is Nebula Data Plus 🪐 v1.12. Historical migration names are intentionally left unchanged.

## v1.11 Genuine live delivery display
The homepage now includes a real-time delivery status board backed by PostgreSQL order records. Paid orders in `Queued`, `Processing`, or `Retrying` are shown as live processing activity, and recently delivered orders are shown with actual placement/delivery timestamps and calculated delivery duration. The public feed uses masked order IDs and no customer phone numbers. Updates are pushed over Server-Sent Events (SSE), with a polling fallback if the SSE connection is unavailable. No screenshot, hard-coded delivery times, or fake delivery figures are used.
