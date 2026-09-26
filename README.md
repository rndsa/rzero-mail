# RZero Mail

> High-Voltage Serverless Disposable Email & Automated OTP Extraction Engine built on Cloudflare Edge (Workers, D1 SQLite & Anycast Email Routing).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Cloudflare](https://img.shields.io/badge/Platform-Cloudflare%20Edge-orange.svg)](https://workers.cloudflare.com/)
[![Runtime: Node / Hono](https://img.shields.io/badge/Stack-TypeScript%20%7C%20Hono%20%7C%20D1-blue.svg)](https://hono.dev)
[![Design: Neo--Brutalism](https://img.shields.io/badge/UI-Neo--Brutalism-ff70a6.svg)](#ui--ux-design-philosophy)

RZero Mail is a production-ready, open-source temporary disposable email service engineered specifically for high-speed automated bot workflows, account registration pipelines, and privacy protection. 

Unlike traditional disposable email systems that rely on heavy webmail UIs and complex POST payloads, RZero Mail offers a **100% GET-based REST API**, a context-aware **Instant OTP Extractor**, multi-domain Anycast routing with zero relay delays, PIN-secured private inboxes, and an opinionated **Neo-Brutalism** responsive web interface.

---

## ⚡ Architecture Overview

```text
[ Inbound Email (Canva / Discord / Social) ]
                     │
                     ▼
       [ Cloudflare Anycast 3-MX Servers ]
   (route1 / route2 / route3.mx.cloudflare.net)
                     │
                     ▼
          [ Cloudflare Email Worker ]
          ├── Inbound MIME Parser (postal-mime)
          ├── Contextual OTP Extractor (Regex Engine)
          └── D1 SQLite Storage Engine (rzero-db)
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  [ REST API Layer ]     [ Web Client (Edge CDN) ]
  ├── 100% GET Methods    ├── Neo-Brutalism UI
  ├── Anti-DDoS Limiter   ├── Reactive Auto-Refresh
  └── Triple-Lock Admin   └── Live API Docs (/docs)
```

---

## ✨ Features & Capabilities

- **100% GET-Based REST API**: Create addresses, list messages, and retrieve OTP codes directly via simple HTTP GET requests. Perfect for bots, curl commands, and browser address bar access.
- **Automated Contextual OTP Extractor**: Built-in algorithmic regex parser isolates 4–8 digit verification codes from incoming message bodies (Canva, Discord, social media, crypto faucets, APK services) directly into clean JSON fields.
- **Cloudflare Anycast 3-MX Redundancy**: Multi-server failover routing prevents bounce-backs and ensures instant delivery under high traffic.
- **Permanent Inboxes & PIN Security**: Inboxes do not expire unless explicitly unlinked. Users can lock their custom mailboxes with a 4–6 digit SHA-256 PIN.
- **Multi-Domain Support**: Seamlessly manage dozens of active domains with live DNS MX inspection and status badges.
- **Triple-Lock Admin Console**: Multi-tier administration console secured with username, master password, secondary security key, and cryptographically signed session cookies.
- **Ad & Sponsor Management**: Built-in CRUD support for custom promo banners, sponsored script units (e.g. A-ADS), and conversion click-tracking.
- **Zero Framework Bloat**: Frontend built with pure vanilla HTML5, CSS3, and JavaScript—zero build steps, zero bloated client-side bundles.

---

## 📂 Repository Structure

```text
├── src/
│   ├── index.ts                # Main Cloudflare Worker entrypoint & static router
│   ├── email-handler.ts        # Postal-Mime inbound processor & D1 storage
│   ├── api/
│   │   └── routes.ts           # 100% GET & POST public API endpoints
│   ├── admin/
│   │   └── admin-handler.ts    # Triple-lock admin RPC controller & MX verifier
│   ├── db/
│   │   ├── schema.sql          # Cloudflare D1 SQLite schema & migration
│   │   └── queries.ts          # Prepared SQL query abstractions
│   ├── middleware/
│   │   └── anti-ddos.ts        # Sliding-window rate limiter & IP protection
│   ├── utils/
│   │   ├── crypto.ts           # SHA-256 hashers & OTP extraction regex
│   │   └── random-address.ts   # Memorable random inbox name generator
│   └── web/
│       ├── index.html          # Webmail client (Neo-Brutalism)
│       ├── docs.html           # Interactive REST API docs & live tester
│       ├── admin.html          # Admin console & DNS routing manager
│       ├── styles.css          # Neo-Brutalism design system stylesheet
│       └── app.js              # Realtime polling & reactive UI controller
├── wrangler.toml.example       # Cloudflare Wrangler configuration template
├── .env.example                # Local environment variables template
├── package.json                # Project dependencies and deployment scripts
├── tsconfig.json               # TypeScript compiler configuration
└── LICENSE                     # MIT License
```

---

## 🛠️ Step-by-Step Deployment Guide

### 1. Prerequisites
- Node.js v18.0+ or v22 LTS
- A Cloudflare account with at least one custom domain (e.g., `yourdomain.com`)

### 2. Clone & Install Dependencies
```bash
git clone https://github.com/rndsa/rzero-mail.git
cd rzero-mail
npm install
```

### 3. Initialize Cloudflare D1 SQLite Database
Create your edge database:
```bash
npx wrangler d1 create rzero-db
```
Wrangler will output your database binding details. Copy the `database_id`:
```toml
[[d1_databases]]
binding = "DB"
database_name = "rzero-db"
database_id = "PASTE_YOUR_DATABASE_ID_HERE"
```

Apply database migrations:
```bash
# Apply schema to remote production D1
npx wrangler d1 execute rzero-db --remote --file=./src/db/schema.sql
```

### 4. Configure `wrangler.toml`
Rename `wrangler.toml.example` to `wrangler.toml` and configure your credentials:
```toml
name = "rzero-mail"
main = "src/index.ts"
compatibility_date = "2025-06-01"
workers_dev = true

# (Optional) Route to custom domain
routes = [
  { pattern = "yourdomain.com", custom_domain = true }
]

[[d1_databases]]
binding = "DB"
database_name = "rzero-db"
database_id = "PASTE_YOUR_DATABASE_ID_HERE"

[email]
action = "process"

[vars]
APP_NAME = "RZero Mail"
MAIL_DOMAIN = "yourdomain.com"
WEB_HOST = "yourdomain.com"

# Admin 3-Step Security Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "your_secure_password"
ADMIN_V2L_KEY = "your_secondary_security_key"
ADMIN_SECRET = "your_jwt_hmac_secret_salt"

[assets]
directory = "./src/web"

[observability]
enabled = true
```

### 5. Setup Cloudflare Email Routing
1. Open the [Cloudflare Dashboard](https://dash.cloudflare.com/) &rarr; select your domain &rarr; **Email Routing**.
2. Add the required DNS records:

| Type | Name | Content | Priority |
| :--- | :--- | :--- | :--- |
| **MX** | `@` | `route1.mx.cloudflare.net` | `10` |
| **MX** | `@` | `route2.mx.cloudflare.net` | `20` |
| **MX** | `@` | `route3.mx.cloudflare.net` | `30` |
| **TXT**| `@` | `v=spf1 include:_spf.mx.cloudflare.net ~all` | - |

3. Under **Routing Rules** &rarr; **Catch-all address**:
   - Status: **Enabled**
   - Action: **Send to Worker** &rarr; select **`rzero-mail`**.

### 6. Deploy to Production
```bash
npx wrangler deploy
```

---

## 🔌 API Reference (100% GET Method)

Base URL: `https://yourdomain.com/api`

### 1. Generate Instant Random Inbox
```http
GET /api/create?domain=yourdomain.com
```
**Response (200 OK):**
```json
{
  "success": true,
  "address": "swiftfox88@yourdomain.com",
  "isLocked": false,
  "isOwner": true,
  "created": true
}
```

### 2. Create Custom Inbox
```http
GET /api/custom/mybot@yourdomain.com
```
*Or via query parameters:*
```http
GET /api/custom?name=mybot&domain=yourdomain.com&pin=123456
```
**Response (200 OK):**
```json
{
  "success": true,
  "address": "mybot@yourdomain.com",
  "isLocked": false,
  "isOwner": true,
  "created": true
}
```

### 3. Extract Latest OTP Code Directly (Bot Optimized)
```http
GET /api/otp/mybot@yourdomain.com
```
**Response (200 OK):**
```json
{
  "success": true,
  "address": "mybot@yourdomain.com",
  "has_otp": true,
  "otp": "482910",
  "from": "messages-noreply@canva.com",
  "subject": "482910 adalah kode masuk Canva Anda",
  "received_at": "2026-09-26 10:04:03"
}
```
*(Add `?raw=1` to receive plain string digits `482910` directly)*

### 4. Fetch All Messages (Lightweight JSON)
```http
GET /api/messages/mybot@yourdomain.com
```
**Response (200 OK):**
```json
{
  "success": true,
  "address": "mybot@yourdomain.com",
  "isLocked": false,
  "count": 1,
  "messages": [
    {
      "id": "msg_canva_user_01",
      "from_address": "messages-noreply@canva.com",
      "subject": "482910 adalah kode masuk Canva Anda",
      "snippet": "Halo! Gunakan kode masuk 482910 ini untuk melanjutkan ke Canva...",
      "otp_code": "482910",
      "received_at": "2026-09-26 10:04:03"
    }
  ]
}
```

### 5. Fetch Full Message Detail (Raw HTML & Text)
```http
GET /api/inboxes/mybot@yourdomain.com/messages/:id
```

### 6. Lock Inbox with Security PIN
```http
GET /api/inboxes/mybot@yourdomain.com/lock?pin=123456
```

### 7. Delete / Unlink Inbox
```http
GET /api/inboxes/mybot@yourdomain.com/delete
```

### 8. List Active Verified Domains
```http
GET /api/domains
```

---

## 🤖 Bot Integration Examples

### Python (Requests)
```python
import requests, time

BASE = "https://yourdomain.com/api"

# 1. Create custom inbox
mail = requests.get(f"{BASE}/custom/workerbot@yourdomain.com").json()
email = mail["address"]
print(f"[*] Inbox created: {email}")

# 2. Wait for incoming OTP
print("[*] Polling for OTP code...")
for attempt in range(30):
    time.sleep(2)
    res = requests.get(f"{BASE}/otp/{email}").json()
    if res.get("has_otp"):
        print(f"[✓] OTP Received: {res['otp']}")
        print(f"[✓] Sender: {res['from']} | Subject: {res['subject']}")
        break
```

### Node.js (Async Fetch)
```javascript
const BASE = 'https://yourdomain.com/api';

async function main() {
  // 1. Create custom email
  const createRes = await fetch(`${BASE}/custom/nodebot@yourdomain.com`);
  const { address } = await createRes.json();
  console.log(`[*] Inbox ready: ${address}`);

  // 2. Poll for OTP
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const otpRes = await fetch(`${BASE}/otp/${address}`);
    const data = await otpRes.json();
    if (data.has_otp) {
      console.log(`[✓] OTP Code: ${data.otp}`);
      break;
    }
  }
}
main();
```

---

## 🔒 Triple-Lock Admin Security

The admin console (`/admin`) implements a zero-trust multi-tier authentication handshake:
1. **Tier 1**: Admin username & SHA-256 hashed password.
2. **Tier 2**: Secondary security passkey verification (`ADMIN_V2L_KEY`).
3. **Tier 3**: HMAC-SHA256 cryptographically signed session cookie validation on every privileged RPC call.

Privileged features include:
- Realtime DNS DoH 3-MX inspection with Turbo/Standard status badges.
- Dynamic domain registry management (Add, Verify, Toggle, Delete).
- Ad banner and sponsor unit manager.
- Edge IP rate limiting monitor & traffic logs.

---

## 📄 License & Credits

- **License**: MIT License
- **Author**: [ren](https://instagram.com/rskl411_) &bull; GitHub: [@rndsa](https://github.com/rndsa)
- **Copyright**: (c) 2026 ren. All rights reserved.
