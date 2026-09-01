# LinkShield API

Node.js + Express + PostgreSQL backend for LinkShield ("Check Before You Click").
 
## Setup

```bash
cp .env.example .env    # fill in secrets / API keys
npm install
psql "$DATABASE_URL" -f db/schema.sql
npm run dev
```

Health check: `GET /health`

## Architecture

```
server.js            - app bootstrap, security middleware, route mounting
config/db.js         - pg Pool
middleware/          - auth (JWT), rate limiting, validation/error handling
routes/               -> controllers/  -> services/
services/
  urlAnalysisService.js       domain/HTTPS/redirect/typosquat heuristics + local threat DB lookup
  threatIntelService.js       Google Safe Browsing / VirusTotal / URLhaus (mock fallback if no keys)
  messageAnalysisService.js   scam-pattern regex library for SMS/chat/email text
  qrService.js                classifies decoded QR payload, routes to URL/message analysis
  riskScoreService.js         deterministic rules engine -> 0-100 score (AI never decides this)
  aiExplanationService.js     Claude-generated plain-language explanation of an already-computed verdict
db/schema.sql         - full Postgres schema (see table list in main spec)
```

**Security decision boundary:** `riskScoreService.js` is a deterministic, auditable
rules engine. `aiExplanationService.js` only explains a verdict that has already been
computed - it cannot change the score or level. This keeps the "AI assists, doesn't
decide" requirement enforced in code, not just in a system prompt.

## Demo vs. production data

Set `USE_MOCK_THREAT_DATA=true` (default) to run entirely offline/demo, using a small
deterministic mock list in `threatIntelService.js`. Set it to `false` and populate the
three provider API keys to hit live Safe Browsing / VirusTotal / URLhaus. The
`threat_domains` table is always real Postgres data (seeded via admin endpoints or a
confirmed scam report) - only the three external provider calls are mocked.

## Auth flow

Short-lived access tokens (15m) + long-lived refresh tokens (30d), both JWT. Passwords
hashed with bcrypt (cost 12). Login uses a constant-shape bcrypt.compare against a dummy
hash for non-existent emails to reduce user-enumeration timing signal.

## Key endpoints

| Method | Path | Notes |
|---|---|---|
| POST | /api/auth/register, /login, /refresh | |
| GET  | /api/auth/me | |
| POST | /api/scans/link, /qr, /message | quota-checked, rate-limited |
| GET  | /api/scans/history?type=&level=&q=& page=& pageSize= | |
| GET/DELETE | /api/scans/:id | |
| POST | /api/reports | user-submitted scam reports |
| GET/PATCH | /api/users/settings, /profile | |
| GET | /api/subscriptions/plans | |
| POST | /api/subscriptions/checkout | seam for PayMongo/GCash/Stripe integration |
| GET/PATCH | /api/admin/* | requires role admin/support |

See `docs/API_SPEC.md` for the full request/response contracts.
