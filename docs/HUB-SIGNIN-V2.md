# Hub sign-in v2: the wallet signs in to id.bwalletx.com directly

Status: hub side built (bitcoin-corp/bwalletx-id PR #1), with `@bwalletx/connect` 0.10.0. Wallet side: bWalletX
5.2.62. Until a wallet does the steps in "What the wallet must do", nobody can sign in to the hub.

## Why (security review, 22 Nov 2026, HIGH-1)

In v1 the hub's own page asked the wallet for a signature over the hub's challenge, under `[2, 'bwalletx id sign in']`,
and posted it to `/api/verify`. The hub could only check that the request said `Origin: https://id.bwalletx.com`, and
an `Origin` header only binds a browser. Any script can send one. So:

1. An attacker's server fetches a hub challenge.
2. The attacker's page asks the victim's wallet to sign it. Shipped bWalletX does not pin the protocol to the hub (only
   the draft yours-mobile PR #512 did), other BRC-100 wallets never will, and a relay pairing cannot prove origin.
3. The attacker posts the signature and gets a hub session as the victim, and through `/authorize` a session on every
   b*X site.

One phish signed someone in everywhere. v2 removes the page from the signing path.

## The idea

The page never carries the wallet's answer. It shows a short **code**. The wallet shows the **same code**, and on
approval signs and **POSTs straight to the hub** over TLS, to an address built into the wallet. The browser that started
the sign-in holds a secret in an HttpOnly cookie, and only that browser can collect the session. This follows the shape
of OAuth device authorization (RFC 8628).

## Protocol constants (from `@bwalletx/connect/sso`)

| Name | Value |
|------|-------|
| `HUB_SIGNIN_ORIGIN` | `https://id.bwalletx.com`. **Hard-coded in the wallet.** Never taken from a link, page or relay. |
| `HUB_WALLET_SIGNIN_PATH` | `/api/wallet-signin` |
| `HUB_SIGNIN_PROTOCOL` | `[2, 'admin bwalletx hub signin']` |
| keyID | the request id |
| counterparty | `'anyone'` (the hub verifies with `ProtoWallet('anyone')` and counterparty = the identity key) |

The protocol name starts with `admin`. BRC-100 reserves `admin…` names for the wallet itself: wallet-toolbox's
`WalletPermissionsManager.isAdminProtocol` refuses them to any non-admin originator ("Protocol … is admin-only"). So a
BRC-100 wallet built on that manager refuses this protocol to every website, and only the wallet's own code can sign
under it. This is a second line of defence, not the main one. bWalletX must also check this explicitly (below).

### The message (exact bytes, UTF-8, `\n` between lines, no trailing newline)

```
bWalletX hub sign-in v2
Hub: id.bwalletx.com
Request: <request id: 22–64 chars of A-Z a-z 0-9 _ ->
Code: <user code: XXXX-XXXX from BCDFGHJKLMNPQRSTVWXZ>
Site: <client_id of the site the sign-in continues to, or ->
Issued: <ISO 8601 UTC with milliseconds, e.g. 2026-11-22T12:00:00.000Z>
```

`hubSignInMessage(fields)` builds it and `parseHubSignInMessage(text)` parses it, accepting only this exact form.

## Endpoints

### Browser (the hub's own pages; same-origin only: `Origin` = the hub, `Sec-Fetch-Site: same-origin` when sent)

`POST /api/signin/start` with body `{ authorize?: { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type? } }`

- Checks `authorize` against the registry (400 if it isn't registered). `prompt` is dropped.
- Creates a pending sign-in that lasts 5 minutes.
- Sets `__Host-bwx_signin=<32 random bytes>` with `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`. Only its
  SHA-256 is stored.
- Returns `{ requestId, userCode, walletLink: "bwalletx://hub-signin?r=<requestId>", interval: 2, expiresAt, site }`.
  The cookie value is never in the body.
- 10 per minute per IP.

`POST /api/signin/poll` (sends the cookie)

- `{ status: "pending", interval, expiresAt, userCode }`: the wallet hasn't approved yet.
- `{ status: "approved", identityKey, paymail, handle, next }`: comes back **once**. It sets `__Host-bwx_hub` (the hub
  session, 30 days, as before) and clears `__Host-bwx_signin`. `next` is `/authorize?…` for the site, or `/`.
- `{ status: "expired" }`: no cookie, an unknown or used sign-in, or more than 5 minutes have passed. Clears the cookie.
- `{ status: "failed" }`: 5 bad wallet attempts. Clears the cookie.
- 120 per minute per IP.

`/signin/continue`: a page that only polls. The wallet may open it after approval. In the browser that started the
sign-in, it finishes and goes on to the site.

### Wallet (`HUB_SIGNIN_ORIGIN + HUB_WALLET_SIGNIN_PATH`)

A request with an `http(s)` `Origin` (a web page), or `Origin: null`, is refused (403). The exception is an origin
listed in `SSO_WALLET_ORIGINS` (a web wallet). Native apps send no `Origin`, and extensions send `chrome-extension://…`;
both are accepted. On Android, a Capacitor web view's `fetch` sends `Origin: https://localhost`, so use native HTTP
(CapacitorHttp) for these calls. 30 per minute per IP, counting GETs and POSTs.

`GET ?r=<requestId>` or `GET ?code=<XXXX-XXXX>` returns 200:
```json
{ "requestId": "…", "userCode": "BCDF-GHJK", "hub": "https://id.bwalletx.com",
  "site": { "clientId": "bsvapi", "name": "BSVAPI" } | null,
  "message": "<the exact text above>", "protocolID": [2, "admin bwalletx hub signin"], "keyID": "<requestId>",
  "issuedAt": 1795000000000, "expiresAt": 1795000300000 }
```
It returns 404 when nothing is waiting: unknown, expired, approved, used or failed.

`POST` with body `{ requestId, userCode, identityKey, signature: number[] (DER) }`:
- 200 `{ ok: true, site }`: approved. The page's next poll collects it.
- 401 `not_accepted`: wrong code, a message that isn't the exact v2 text for this hub, request, code and site, a bad
  key, or a bad signature. Each counts as an attempt, and 5 attempts kill the request.
- 404 unknown request. 409 not pending (already approved, used or failed). 410 expired.

## What the wallet must do (bWalletX 5.2.62)

1. **Never sign `HUB_SIGNIN_PROTOCOL` for anyone else.** Refuse `createSignature` and any other key operation under
   `admin bwalletx hub signin` from any originator: websites, relay pairings, other apps, the extension's page API.
   Only the wallet's own hub sign-in screen may use it. (The old `[2, 'bwalletx id sign in']` pin from PR #512 does not
   carry over. Replace it with this.)
2. **Get the request from the user, never from a page's API.** Two ways in:
   - a `bwalletx://hub-signin?r=<requestId>` link (same device; the page's "Open bWalletX" button), or the same link
     scanned as a QR code;
   - **Sign in to a b*X site** in the wallet, where the user types the code from the page (`?code=`).

   Take only `r` from the link. Ignore any host, URL or message in it.
3. `GET https://id.bwalletx.com/api/wallet-signin?r=…` (or `?code=…`). Use the **built-in** origin, over TLS, with
   certificate validation on.
4. **Rebuild the message yourself** with `hubSignInMessage({ hub: HUB_SIGNIN_ORIGIN, requestId, userCode, clientId:
   site?.clientId ?? null, issuedAt })`, and refuse unless it equals `message` byte for byte. Refuse if `hub` isn't
   `HUB_SIGNIN_ORIGIN` or `protocolID`/`keyID` differ from the constants above.
5. Show one sheet:
   - **"Sign in to <site name> through id.bwalletx.com"**
   - the code, large: **BCDF-GHJK**
   - "Only approve if id.bwalletx.com is showing this code on a screen you are using right now. Never approve a code
     someone sent you."
   - Approve / Cancel. Show the expiry; don't offer Approve once it has passed.
6. On Approve: `createSignature({ protocolID: HUB_SIGNIN_PROTOCOL, keyID: requestId, counterparty: 'anyone', data:
   utf8(message) })` with the **identity** key, then `POST` `{ requestId, userCode, identityKey, signature }` to the
   same built-in URL.
7. On 200: "Signed in. Go back to your browser." Optionally open `https://id.bwalletx.com/signin/continue`. That only
   helps when it opens in the browser that started the sign-in; otherwise the user returns to the original tab, which
   is polling. On 401, 409 or 410, show the hub's `error_description`.
8. Never put the signature, the identity key or the message anywhere except that POST: not in a URL, a fragment, the
   relay, or a page.

## What this protects, and what it doesn't

**Protected:**
- A phishing page can no longer get a hub session from a signature. The hub ignores signatures a page delivers (the v1
  `/api/challenge` and `/api/verify` routes are gone).
- Under v2, a page can't get a signature at all. bWalletX refuses the protocol to originators (step 1), and BRC-100
  permission managers reserve `admin…` names.
- The approval only helps the browser holding the `__Host-` HttpOnly cookie for that request. The cookie is unreadable
  to scripts, can't be set by a subdomain, and works once.
- An approval can't be replayed. Each request is single-use, lasts 5 minutes, and allows 5 attempts. The signature
  covers the hub host, request, code and site.

**Remaining risks (be honest about them):**
- **Code phishing.** This is the known weakness of device-style flows. An attacker starts a sign-in in their own
  browser and talks the victim into approving the attacker's code ("support needs you to approve BCDF-GHJK"). Then the
  attacker's browser is signed in as the victim. Mitigations: the wallet shows the site name, the code and the warning
  in step 5, and codes last 5 minutes. Possible later additions:
  - number matching (the wallet asks the user to pick the page's code from three);
  - a same-device check (the page and the wallet report coarse network or location, and a mismatch is flagged);
  - showing "started from <city> / <browser>" in the wallet.
- **Wallets that don't follow step 1.** A wallet that signs any protocol for any website (an old bWalletX, a
  non-conforming wallet) can still be asked by a phishing page to sign the v2 message, and the attacker can POST the
  result to `/api/wallet-signin` from a server. The hub can't tell who made the POST. The defences are: the `admin`
  name (conforming BRC-100 wallets refuse it to sites), the protocol pin in bWalletX 5.2.62, and refusing web
  `Origin`s, which only stops browsers. **Don't launch the hub publicly until bWalletX 5.2.62 (with step 1) is the
  build users have**, and consider an allow-list of wallet builds if other wallets are to be supported.
- A session still never authorises spending (rule zero). Every payment still asks in the wallet.

## Configuration (hub env)

| Var | What |
|-----|------|
| `SSO_CLIENT_KEY` | 32+ random chars. Site client secrets are derived from it (`lib/clients.ts`). Required in production. Give a site its secret with `SSO_CLIENT_KEY=… pnpm client-secret <client_id>`; it goes in that site's env (`BWX_CLIENT_SECRET`, passed to `createSso({ clientSecret })`). Bump a client's `secret_version` in `clients.json` to rotate only that site. |
| `SSO_WALLET_ORIGINS` | Optional, comma-separated `https://` origins of web wallets allowed to POST `/api/wallet-signin`. |
| `SSO_RATE_LIMITS` | Optional JSON overriding `start`, `poll`, `wallet`, `token` (failed per IP), `epoch` (unauthenticated), `clientToken`, `clientEpoch`. |

Database: run `supabase/migrations/0002_signin_v2.sql` after 0001 (it is additive: one new table, `sso.pending_signins`).
