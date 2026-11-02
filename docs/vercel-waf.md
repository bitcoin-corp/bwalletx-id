# Vercel WAF rules for id.bwalletx.com (for the owner to apply)

**Nothing here has been applied.** These rules sit in front of the hub's own in-app limits (lib/hub.ts, kept in
Postgres table `sso.rate_limits`). The WAF stops floods before they reach a function (blocked requests are not billed);
the in-app limits are exact and also cover per-identity-key buckets the WAF can't see.

| Route | Method | In-app limit (per IP, per identity key) | WAF rule (per IP, per region) |
|-------|--------|------------------------------------------|-------------------------------|
| `/api/challenge` | POST | 10 / min | 30 / min |
| `/api/verify` | POST | 10 / min | 30 / min |
| `/token` | POST | 60 / min | 300 / min |
| `/session/epoch` | GET | 120 / min | 600 / min |
| `/logout` | POST | (Origin must be the hub) | 30 / min |

The WAF limits are deliberately looser (about 3–5x): WAF counters are per region, and `/token` and `/session/epoch` are
called by site **servers** from shared Vercel egress IPs. If a busy site meets the in-app limit, raise it with the env
var `SSO_RATE_LIMITS='{"epoch":600,"token":300}'` rather than loosening the WAF.

## Roll-out (one rule at a time)

1. Add each rule with `--rate-limit-action log` (as below), publish, and watch
   `https://vercel.com/<team>/<project>/firewall/traffic?filter=<ruleId>` for a few days.
2. If only abusive traffic matches, edit the rule to `--rate-limit-action rate_limit` (429) and publish.

```bash
cd /Volumes/2026/Projects/bwalletx-id && vercel link   # once

vercel firewall rules add "sso: challenge flood" \
  --condition '{"type":"path","op":"eq","value":"/api/challenge"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 30 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: verify flood" \
  --condition '{"type":"path","op":"eq","value":"/api/verify"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 30 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: token flood" \
  --condition '{"type":"path","op":"eq","value":"/token"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 300 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: epoch flood" \
  --condition '{"type":"path","op":"eq","value":"/session/epoch"}' \
  --condition '{"type":"method","op":"eq","value":"GET"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 600 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: logout post flood" \
  --condition '{"type":"path","op":"eq","value":"/logout"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 30 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall diff        # review
vercel firewall publish --yes
```

## Same rules as JSON (`vercel firewall rules add --json '<rule>' --yes`)

```json
[
  {
    "name": "sso: challenge flood",
    "conditionGroup": [{ "conditions": [
      { "type": "path", "op": "eq", "value": "/api/challenge" },
      { "type": "method", "op": "eq", "value": "POST" }
    ] }],
    "action": { "mitigate": { "action": "rate_limit",
      "rateLimit": { "algo": "fixed_window", "window": 60, "limit": 30, "keys": ["ip"], "action": "log" } } }
  },
  {
    "name": "sso: verify flood",
    "conditionGroup": [{ "conditions": [
      { "type": "path", "op": "eq", "value": "/api/verify" },
      { "type": "method", "op": "eq", "value": "POST" }
    ] }],
    "action": { "mitigate": { "action": "rate_limit",
      "rateLimit": { "algo": "fixed_window", "window": 60, "limit": 30, "keys": ["ip"], "action": "log" } } }
  },
  {
    "name": "sso: token flood",
    "conditionGroup": [{ "conditions": [
      { "type": "path", "op": "eq", "value": "/token" },
      { "type": "method", "op": "eq", "value": "POST" }
    ] }],
    "action": { "mitigate": { "action": "rate_limit",
      "rateLimit": { "algo": "fixed_window", "window": 60, "limit": 300, "keys": ["ip"], "action": "log" } } }
  },
  {
    "name": "sso: epoch flood",
    "conditionGroup": [{ "conditions": [
      { "type": "path", "op": "eq", "value": "/session/epoch" },
      { "type": "method", "op": "eq", "value": "GET" }
    ] }],
    "action": { "mitigate": { "action": "rate_limit",
      "rateLimit": { "algo": "fixed_window", "window": 60, "limit": 600, "keys": ["ip"], "action": "log" } } }
  },
  {
    "name": "sso: logout post flood",
    "conditionGroup": [{ "conditions": [
      { "type": "path", "op": "eq", "value": "/logout" },
      { "type": "method", "op": "eq", "value": "POST" }
    ] }],
    "action": { "mitigate": { "action": "rate_limit",
      "rateLimit": { "algo": "fixed_window", "window": 60, "limit": 30, "keys": ["ip"], "action": "log" } } }
  }
]
```

Check the JSON shape against https://vercel.com/docs/vercel-firewall/vercel-waf/rule-configuration before use; the
CLI flag form above is the safer one.
