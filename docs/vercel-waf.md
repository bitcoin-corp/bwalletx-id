# Vercel WAF rules for id.bwalletx.com (for the owner to apply)

**Nothing here has been applied.** These rules sit in front of the hub's own in-app limits (lib/hub.ts, kept in
Postgres table `sso.rate_limits`). The WAF stops floods before they reach a function (blocked requests are not billed);
the in-app limits are exact and also cover per-client and per-identity-key buckets the WAF can't see.

| Route | Method | In-app limit | WAF rule (per IP, per region) |
|-------|--------|--------------|-------------------------------|
| `/api/signin/start` | POST | 10 / min per IP | 30 / min |
| `/api/signin/poll` | POST | 120 / min per IP | 600 / min |
| `/api/wallet-signin` | GET, POST | 30 / min per IP | 120 / min |
| `/token` | POST | 20 **failed** / min per IP; 600 / min per client | 300 / min |
| `/session/epoch` | GET, POST | 600 / min per client (each POST checks up to 100 sessions) | 600 / min |
| `/logout` | POST | (Origin must be the hub, Sec-Fetch-Site same-origin) | 30 / min |

The WAF limits are deliberately looser: WAF counters are per region, and `/token` and `/session/epoch` are called by
site **servers** from shared Vercel egress IPs. Those two now authenticate each site (client secret), and the hub limits
them per site, so the per-IP WAF rule is only a flood guard. If a busy site meets the in-app limit, raise it with the env
var `SSO_RATE_LIMITS='{"clientEpoch":1200,"clientToken":1200}'` rather than loosening the WAF.

## Roll-out (one rule at a time)

1. Add each rule with `--rate-limit-action log` (as below), publish, and watch
   `https://vercel.com/<team>/<project>/firewall/traffic?filter=<ruleId>` for a few days.
2. If only abusive traffic matches, edit the rule to `--rate-limit-action rate_limit` (429) and publish.

```bash
cd /Volumes/2026/Projects/bwalletx-id && vercel link   # once

vercel firewall rules add "sso: sign-in start flood" \
  --condition '{"type":"path","op":"eq","value":"/api/signin/start"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 30 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: sign-in poll flood" \
  --condition '{"type":"path","op":"eq","value":"/api/signin/poll"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 600 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: wallet sign-in flood" \
  --condition '{"type":"path","op":"eq","value":"/api/wallet-signin"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 120 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: token flood" \
  --condition '{"type":"path","op":"eq","value":"/token"}' \
  --condition '{"type":"method","op":"eq","value":"POST"}' \
  --action rate_limit --rate-limit-window 60 --rate-limit-requests 300 \
  --rate-limit-keys ip --rate-limit-action log --yes

vercel firewall rules add "sso: epoch flood" \
  --condition '{"type":"path","op":"eq","value":"/session/epoch"}' \
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

The JSON form (`vercel firewall rules add --json '<rule>' --yes`) takes the same fields: `conditionGroup` with a
`path` `eq` condition (plus `method` where shown) and `action.mitigate.rateLimit` `{ algo: "fixed_window", window: 60,
limit, keys: ["ip"], action: "log" }`. Check the shape against
https://vercel.com/docs/vercel-firewall/vercel-waf/rule-configuration before use; the CLI flag form above is the safer
one.
