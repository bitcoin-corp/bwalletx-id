/** Small server-rendered pages (error, signed out). Gold on black, phone-first, no horizontal scroll. */

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export interface PageForm {
  /** Same-origin path. */
  action: string;
  fields: Record<string, string>;
  label: string;
}

export function page(o: { title: string; body: string; status?: number; links?: { href: string; label: string }[]; form?: PageForm }): Response {
  const links = (o.links ?? []).map((l) => `<a class="btn${o.form ? ' alt' : ''}" href="${esc(l.href)}">${esc(l.label)}</a>`).join('');
  const form = o.form
    ? `<form method="post" action="${esc(o.form.action)}">${Object.entries(o.form.fields)
        .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
        .join('')}<button class="btn" type="submit" data-confirm>${esc(o.form.label)}</button></form>`
    : '';
  // A form page sends its POST with Origin (the hub checks it): "same-origin" instead of the site-wide no-referrer,
  // which would make browsers send Origin: null on form posts. Cross-origin requests still get no referrer.
  const referrer = o.form ? '<meta name="referrer" content="same-origin">' : '';
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">${referrer}<title>${esc(o.title)} · bWalletX</title>
<style>
*{box-sizing:border-box}html,body{margin:0;background:#000;color:#f5b800;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;overflow-x:hidden}
main{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.card{width:100%;max-width:420px;border:1px solid #f5b800;border-radius:20px;padding:28px 22px;background:#000}
.b{display:inline-grid;place-items:center;width:44px;height:44px;border-radius:50%;background:#f5b800;color:#000;font-weight:800;font-size:24px;margin-bottom:14px}
h1{font-size:22px;margin:0 0 8px}p{margin:0 0 18px;color:#ffd96a;overflow-wrap:anywhere}
.btn{display:inline-block;background:#f5b800;color:#000;border:0;border-radius:999px;padding:10px 18px;text-decoration:none;font:inherit;font-weight:700;margin:4px 8px 0 0;cursor:pointer}
.btn.alt{background:#000;color:#f5b800;box-shadow:inset 0 0 0 1px #f5b800}form{display:inline}
</style></head><body><main><div class="card"><div class="b">b</div><h1>${esc(o.title)}</h1><p>${esc(o.body)}</p>${form}${links}</div></main></body></html>`;
  return new Response(html, {
    status: o.status ?? 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'content-security-policy': "frame-ancestors 'none'" },
  });
}

/** The error page for a bad sign-in link. Never a redirect: an unknown site or address could be a phishing page. */
export function errorPage(reason: string): Response {
  return page({
    title: "This sign-in link isn't valid",
    body: `${reason} For your safety we won't send you on. Go back to the site and try again.`,
    status: 400,
    links: [{ href: 'https://bwalletx.com', label: 'bwalletx.com' }],
  });
}

/** GET /logout without a site's logout_hint: ask first, with a same-origin POST button. */
export function confirmLogoutPage(o: { who: string; clientId: string | null; redirectUri: string | null }): Response {
  const fields: Record<string, string> = {};
  if (o.clientId && o.redirectUri) {
    fields.client_id = o.clientId;
    fields.redirect_uri = o.redirectUri;
  }
  return page({
    title: 'Sign out of all b*X sites?',
    body: `This signs you out here and on every b*X site (signed in as ${o.who}).`,
    form: { action: '/logout', fields, label: 'Sign out of all b*X sites' },
    links: [{ href: o.redirectUri ?? '/', label: 'Stay signed in' }],
  });
}
