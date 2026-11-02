/** Small server-rendered pages (error, signed out). Gold on black, phone-first, no horizontal scroll. */

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export function page(o: { title: string; body: string; status?: number; links?: { href: string; label: string }[] }): Response {
  const links = (o.links ?? []).map((l) => `<a class="btn" href="${esc(l.href)}">${esc(l.label)}</a>`).join('');
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(o.title)} · bWalletX</title>
<style>
*{box-sizing:border-box}html,body{margin:0;background:#000;color:#f5b800;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;overflow-x:hidden}
main{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.card{width:100%;max-width:420px;border:1px solid #f5b800;border-radius:20px;padding:28px 22px;background:#000}
.b{display:inline-grid;place-items:center;width:44px;height:44px;border-radius:50%;background:#f5b800;color:#000;font-weight:800;font-size:24px;margin-bottom:14px}
h1{font-size:22px;margin:0 0 8px}p{margin:0 0 18px;color:#ffd96a;overflow-wrap:anywhere}
.btn{display:inline-block;background:#f5b800;color:#000;border-radius:999px;padding:10px 18px;text-decoration:none;font-weight:700;margin:4px 8px 0 0}
</style></head><body><main><div class="card"><div class="b">b</div><h1>${esc(o.title)}</h1><p>${esc(o.body)}</p>${links}</div></main></body></html>`;
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
