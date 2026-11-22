// End-to-end: the full redirect dance between the hub (localhost:3400) and BSVAPI (localhost:3401) in headless Chrome.
// The wallet is a THROWAWAY key made here with @bsv/sdk ProtoWallet, playing bWalletX's side of hub sign-in v2 from
// Node (it POSTs straight to the hub; the page never sees it). Never a real key. Uses localhost, not 127.0.0.1 (bWalletX refuses IP origins).
//
//   HUB=http://localhost:3400 SITE=http://localhost:3401 node test/e2e/run.mjs
//   env: PUPPETEER (path to puppeteer's ESM entry), CHROME (Chrome binary), SHOTS (dir for screenshots, outside git)
import { PrivateKey, ProtoWallet } from '@bsv/sdk';
import os from 'node:os';
import path from 'node:path';

const HUB = process.env.HUB ?? 'http://localhost:3400';
const SITE = process.env.SITE ?? 'http://localhost:3401';
const PUPPETEER = process.env.PUPPETEER ?? '/Volumes/2026/Projects/bitcoin-corp-website/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js';
const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const SHOTS = process.env.SHOTS ?? os.tmpdir();
const { default: puppeteer } = await import(PUPPETEER);

const root = PrivateKey.fromRandom(); // throwaway, in memory only
const pw = new ProtoWallet(root);
const identityKey = root.toPublicKey().toString();
const calls = [];
let pass = 0;
let fail = 0;
const check = (ok, what) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`);
  ok ? pass++ : fail++;
};

const browser = await puppeteer.launch({
  headless: 'new',
  executablePath: CHROME,
  userDataDir: path.join(SHOTS, `e2e-profile-${Date.now()}`),
  args: ['--no-first-run', '--no-default-browser-check'],
  defaultViewport: { width: 390, height: 844, isMobile: true, hasTouch: false },
});
const page = await browser.newPage();
const nav = [];
// every hop of a redirect chain (303s included) is its own navigation request
page.on('request', (r) => r.isNavigationRequest() && r.frame() === page.mainFrame() && nav.push(r.url()));
page.on('pageerror', (e) => console.log('  [pageerror]', e.message));

// The test wallet (hub sign-in v2): it never talks to the page. Like bWalletX, it reads the request id from the page's
// "Open bWalletX" link, GETs what to show from the hub, checks the code matches the page, signs, and POSTs straight to
// the hub (no Origin header: a native app).
async function approveInWallet(p) {
  await p.waitForSelector('[data-open-wallet]', { timeout: 120000 });
  const link = await p.$eval('[data-open-wallet]', (e) => e.getAttribute('href'));
  const shown = await p.$eval('[data-user-code]', (e) => e.textContent.trim());
  const requestId = new URL(link.replace('bwalletx://', 'https://x/')).searchParams.get('r');
  const info = await (await fetch(`${HUB}/api/wallet-signin?r=${requestId}`)).json();
  calls.push({ method: 'info', args: info });
  if (info.userCode !== shown) throw new Error(`code mismatch: page ${shown}, hub ${info.userCode}`);
  const { signature } = await pw.createSignature({ protocolID: info.protocolID, keyID: info.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(info.message)) });
  calls.push({ method: 'createSignature', args: { protocolID: info.protocolID, keyID: info.keyID, message: info.message } });
  const r = await fetch(`${HUB}/api/wallet-signin`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ requestId, userCode: info.userCode, identityKey, signature: Array.from(signature) }),
  });
  if (r.status !== 200) throw new Error(`wallet approve ${r.status}`);
  return info;
}

const siteCookies = async () => (await page.cookies(SITE)).filter((c) => c.name === 'bwx_site');
const sessionJson = () => page.evaluate(async () => (await fetch('/sso/session')).json());

try {
  // 1. First visit: quiet check (prompt=none) to the hub, no hub session → straight back, signed out.
  await page.goto(SITE + '/', { waitUntil: 'networkidle0', timeout: 120000 });
  await page.waitForSelector('[data-bwx-sso-signin]', { timeout: 120000 });
  check(nav.some((u) => u.startsWith(SITE + '/sso/callback') && u.includes('error=login_required')), 'first visit: quiet prompt=none round trip came back login_required');
  check(new URL(page.url()).origin === SITE && new URL(page.url()).pathname === '/', `back on the site, signed out (${page.url()})`);
  const btnText = await page.$eval('[data-bwx-sso-signin]', (e) => e.textContent);
  check(/Sign in/.test(btnText), `top-right button says "${btnText.trim()}"`);
  const box = await page.$eval('[data-bwx-sso-signin]', (e) => { const r = e.getBoundingClientRect(); return { right: r.right, top: r.top, w: innerWidth }; });
  check(box.right > box.w * 0.6 && box.top < 80, `button sits top-right (right=${Math.round(box.right)}/${box.w}, top=${Math.round(box.top)})`);
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal scroll at phone width (site)');
  await page.screenshot({ path: path.join(SHOTS, 'e2e-1-site-signed-out.png') });

  // 2. Click Sign in → hub /authorize → hub sign-in page.
  nav.length = 0;
  await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 120000 }), page.click('[data-bwx-sso-signin]')]);
  await page.waitForSelector('[data-signin-button]', { timeout: 120000 });
  check(page.url().startsWith(HUB + '/signin?'), `hub sign-in page (${page.url().split('?')[0]})`);
  const explain = await page.$eval('[data-explain]', (e) => e.textContent.replace(/\s+/g, ' ').trim());
  check(explain === 'Sign in: shares only your public identity key, moves no money', `one plain line before the sheet: "${explain}"`);
  const title = await page.$eval('h1', (e) => e.textContent);
  check(title === 'Sign in to BSVAPI', `names the site: "${title}"`);
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal scroll at phone width (hub)');
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  check(bg === 'rgb(0, 0, 0)', `hub is gold on black (body ${bg})`);
  await page.screenshot({ path: path.join(SHOTS, 'e2e-2-hub-signin.png') });

  // 3. Start the sign-in: the page shows a code; the wallet approves straight to the hub; the page polls and goes on.
  nav.length = 0;
  calls.length = 0;
  await page.click('[data-signin-button]');
  const info = await approveInWallet(page);
  await page.waitForFunction((site) => location.origin === site, { timeout: 120000 }, SITE);
  await page.waitForSelector('[data-bwx-sso-chip]', { timeout: 120000 });
  const sig = calls.find((c) => c.method === 'createSignature');
  check(JSON.stringify(sig?.args?.protocolID) === JSON.stringify([2, 'admin bwalletx hub signin']), `wallet signed under the admin-reserved hub protocol ${JSON.stringify(sig?.args?.protocolID)}`);
  check(sig?.args?.keyID === info.requestId && sig.args.message.includes(`Code: ${info.userCode}`) && sig.args.message.includes(`Hub: ${new URL(HUB).host}`), 'signed message names the hub, the request and the code');
  check(!(await page.cookies(HUB)).some((c) => c.name.endsWith('bwx_signin') && c.value), 'pending sign-in cookie cleared after use');
  check(nav.some((u) => u.startsWith(SITE + '/sso/callback?code=')), 'hub redirected to BSVAPI /sso/callback with a code');
  check(nav.some((u) => u.startsWith(HUB + '/authorize?')), 'went through hub /authorize after the wallet sign-in');
  const cookies = await siteCookies();
  check(cookies.length === 1 && cookies[0].httpOnly && cookies[0].sameSite === 'Lax', `BSVAPI session cookie set: bwx_site httpOnly=${cookies[0]?.httpOnly} sameSite=${cookies[0]?.sameSite}`);
  check(!(await page.evaluate(() => document.cookie)).includes('bwx_site'), 'page JavaScript cannot read bwx_site');
  const hubCookie = (await page.cookies(HUB)).find((c) => c.name === 'bwx_hub');
  check(!!hubCookie && hubCookie.httpOnly && hubCookie.sameSite === 'Lax', `hub cookie bwx_hub httpOnly=${hubCookie?.httpOnly} sameSite=${hubCookie?.sameSite}`);
  const chip = await page.$eval('[data-bwx-sso-chip]', (e) => e.textContent);
  check(chip.includes(identityKey.slice(0, 6)) || chip.includes('@'), `account chip renders: "${chip}"`);
  const s = await sessionJson();
  check(s.signedIn === true && s.identityKey === identityKey, `GET /sso/session → signedIn as the test key (${identityKey.slice(0, 10)}…)`);
  const toast = await page.$('.bwx-sso-toast');
  check(!!toast, 'Signed in as … toast shown');
  await page.screenshot({ path: path.join(SHOTS, 'e2e-3-site-chip.png') });
  await page.click('[data-bwx-sso-chip]');
  const items = await page.$$eval('.bwx-sso-item', (els) => els.map((e) => e.textContent));
  check(items.includes('Sign out of this site') && items.includes('Sign out of all b*X sites'), `chip menu: ${items.join(' | ')}`);
  await page.screenshot({ path: path.join(SHOTS, 'e2e-4-chip-menu.png') });
  await page.keyboard.press('Escape');

  // 4. Single sign-on: drop only the BSVAPI session; the quiet check signs back in with NO wallet prompt.
  await page.deleteCookie(...(await siteCookies()).map((c) => ({ name: c.name, url: SITE })));
  await page.evaluate(() => sessionStorage.clear());
  calls.length = 0;
  nav.length = 0;
  await page.goto(SITE + '/', { waitUntil: 'networkidle0', timeout: 120000 });
  await page.waitForSelector('[data-bwx-sso-chip]', { timeout: 120000 });
  check(calls.length === 0 && nav.some((u) => u.startsWith(SITE + '/sso/callback?code=')), 'signed in again from the hub session alone (no wallet call): one sign-in, every site');

  // 5. Sign out of all b*X sites → hub /logout → epoch bumped → back on BSVAPI, signed out.
  await page.click('[data-bwx-sso-chip]');
  nav.length = 0;
  await Promise.all([
    page.waitForRequest((r) => r.url().startsWith(HUB + '/logout'), { timeout: 60000 }),
    page.evaluate(() => [...document.querySelectorAll('.bwx-sso-item')].find((e) => e.textContent === 'Sign out of all b*X sites').click()),
  ]);
  await page.waitForFunction((site) => location.origin === site && document.readyState === 'complete', { timeout: 120000 }, SITE);
  await page.waitForSelector('[data-bwx-sso-signin]', { timeout: 120000 });
  check(page.url() === SITE + '/', `hub sent the visitor back to the registered home page (${page.url()})`);
  check(nav.some((u) => u.startsWith(HUB + '/logout?')), 'went through hub /logout');
  check(nav.some((u) => u.startsWith(HUB + '/logout?') && new URL(u).searchParams.get('logout_hint')), "the site's link carried a logout_hint (one click, no confirm page)");
  check((await siteCookies()).length === 0, 'BSVAPI session cookie cleared');
  check(!(await page.cookies(HUB)).some((c) => c.name === 'bwx_hub' && c.value), 'hub cookie cleared');
  const after = await sessionJson();
  check(after.signedIn === false, 'GET /sso/session → signed out');
  // and the old hub session can't mint codes: a quiet check now comes back login_required
  await page.evaluate(() => sessionStorage.clear());
  nav.length = 0;
  await page.goto(SITE + '/', { waitUntil: 'networkidle0', timeout: 120000 });
  await page.waitForSelector('[data-bwx-sso-signin]', { timeout: 120000 });
  check(nav.some((u) => u.includes('error=login_required')), 'after logout a quiet check returns login_required');
  await page.screenshot({ path: path.join(SHOTS, 'e2e-5-signed-out.png') });

  // 6. /logout can't be triggered by a foreign page. Sign in again first.
  await page.evaluate(() => sessionStorage.clear());
  await page.goto(SITE + '/', { waitUntil: 'networkidle0', timeout: 120000 });
  await page.waitForSelector('[data-bwx-sso-signin]', { timeout: 120000 });
  await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 120000 }), page.click('[data-bwx-sso-signin]')]);
  await page.waitForSelector('[data-signin-button]', { timeout: 120000 });
  await page.click('[data-signin-button]');
  await approveInWallet(page);
  await page.waitForFunction((site) => location.origin === site, { timeout: 120000 }, SITE);
  await page.waitForSelector('[data-bwx-sso-chip]', { timeout: 120000 });
  const hubLive = async () => (await page.cookies(HUB)).some((c) => c.name === 'bwx_hub' && c.value);
  check(await hubLive(), 'signed in again (hub cookie set)');
  //   a. a plain link to the hub's /logout (no hint): a confirm page, nobody signed out
  let resp = await page.goto(`${HUB}/logout?client_id=bsvapi&redirect_uri=${encodeURIComponent(SITE + '/')}`, { waitUntil: 'networkidle0' });
  const confirmTitle = await page.$eval('h1', (e) => e.textContent);
  check(resp.status() === 200 && confirmTitle === 'Sign out of all b*X sites?' && !!(await page.$('form[method="post"] [data-confirm]')), `GET /logout without a hint → confirm page ("${confirmTitle}")`);
  check(await hubLive(), 'the link alone signed nobody out');
  await page.screenshot({ path: path.join(SHOTS, 'e2e-6-logout-confirm.png') });
  //   b. a cross-site auto-submitting form from another origin (the site stands in for "evil"): refused
  await page.goto(SITE + '/', { waitUntil: 'networkidle0' });
  const [xs] = await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle0' }),
    page.evaluate((hub) => {
      const f = document.createElement('form');
      f.method = 'POST';
      f.action = hub + '/logout';
      document.body.appendChild(f);
      f.submit();
    }, HUB),
  ]);
  check(xs.status() === 403, `cross-site POST /logout refused (${xs.status()})`);
  check(await hubLive(), 'still signed in after the cross-site POST');
  //   c. the confirm button (same-origin POST, Origin = hub) does sign out
  await page.goto(`${HUB}/logout?client_id=bsvapi&redirect_uri=${encodeURIComponent(SITE + '/')}`, { waitUntil: 'networkidle0' });
  const [done] = await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle0' }), page.click('[data-confirm]')]);
  await page.waitForFunction((site) => location.origin === site, { timeout: 120000 }, SITE).catch(() => {});
  check(!(await hubLive()) && page.url() === SITE + '/', `confirm button signed out and returned to the site (${page.url()}, ${done?.status()})`);

  // 7. Open redirect attempt at the hub: unregistered redirect_uri → error page, no redirect.
  const r = await page.goto(`${HUB}/authorize?client_id=bsvapi&redirect_uri=${encodeURIComponent('https://evil.example/cb')}&state=${'s'.repeat(20)}&code_challenge=${'c'.repeat(43)}&code_challenge_method=S256`);
  check(r.status() === 400 && new URL(page.url()).origin === HUB, `unregistered redirect_uri → hub error page (${r.status()}), no redirect`);
} catch (e) {
  fail++;
  console.log('FAIL  ', e.message);
  await page.screenshot({ path: path.join(SHOTS, 'e2e-error.png') }).catch(() => {});
} finally {
  await browser.close();
}
console.log(`\nE2E: ${pass} passed, ${fail} failed. Screenshots in ${SHOTS}`);
process.exit(fail ? 1 : 0);
