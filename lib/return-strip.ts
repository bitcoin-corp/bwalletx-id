// A plain module (not 'use client'), so the root layout (a server component) gets the string itself.

/**
 * Runs inline (with the CSP nonce) in the layout's <head>, before the app's own code, on every path: drops a
 * bWalletX connect return fragment (`#bwx=ok&…`) from the address bar. The hub's sign-in (v2) never pairs a page with a
 * wallet, so nothing here uses the fragment; a stray one (an old wallet build, a crafted link) must not stay in the
 * address bar or in history where a later script or history sync could read it. Same test as @bwalletx/connect's
 * isReturnHash.
 */
export const RETURN_STRIP_SCRIPT =
  "(function(){try{if(/(^#|&)bwx=ok(&|$)/.test(location.hash)){history.replaceState(history.state,'',location.pathname+location.search);}}catch(e){}})();";
