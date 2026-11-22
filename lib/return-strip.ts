// A plain module (not 'use client'), so the root layout (a server component) gets the string itself.

/**
 * Runs inline in the layout's <head>, before the app's own code: on the root page (where bWalletX returns a phone),
 * moves `#bwx=ok&…` off the address bar (so nothing that loads later, and no history sync, can read it) into
 * window.__bwxReturn for <Returned/>. Same test as @bwalletx/connect's own isReturnHash; other pages are left to
 * connect, which strips the fragment itself when its module loads.
 */
export const RETURN_STRIP_SCRIPT =
  "(function(){try{var h=location.hash;if(location.pathname==='/'&&/(^#|&)bwx=ok(&|$)/.test(h)){window.__bwxReturn=h;history.replaceState(history.state,'',location.pathname+location.search);}}catch(e){}})();";
