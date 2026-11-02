/** One Hub per process, shared by every route bundle (Next compiles routes separately, so it lives on globalThis). */
import { issuer } from './config';
import { Hub } from './hub';
import { loadSigner } from './keys';
import { lookupNames } from './paymail';
import { loadRegistry } from './registry';
import { storeFromEnv } from './store';

const g = globalThis as { __bwxHub?: Promise<Hub> };

export function getHub(): Promise<Hub> {
  g.__bwxHub ??= (async () => new Hub({ issuer: issuer(), registry: loadRegistry(), store: await storeFromEnv(), signer: await loadSigner(), lookup: (k) => lookupNames(k) }))();
  // A failed start (missing env in production) is retried on the next request instead of being cached.
  g.__bwxHub.catch(() => {
    g.__bwxHub = undefined;
  });
  return g.__bwxHub;
}
