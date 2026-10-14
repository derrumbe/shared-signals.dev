import type { KeyStore } from './keys';
import type { Transmitter } from './transmitter';
import type { Receiver } from './receiver';
import type { Account } from './account';

export interface Env {
  ASSETS: Fetcher;
  KEYS: DurableObjectNamespace<KeyStore>;
  TRANSMITTER: DurableObjectNamespace<Transmitter>;
  RECEIVER: DurableObjectNamespace<Receiver>;
  ACCOUNT: DurableObjectNamespace<Account>;
  /** Optional RSA private key (PKCS#8 PEM or JWK). Set with `wrangler secret put SSF_SIGNING_KEY`. */
  SSF_SIGNING_KEY?: string;
  /** Workers rate limiting binding, per client IP. Optional so local dev works without it. */
  RATE_LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
}
