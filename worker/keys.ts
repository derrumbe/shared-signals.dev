import { DurableObject } from 'cloudflare:workers';
import { generatePrivateJwk, type Jwk } from './jose';
import type { Env } from './env';

/** Holds the generated signing key when no SSF_SIGNING_KEY secret is set. One instance, by name. */
export class KeyStore extends DurableObject<Env> {
  async privateJwk(): Promise<Jwk> {
    // blockConcurrencyWhile so two first requests can't each generate (and store) a different key.
    return this.ctx.blockConcurrencyWhile(async () => {
      let jwk = await this.ctx.storage.get<Jwk>('private-jwk');
      if (!jwk) {
        jwk = await generatePrivateJwk();
        await this.ctx.storage.put('private-jwk', jwk);
      }
      return jwk;
    });
  }
}
