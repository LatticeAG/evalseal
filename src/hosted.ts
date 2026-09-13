/** Hosted/paid surfaces — documented stub interfaces (spec §2.1).
 *
 * The OSS core ships every client-side and verification mechanism. The paid
 * surface — hosted certification runs on Cloudflare Workers + Durable Objects,
 * private R2 evidence buckets, the isolated IssuerSigner service binding — is
 * deployment infrastructure, not library code. These stubs deliberately throw
 * NotImplemented rather than pretend to run server-side primitives locally.
 *
 * Reference: docs/phase0-scope-identity.md (OSS/hosted split), spec §2.1.
 */

const LINK = "Hosted surface — runs on the deployed LatticeAG Workers/DO service. " +
  "See docs/phase0-scope-identity.md (OSS/hosted split) and spec §2.1.";

export class HostedUnavailable extends Error {
  what: string;
  constructor(what: string) {
    super(`${what}: ${LINK}`);
    this.what = what;
    this.name = "NotImplemented";
  }
}

export class DurableObjectNamespace {
  constructor(public binding: string) {}
  get(_id: unknown): never {
    throw new HostedUnavailable(`DurableObjectNamespace(${this.binding}).get`);
  }
}

export class R2Bucket {
  constructor(public binding: string) {}
  put(..._a: unknown[]): never {
    throw new HostedUnavailable(`R2Bucket(${this.binding}).put`);
  }
  get(..._a: unknown[]): never {
    throw new HostedUnavailable(`R2Bucket(${this.binding}).get`);
  }
}

export class IssuerSignerBinding {
  sign(..._a: unknown[]): never {
    throw new HostedUnavailable("IssuerSignerBinding.sign");
  }
}

export function hostedWorkerFetch(..._a: unknown[]): never {
  throw new HostedUnavailable("worker.fetch");
}
