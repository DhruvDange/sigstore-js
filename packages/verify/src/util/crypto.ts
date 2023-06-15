import crypto, { BinaryLike } from 'crypto';

const SHA256_ALGORITHM = 'sha256';

export function createPublicKey(key: string | Buffer): crypto.KeyObject {
  if (typeof key === 'string') {
    return crypto.createPublicKey(key);
  } else {
    return crypto.createPublicKey({ key, format: 'der', type: 'spki' });
  }
}

export function hash(...data: BinaryLike[]): Buffer {
  const hash = crypto.createHash(SHA256_ALGORITHM);
  for (const d of data) {
    hash.update(d);
  }
  return hash.digest();
}

export function verify(
  data: Buffer,
  key: crypto.KeyLike,
  signature: Buffer,
  algorithm?: string
): boolean {
  // The try/catch is to work around an issue in Node 14.x where verify throws
  // an error in some scenarios if the signature is invalid.
  try {
    return crypto.verify(algorithm, data, key, signature);
  } catch (e) {
    /* istanbul ignore next */
    return false;
  }
}

export function bufferEqual(a: Buffer, b: Buffer): boolean {
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    /* istanbul ignore next */
    return false;
  }
}
