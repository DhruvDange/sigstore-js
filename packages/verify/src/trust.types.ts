import type {
  PublicKey,
  TransparencyLogInstance,
} from '@sigstore/protobuf-specs';
import type { WithRequired } from './utility.types';
export { HashAlgorithm, PublicKeyDetails } from '@sigstore/protobuf-specs';
export type {
  PublicKey,
  TransparencyLogInstance,
} from '@sigstore/protobuf-specs';

export type ViableTransparencyLogInstance = TransparencyLogInstance & {
  logId: NonNullable<TransparencyLogInstance['logId']>;
  publicKey: WithRequired<PublicKey, 'rawBytes'>;
};
