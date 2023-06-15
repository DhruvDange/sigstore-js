import type { Envelope, TransparencyLogEntry } from '@sigstore/protobuf-specs';
export type SignatureProvider = {
  signature(): Buffer;
};

export type KeyIDProvider = {
  keyID(): string;
};

export type CertificateProvider = {
  certificateChain(): Buffer[];
};

export type EnvelopeProvider = {
  envelope(): Envelope;
};

export type SignedTimestampProvider = {
  timestamps(): Buffer[];
};

export type TLogEntryProvider = {
  tlogEntries(): TransparencyLogEntry;
};

export type SignedEntity = SignatureProvider &
  KeyIDProvider &
  CertificateProvider &
  EnvelopeProvider &
  SignedTimestampProvider &
  TLogEntryProvider;

export type Policy = {
  verify(entity: SignedEntity): Promise<void>;
};
