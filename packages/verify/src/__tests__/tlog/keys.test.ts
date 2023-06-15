import { HashAlgorithm, PublicKeyDetails } from '@sigstore/protobuf-specs';
import { filterTLogInstances } from '../../tlog/keys';
import type { TransparencyLogInstance } from '../../trust.types';

describe('filterTLogInstances', () => {
  const tlogInstances: TransparencyLogInstance[] = [
    {
      logId: { keyId: Buffer.from('log1') },
      baseUrl: 'https://logid1.sigstore.dev',
      hashAlgorithm: HashAlgorithm.SHA2_256,
      publicKey: {
        rawBytes: Buffer.from('rawBytes1'),
        keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      },
    },
    {
      logId: { keyId: Buffer.from('log2') },
      baseUrl: 'https://logid2.sigstore.dev',
      hashAlgorithm: HashAlgorithm.SHA2_256,
      publicKey: {
        rawBytes: Buffer.from('rawBytes2'),
        keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
        validFor: {
          start: new Date('2020-01-01'),
          end: new Date('2020-12-31'),
        },
      },
    },
    {
      logId: { keyId: Buffer.from('log3') },
      baseUrl: 'https://logid3.sigstore.dev',
      hashAlgorithm: HashAlgorithm.SHA2_256,
      publicKey: {
        rawBytes: Buffer.from('rawBytes3'),
        keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
        validFor: {
          start: new Date('2020-01-01'),
        },
      },
    },
    {
      logId: { keyId: Buffer.from('log4') },
      baseUrl: 'https://logid4.sigstore.dev',
      hashAlgorithm: HashAlgorithm.SHA2_256,
      publicKey: undefined,
    },
    {
      logId: { keyId: Buffer.from('log5') },
      baseUrl: 'https://logid6.sigstore.dev',
      hashAlgorithm: HashAlgorithm.SHA2_256,
      publicKey: {
        keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      },
    },
    {
      logId: undefined,
      baseUrl: 'https://logid6.sigstore.dev',
      hashAlgorithm: HashAlgorithm.SHA2_256,
      publicKey: undefined,
    },
  ];

  describe('when filtering by date', () => {
    it('returns instances valid during the given date', () => {
      const tlogs = filterTLogInstances(tlogInstances, {
        targetDate: new Date('2020-02-01'),
      });

      expect(tlogs).toHaveLength(3);
      expect(tlogs[0].logId.keyId).toEqual(Buffer.from('log1'));
      expect(tlogs[1].logId.keyId).toEqual(Buffer.from('log2'));
      expect(tlogs[2].logId.keyId).toEqual(Buffer.from('log3'));
    });
  });

  describe('when filtering by date and log ID', () => {
    it('returns instances valid during the given date for the given log ID', () => {
      const tlogs = filterTLogInstances(tlogInstances, {
        targetDate: new Date('2020-02-01'),
        logID: Buffer.from('log2'),
      });

      expect(tlogs).toHaveLength(1);
      expect(tlogs[0].logId.keyId).toEqual(Buffer.from('log2'));
    });
  });
});
