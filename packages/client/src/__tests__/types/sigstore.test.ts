/*
Copyright 2022 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import type { Entry } from '../../external/rekor';
import { SignatureMaterial } from '../../types/signature';
import * as sigstore from '../../types/sigstore';
import { encoding as enc, pem } from '../../util';

describe('isCAVerificationOptions', () => {
  describe('when the verification options are for a CA', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      ctlogOptions: {
        detachedSct: false,
        disable: false,
        threshold: 1,
      },
      signers: {
        $case: 'certificateIdentities',
        certificateIdentities: {
          identities: [],
        },
      },
    };
    it('returns true', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(true);
    });
  });

  describe('when the verification options do not include ctlogOptions', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      signers: {
        $case: 'certificateIdentities',
        certificateIdentities: {
          identities: [],
        },
      },
    };

    it('returns false', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(false);
    });
  });

  describe('when the verification options do not include signers', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      ctlogOptions: {
        detachedSct: false,
        disable: false,
        threshold: 1,
      },
    };

    it('returns true', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(true);
    });
  });

  describe('when the verification options include public key signers', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      ctlogOptions: {
        detachedSct: false,
        disable: false,
        threshold: 1,
      },
      signers: {
        $case: 'publicKeys',
        publicKeys: {
          publicKeys: [],
        },
      },
    };

    it('returns false', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(false);
    });
  });
});

describe('bundle', () => {
  const signature = Buffer.from('signature');
  const certificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;

  describe('toDSSEBundle', () => {
    const sigMaterial: SignatureMaterial = {
      signature,
      certificates: [certificate],
      key: undefined,
    };
    const envelope: sigstore.Envelope = {
      payloadType: 'application/vnd.in-toto+json',
      payload: Buffer.from('payload'),
      signatures: [
        {
          keyid: '',
          sig: signature,
        },
      ],
    };

    const entryKind = {
      kind: 'intoto',
      apiVersion: '0.0.2',
    };

    const rekorEntry = {
      uuid: 'a12bc3',
      body: enc.base64Encode(JSON.stringify(entryKind)),
      integratedTime: 1654015743,
      logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        signedEntryTimestamp: Buffer.from('set').toString('base64'),
        inclusionProof: {
          hashes: ['deadbeef', 'feedface'],
          logIndex: 12345,
          rootHash: 'fee1dead',
          treeSize: 12346,
          checkpoint: 'checkpoint',
        },
      },
    } satisfies Entry;

    const timestamp = Buffer.from('timestamp');

    it('returns a valid DSSE bundle', () => {
      const b = sigstore.toDSSEBundle({
        envelope,
        signature: sigMaterial,
        tlogEntry: rekorEntry,
        timestamp: timestamp,
      });

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      if (b.content?.$case === 'dsseEnvelope') {
        expect(b.content.dsseEnvelope).toEqual(envelope);
      } else {
        fail('Expected dsseEnvelope');
      }

      // Verification material
      if (b.verificationMaterial?.content?.$case === 'x509CertificateChain') {
        const chain = b.verificationMaterial.content.x509CertificateChain;
        expect(chain).toBeTruthy();
        expect(chain.certificates).toHaveLength(1);
        expect(chain.certificates[0].rawBytes).toEqual(pem.toDER(certificate));
      } else {
        fail('Expected x509CertificateChain');
      }

      // TLog entry
      expect(b.verificationMaterial?.tlogEntries).toHaveLength(1);

      const tlog = b.verificationMaterial?.tlogEntries[0];
      expect(tlog?.inclusionPromise).toBeTruthy();
      expect(
        tlog?.inclusionPromise?.signedEntryTimestamp.toString('base64')
      ).toEqual(rekorEntry.verification.signedEntryTimestamp);
      expect(tlog?.integratedTime).toEqual(
        rekorEntry.integratedTime.toString()
      );
      expect(tlog?.logId).toBeTruthy();
      expect(tlog?.logId?.keyId).toBeTruthy();
      expect(tlog?.logId?.keyId.toString('hex')).toEqual(rekorEntry.logID);
      expect(tlog?.logIndex).toEqual(rekorEntry.logIndex.toString());
      expect(tlog?.kindVersion?.kind).toEqual(entryKind.kind);
      expect(tlog?.kindVersion?.version).toEqual(entryKind.apiVersion);
      expect(tlog?.inclusionProof?.checkpoint?.envelope).toEqual(
        rekorEntry.verification.inclusionProof.checkpoint
      );
      expect(tlog?.inclusionProof?.hashes).toHaveLength(2);
      expect(tlog?.inclusionProof?.hashes[0]).toEqual(
        Buffer.from(rekorEntry.verification.inclusionProof.hashes[0], 'hex')
      );
      expect(tlog?.inclusionProof?.hashes[1]).toEqual(
        Buffer.from(rekorEntry.verification.inclusionProof.hashes[1], 'hex')
      );
      expect(tlog?.inclusionProof?.logIndex).toEqual(
        rekorEntry.verification.inclusionProof.logIndex.toString()
      );
      expect(tlog?.inclusionProof?.rootHash).toEqual(
        Buffer.from(rekorEntry.verification.inclusionProof.rootHash, 'hex')
      );
      expect(tlog?.inclusionProof?.treeSize).toEqual(
        rekorEntry.verification.inclusionProof.treeSize.toString()
      );

      // Timestamp verification data
      expect(
        b.verificationMaterial?.timestampVerificationData?.rfc3161Timestamps
      ).toHaveLength(1);
      const ts =
        b.verificationMaterial?.timestampVerificationData?.rfc3161Timestamps[0];
      expect(ts?.signedTimestamp).toEqual(timestamp);
    });
  });

  describe('toMessageSignatureBundle', () => {
    const sigMaterial: SignatureMaterial = {
      signature,
      certificates: undefined,
      key: { value: 'key', id: 'hint' },
    };

    const digest = Buffer.from('digest');

    it('returns a valid message signature bundle', () => {
      const b = sigstore.toMessageSignatureBundle({
        digest,
        signature: sigMaterial,
      });

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      if (b.content?.$case === 'messageSignature') {
        expect(b.content.messageSignature.messageDigest?.algorithm).toEqual(
          sigstore.HashAlgorithm.SHA2_256
        );
        expect(b.content.messageSignature.messageDigest?.digest).toEqual(
          digest
        );
        expect(b.content.messageSignature.signature).toEqual(signature);
      } else {
        fail('Expected messageSignature');
      }

      // Verification material
      if (b.verificationMaterial?.content?.$case === 'publicKey') {
        const publicKey = b.verificationMaterial.content.publicKey;
        expect(publicKey).toBeTruthy();
        expect(publicKey.hint).toEqual('hint');
      } else {
        fail('Expected publicKey');
      }

      expect(b.verificationMaterial?.timestampVerificationData).toBeUndefined();
      expect(b.verificationMaterial?.tlogEntries).toHaveLength(0);
    });
  });
});