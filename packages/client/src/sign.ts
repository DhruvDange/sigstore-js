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
import { SignatureMaterial, SignerFunc } from './types/signature';
import * as sigstore from './types/sigstore';
import { crypto, dsse, oidc } from './util';

import type { CA } from './ca';
import type { Provider } from './identity';
import type { TLog } from './tlog';
import type { TSA } from './tsa';

export interface SignOptions {
  ca: CA;
  tlog: TLog;
  tsa?: TSA;
  identityProviders: Provider[];
  tlogUpload?: boolean;
  signer?: SignerFunc;
}

export class Signer {
  private ca: CA;
  private tlog: TLog;
  private tsa?: TSA;
  private tlogUpload: boolean;
  private signer: SignerFunc;

  private identityProviders: Provider[] = [];

  constructor(options: SignOptions) {
    this.ca = options.ca;
    this.tlog = options.tlog;
    this.tsa = options.tsa;
    this.identityProviders = options.identityProviders;
    this.tlogUpload = options.tlogUpload ?? true;
    this.signer = options.signer || this.signWithEphemeralKey.bind(this);
  }

  public async signBlob(payload: Buffer): Promise<sigstore.Bundle> {
    // Get signature and verification material for payload
    const sigMaterial = await this.signer(payload);

    // Calculate artifact digest
    const digest = crypto.hash(payload);

    // Create a Rekor entry (if tlogUpload is enabled)
    const entry = this.tlogUpload
      ? await this.tlog.createMessageSignatureEntry(digest, sigMaterial)
      : undefined;

    return sigstore.toMessageSignatureBundle({
      digest,
      signature: sigMaterial,
      tlogEntry: entry,
      timestamp: this.tsa
        ? await this.tsa.createTimestamp(sigMaterial.signature)
        : undefined,
    });
  }

  public async signAttestation(
    payload: Buffer,
    payloadType: string
  ): Promise<sigstore.Bundle> {
    // Pre-authentication encoding to be signed
    const paeBuffer = dsse.preAuthEncoding(payloadType, payload);

    // Get signature and verification material for pae
    const sigMaterial = await this.signer(paeBuffer);

    const envelope: sigstore.Envelope = {
      payloadType,
      payload: payload,
      signatures: [
        {
          keyid: sigMaterial.key?.id || '',
          sig: sigMaterial.signature,
        },
      ],
    };

    // Create a Rekor entry (if tlogUpload is enabled)
    const entry = this.tlogUpload
      ? await this.tlog.createDSSEEntry(envelope, sigMaterial)
      : undefined;

    return sigstore.toDSSEBundle({
      envelope,
      signature: sigMaterial,
      tlogEntry: entry,
      timestamp: this.tsa
        ? await this.tsa.createTimestamp(sigMaterial.signature)
        : undefined,
    });
  }

  private async signWithEphemeralKey(
    payload: Buffer
  ): Promise<SignatureMaterial> {
    // Create emphemeral key pair
    const keypair = crypto.generateKeyPair();

    // Retrieve identity token from one of the supplied identity providers
    const identityToken = await this.getIdentityToken();

    // Extract challenge claim from OIDC token
    const subject = oidc.extractJWTSubject(identityToken);

    // Construct challenge value by encrypting subject with private key
    const challenge = crypto.signBlob(Buffer.from(subject), keypair.privateKey);

    // Create signing certificate
    const certificates = await this.ca.createSigningCertificate(
      identityToken,
      keypair.publicKey,
      challenge
    );

    // Generate artifact signature
    const signature = crypto.signBlob(payload, keypair.privateKey);

    return {
      signature,
      certificates,
      key: undefined,
    };
  }

  private async getIdentityToken(): Promise<string> {
    const aggErrs = [];

    for (const provider of this.identityProviders) {
      try {
        const token = await provider.getToken();
        if (token) {
          return token;
        }
      } catch (err) {
        aggErrs.push(err);
      }
    }

    throw new Error(`Identity token providers failed: ${aggErrs}`);
  }
}