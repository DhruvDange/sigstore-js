import { Bundle } from '@sigstore/bundle';

export type Verifier = {
  verify(bundle: Bundle): Promise<void>;
};

class TransparencyLogVerifier implements Verifier {
  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}

class CertificateTransparencyLogVerifier implements Verifier {
  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}

class TimestampAuthorityVerifier implements Verifier {
  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}

class SignatureVerifier implements Verifier {
  async verify(bundle: Bundle): Promise<void> {
    bundle;
  }
}
