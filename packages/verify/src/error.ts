class BaseError<T extends string> extends Error {
  code: T;
  cause: any; /* eslint-disable-line @typescript-eslint/no-explicit-any */

  constructor({
    code,
    message,
    cause,
  }: {
    code: T;
    message: string;
    cause?: any /* eslint-disable-line @typescript-eslint/no-explicit-any */;
  }) {
    super(message);
    this.code = code;
    this.cause = cause;
    this.name = this.constructor.name;
  }
}

type VerificationErrorCode = 'CERTIFICATE_ERROR' | 'FOO';

export class VerificationError extends BaseError<VerificationErrorCode> {
  // Using during transition to new error class. Callers should specify their own code
  constructor(message: string) {
    super({
      code: 'CERTIFICATE_ERROR',
      message,
    });
  }
}
