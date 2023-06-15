import type {
  TransparencyLogInstance,
  ViableTransparencyLogInstance,
} from '../trust.types';

type FilterCriteria = {
  targetDate: Date;
  logID?: Buffer;
};

// Filter the list of tlog instances to only those which match the given log
// ID and have public keys which are valid for the given integrated time.
export function filterTLogInstances(
  tlogInstances: TransparencyLogInstance[],
  criteria: FilterCriteria
): ViableTransparencyLogInstance[] {
  return tlogInstances.filter((tlog): tlog is ViableTransparencyLogInstance => {
    const keyID = tlog.logId?.keyId;
    if (!keyID) {
      return false;
    }

    // If we're filtering by log ID the log IDs don't match, we can't use this
    // tlog
    if (criteria.logID && !keyID.equals(criteria.logID)) {
      return false;
    }

    // If the tlog doesn't have a public key, we can't use it
    const publicKey = tlog.publicKey;
    if (publicKey === undefined) {
      return false;
    }

    // If the tlog doesn't have a rawBytes field, we can't use it
    if (publicKey.rawBytes === undefined) {
      return false;
    }

    // If the tlog doesn't have a validFor field, we don't need to check it
    if (publicKey.validFor === undefined) {
      return true;
    }

    // Check that the integrated time is within the validFor range
    return (
      publicKey.validFor.start !== undefined &&
      publicKey.validFor.start <= criteria.targetDate &&
      (!publicKey.validFor.end || criteria.targetDate <= publicKey.validFor.end)
    );
  });
}
