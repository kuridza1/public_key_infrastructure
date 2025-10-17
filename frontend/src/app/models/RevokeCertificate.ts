import {RevocationReason} from './RevocationReason';

export interface RevokeCertificate {
  serialNumber: string;
  revocationReason: RevocationReason;
}
