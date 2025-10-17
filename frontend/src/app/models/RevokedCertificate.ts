import {RevocationReason} from './RevocationReason';

export interface RevokedCertificate {
  serialNumber: string;
  prettySerialNumber: string;
  issuedTo: string;
  issuedBy: string;
  decryptedCertificate: string;
  revocationReason: RevocationReason;
}
