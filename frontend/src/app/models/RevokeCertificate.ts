import {RevocationReason} from './RevocationReason';

export type RevocationReasonName =
  | 'UNSPECIFIED'
  | 'KEY_COMPROMISE'
  | 'AFFILIATION_CHANGED'
  | 'SUPERSEDED'
  | 'CESSATION_OF_OPERATION'
  | 'PRIVILEGE_WITHDRAWN';

export interface RevokeCertificate {
  serialNumber: string;
  revocationReason: RevocationReasonName;
}
