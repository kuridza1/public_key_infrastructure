import {ExtendedKeyUsageValue} from './ExtendedKeyUsageValue';
import {KeyUsageValue} from './KeyUsageValue';

export interface CreateCertificate {
  signingCertificate: string;
  commonName: string;
  organization: string;
  organizationalUnit: string;
  email: string;
  country: string;
  notBefore?: Date;
  notAfter?: Date;
  keyUsage?: KeyUsageValue[];
  extendedKeyUsage?: ExtendedKeyUsageValue[];
  subjectAlternativeNames?: ListOfNames;
  issuerAlternativeNames?: ListOfNames;
  nameConstraints?: NamesConstraintsValue;
  basicConstraints?: BasicConstraintsValue;
  certificatePolicy?: CertificatePolicy;
}

export interface ListOfNames {
  value: string;
}

export interface NamesConstraintsValue {
  permitted?: ListOfNames;
  excluded?: ListOfNames;
}

export interface BasicConstraintsValue {
  isCa: boolean;
  pathLen?: number;
}

export interface CertificatePolicy {
  policyIdentifier: string;
  cpsUri: string;
  userNotice: string;
}
