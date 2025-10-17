import {ExtendedKeyUsageValue} from './ExtendedKeyUsageValue';
import {KeyUsageValue} from './KeyUsageValue';
import {BasicConstraintsValue, CertificatePolicy, ListOfNames, NamesConstraintsValue} from './CreateCertificate';

export interface CertificateRequest {
  signingOrganization: string;
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
