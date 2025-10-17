import {ExtendedKeyUsageValue} from './ExtendedKeyUsageValue';
import {KeyUsageValue} from './KeyUsageValue';
import {BasicConstraintsValue, CertificatePolicy, ListOfNames, NamesConstraintsValue} from './CreateCertificate';

export interface CSRResponse {
  id: string;
  commonName: string;
  organization: string;
  organizationalUnit: string;
  email: string;
  country: string;
  notBefore: Date | null;
  notAfter: Date | null;
  keyUsage?: KeyUsageValue[];
  extendedKeyUsage?: ExtendedKeyUsageValue[];
  subjectAlternativeNames?: ListOfNames;
  issuerAlternativeNames?: ListOfNames;
  nameConstraints?: NamesConstraintsValue;
  basicConstraints?: BasicConstraintsValue;
  certificatePolicy?: CertificatePolicy;
}
