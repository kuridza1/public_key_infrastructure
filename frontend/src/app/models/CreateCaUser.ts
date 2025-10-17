export interface CreateCaUser {
  name: string;
  surname: string;
  organization: string;
  email: string;
  password: string;
  initialSigningCertificateId: string;
}
