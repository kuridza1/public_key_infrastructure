export interface CaUser {
  id: string;
  name: string;
  surname: string;
  organization: string;
  email: string;
  minValidFrom?: Date;
  maxValidUntil?: Date;
}
