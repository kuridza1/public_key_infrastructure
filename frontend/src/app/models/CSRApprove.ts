import {CreateCertificate} from './CreateCertificate';

export interface CSRApprove {
  requestId: string;
  requestForm: CreateCertificate;
}
