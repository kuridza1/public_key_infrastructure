export interface Certificate {
  id: string;
  serialNumber: string;
  prettySerialNumber: string;
  issuedBy: string;
  issuedTo: string;
  validFrom?: Date;
  validUntil?: Date;
  status: string;
  decryptedCertificate: string;
  canSign: boolean;
  pathLen: number;
}
