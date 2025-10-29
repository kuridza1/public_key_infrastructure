export interface CertificateTemplate {
  id: string;
  name: string;
  caIssuerId: string;
  caIssuerName: string;
  commonNameRegex?: string;
  sanRegex?: string;
  maxTtlDays?: number;
  keyUsage?: string;
  extendedKeyUsage?: string;
  basicConstraints?: string;
  createdBy: string;
  createdAt: string;
}

export interface CreateTemplateRequest {
  name: string;
  caIssuerId: string;
  commonNameRegex?: string;
  sanRegex?: string;
  maxTtlDays?: number;
  keyUsage?: string;
  extendedKeyUsage?: string;
  basicConstraints?: string;
}

export interface TemplateResponse {
  id: string;
  name: string;
  caIssuerName: string;
  commonNameRegex?: string;
  sanRegex?: string;
  maxTtlDays?: number;
  keyUsage?: string;
  extendedKeyUsage?: string;
  basicConstraints?: string;
  createdBy: string;
  createdAt: string;
}