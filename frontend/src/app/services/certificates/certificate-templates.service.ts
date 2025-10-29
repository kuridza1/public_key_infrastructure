import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { AuthService } from '../auth/auth.service';

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

@Injectable({
  providedIn: 'root'
})
export class CertificateTemplateService {
  httpClient = inject(HttpClient)
  auth = inject(AuthService);
  urlCore = "https://localhost:8081/api/templates"

  // Helper method to create headers
  private createHeaders(): HttpHeaders {
    if (!this.auth.userId || !this.auth.role) {
      throw new Error('User authentication data is not available');
    }

    return new HttpHeaders({
      'userId': this.auth.userId,
      'role': this.auth.role
    } as { [key: string]: string });
  }

  // Get all templates for current user
  getTemplates(): Observable<TemplateResponse[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<TemplateResponse[]>(this.urlCore, { headers: headers });
  }

  // Get templates for specific CA certificate
  getTemplatesForCa(caId: string): Observable<TemplateResponse[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<TemplateResponse[]>(`${this.urlCore}/ca/${caId}`, { headers: headers });
  }

  // Create new template
  createTemplate(templateData: CreateTemplateRequest): Observable<TemplateResponse> {
    const headers = this.createHeaders();
    return this.httpClient.post<TemplateResponse>(this.urlCore, templateData, { headers: headers });
  }

  // Update template
  updateTemplate(templateId: string, templateData: CreateTemplateRequest): Observable<TemplateResponse> {
    const headers = this.createHeaders();
    return this.httpClient.put<TemplateResponse>(`${this.urlCore}/${templateId}`, templateData, { headers: headers });
  }

  // Delete template
  deleteTemplate(templateId: string): Observable<void> {
    const headers = this.createHeaders();
    return this.httpClient.delete<void>(`${this.urlCore}/${templateId}`, { headers: headers });
  }
}