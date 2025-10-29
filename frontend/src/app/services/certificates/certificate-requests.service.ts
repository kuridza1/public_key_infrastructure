import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { CertificateRequest } from '../../models/CertificateRequest';
import { KeyPair } from '../../models/KeyPair';
import { CSRResponse } from '../../models/CSRResponse';
import { CSRApprove } from '../../models/CSRApprove';
import { AuthService } from '../auth/auth.service';

@Injectable({
  providedIn: 'root'
})
export class CertificateRequestsService {
  httpClient = inject(HttpClient)
  auth = inject(AuthService); // Inject AuthService
  urlCore = "https://localhost:8081/api/certificate-requests"

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

  createRequest(request: CertificateRequest): Observable<KeyPair> {
    const headers = this.createHeaders();
    return this.httpClient.post<KeyPair>(`${this.urlCore}/form`, request, { headers: headers });
  }

  createRequestCSR(signingOrganization: string, csrFile: File, notAfter: Date | null): Observable<void> {
    const headers = this.createHeaders();
    const formData = new FormData();
    if (notAfter) formData.append('notAfter', notAfter.toISOString());
    formData.append('signingOrganization', signingOrganization);
    formData.append('csrFile', csrFile);
    return this.httpClient.post<void>(`${this.urlCore}/csr`, formData, { headers: headers });
  }

  getRequests(): Observable<CSRResponse[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<CSRResponse[]>(this.urlCore, { headers: headers });
  }

  approveRequest(csrApprove: CSRApprove): Observable<void> {
    const headers = this.createHeaders();
    return this.httpClient.post<void>(`${this.urlCore}/approve`, csrApprove, { headers: headers });
  }

  rejectRequest(request: string): Observable<void> {
    const headers = this.createHeaders().set('Content-Type', 'application/json');
    return this.httpClient.post<void>(`${this.urlCore}/reject`, JSON.stringify(request), { 
      headers: headers 
    });
  }
}