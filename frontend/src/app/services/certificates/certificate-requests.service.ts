import {HttpClient} from '@angular/common/http';
import {inject, Injectable} from '@angular/core';
import {Observable} from 'rxjs';
import {CertificateRequest} from '../../models/CertificateRequest';
import {KeyPair} from '../../models/KeyPair';
import {CSRResponse} from '../../models/CSRResponse';
import {CSRApprove} from '../../models/CSRApprove';

@Injectable({
  providedIn: 'root'
})
export class CertificateRequestsService {
  httpClient = inject(HttpClient)
  urlCore = "https://localhost:8081/api/certificate-requests"

  createRequest(request: CertificateRequest): Observable<KeyPair> {
    return this.httpClient.post<KeyPair>(`${this.urlCore}/form`, request);
  }

  createRequestCSR(signingOrganization: string, csrFile: File, notAfter: Date | null): Observable<void> {
    const formData = new FormData();
    if (notAfter) formData.append('notAfter', notAfter.toISOString());
    formData.append('signingOrganization', signingOrganization);
    formData.append('csrFile', csrFile);
    return this.httpClient.post<void>(`${this.urlCore}/csr`, formData);
  }

  getRequests(): Observable<CSRResponse[]> {
    return this.httpClient.get<CSRResponse[]>(this.urlCore);
  }

  approveRequest(csrApprove: CSRApprove): Observable<void> {
    return this.httpClient.post<void>(`${this.urlCore}/approve`, csrApprove);
  }

  rejectRequest(request: string): Observable<void> {
    return this.httpClient.post<void>(`${this.urlCore}/reject`, JSON.stringify(request), {
      headers: {'Content-Type': 'application/json'}
    });
  }
}