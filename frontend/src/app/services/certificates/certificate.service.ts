import { CreateCertificate } from '../../models/CreateCertificate';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { Certificate } from '../../models/Certificate';
import { AddCertificateToCaUser } from '../../models/AddCertificateToCaUser';
import { DownloadCertificateRequest } from '../../models/DownloadCertificateRequest';
import { AuthService } from '../auth/auth.service';

@Injectable({
  providedIn: 'root'
})
export class CertificatesService {
  httpClient = inject(HttpClient)
  auth = inject(AuthService);
  urlCore = "https://localhost:8081/api/certificates"

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

  issueCertificate(createCertificate: CreateCertificate): Observable<string> {
    const headers = this.createHeaders();
    return this.httpClient.post<string>(`${this.urlCore}/issue`, createCertificate, {
      headers: headers
    });
  }

  getAllCertificates(): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-all`, { headers: headers });
  }

  getValidSigningCertificates(): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-all-valid-signing`, { headers: headers });
  }

  getSigningCertificatesThatCaDoesntHave(caUserId: string): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-signing-ca-doesnt-have/${caUserId}`, { headers: headers });
  }

  getMyCertificates(): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-my-certificates`, { headers: headers });
  }

  getMyValidCertificates(): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-my-valid-certificates`, { headers: headers });
  }
  getMyValidSigningCertificates(): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-my-valid-certificates`, { headers: headers });
  }

  getCertificatesSignedByMe(): Observable<Certificate[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-certificates-signed-by-me`, { headers: headers });
  }

  addNewCertificateToCaUser(addCertificateToCaUser: AddCertificateToCaUser): Observable<void> {
    const headers = this.createHeaders();
    return this.httpClient.put<void>(`${this.urlCore}/add-certificate-to-ca-user`, addCertificateToCaUser, { headers: headers });
  }

  downloadCertificate(downloadCertificateRequest: DownloadCertificateRequest): Observable<Blob> {
    const headers = this.createHeaders();
    return this.httpClient.post(`${this.urlCore}/download`, downloadCertificateRequest, {
      headers: headers,
      responseType: 'blob'
    });
  }
}
