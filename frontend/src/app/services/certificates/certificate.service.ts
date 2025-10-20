import {CreateCertificate} from '../../models/CreateCertificate';
import {HttpClient} from '@angular/common/http';
import {inject, Injectable} from '@angular/core';
import {Observable} from 'rxjs';
import {Certificate} from '../../models/Certificate';
import {AddCertificateToCaUser} from '../../models/AddCertificateToCaUser';
import {DownloadCertificateRequest} from '../../models/DownloadCertificateRequest';

@Injectable({
  providedIn: 'root'
})
export class CertificatesService {
  httpClient = inject(HttpClient)
  urlCore = "https://localhost:8081/api/certificates"

  issueCertificate(createCertificate: CreateCertificate): Observable<string> {
    return this.httpClient.post<string>(`${this.urlCore}/issue`, createCertificate);
  }

  getAllCertificates(): Observable<Certificate[]> {
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-all`);
  }

  getValidSigningCertificates(): Observable<Certificate[]> {
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-all-valid-signing`);
  }

  getSigningCertificatesThatCaDoesntHave(caUserId: string): Observable<Certificate[]> {
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-signing-ca-doesnt-have/${caUserId}`);
  }

  getMyCertificates(): Observable<Certificate[]> {
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-my-certificates`);
  }

  getMyValidCertificates(): Observable<Certificate[]> {
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-my-valid-certificates`);
  }

  getCertificatesSignedByMe(): Observable<Certificate[]> {
    return this.httpClient.get<Certificate[]>(`${this.urlCore}/get-certificates-signed-by-me`);
  }

  addNewCertificateToCaUser(addCertificateToCaUser: AddCertificateToCaUser): Observable<void> {
    return this.httpClient.put<void>(`${this.urlCore}/add-certificate-to-ca-user`, addCertificateToCaUser);
  }

  downloadCertificate(downloadCertificateRequest: DownloadCertificateRequest): Observable<Blob> {
    return this.httpClient.post(`${this.urlCore}/download`, downloadCertificateRequest, { responseType: 'blob' });
  }
}