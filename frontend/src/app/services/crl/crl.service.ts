import {inject, Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {RevokedCertificate} from '../../models/RevokedCertificate';
import {RevokeCertificate} from '../../models/RevokeCertificate';

@Injectable({
  providedIn: 'root'
})
export class  CrlService {
  httpClient = inject(HttpClient)
  urlCore = "https://localhost:8081/api/crl"

  getAllRevokedCertificates(): Observable<RevokedCertificate[]> {
    return this.httpClient.get<RevokedCertificate[]>(`${this.urlCore}/web`);
  }

  revokeCertificate(revokeCertificate: RevokeCertificate): Observable<void> {
    return this.httpClient.post<void>(`${this.urlCore}/revoke`, revokeCertificate)
  }
}