import { inject, Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { RevokeCertificate} from '../../models/RevokeCertificate';
import { AuthService } from '../auth/auth.service';

@Injectable({ providedIn: 'root' })
export class CrlService {
  private http = inject(HttpClient);
  private auth = inject(AuthService);
  private urlCore = 'https://localhost:8081/api/crl';

  private createHeaders(): HttpHeaders {
    const userId = this.auth.userId;
    const role = this.auth.role; // ensure this is already a string like "Admin"
    if (!userId || !role) throw new Error('User authentication data is not available');

    return new HttpHeaders({
      userId: String(userId),
      role: String(role),
      // Authorization is added by your AuthInterceptor
      'Content-Type': 'application/json',
    });
  }

  getAllRevokedCertificates(): Observable<any[]> {
    return this.http.get<any[]>(`${this.urlCore}/web`, { headers: this.createHeaders() });
  }

  revokeCertificate(payload: RevokeCertificate): Observable<void> {
    return this.http.post<void>(`${this.urlCore}/revoke`, payload, { headers: this.createHeaders() });
  }
}
