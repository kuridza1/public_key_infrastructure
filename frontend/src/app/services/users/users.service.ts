import { inject, Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { CaUser } from '../../models/CaUser';
import { AuthService } from '../auth/auth.service';

@Injectable({
  providedIn: 'root'
})
export class UsersService {
  httpClient = inject(HttpClient)
  auth = inject(AuthService); // Inject AuthService
  urlCore = "https://localhost:8081/api/users"

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

  getAllCaUsers(): Observable<CaUser[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<CaUser[]>(`${this.urlCore}/ca`, { headers: headers });
  }

  getValidCaUsers(): Observable<CaUser[]> {
    const headers = this.createHeaders();
    return this.httpClient.get<CaUser[]>(`${this.urlCore}/ca/valid`, { headers: headers });
  }
}