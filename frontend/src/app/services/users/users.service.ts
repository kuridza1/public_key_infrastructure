import {inject, Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {CaUser} from '../../models/CaUser';

@Injectable({
  providedIn: 'root'
})
export class UsersService {
  httpClient = inject(HttpClient)
  urlCore = "https://localhost:8081/api/v1/users"

  getAllCaUsers(): Observable<CaUser[]> {
    return this.httpClient.get<CaUser[]>(`${this.urlCore}/get-all-ca-users`);
  }

  getValidCaUsers(): Observable<CaUser[]> {
    return this.httpClient.get<CaUser[]>(`${this.urlCore}/get-valid-ca-users`);
  }
}
