import {inject, Injectable, Injector} from '@angular/core';
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { AuthService } from './auth.service';
import { catchError, switchMap } from 'rxjs/operators';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  injector = inject(Injector)

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const auth = this.injector.get(AuthService);

    const isApi = req.url.startsWith('https://localhost:8081/');
    const isAuthEndpoint =
      req.url.includes('/api/v1/users/login') ||
      req.url.includes('/api/v1/users/register') ||
      req.url.includes('/api/v1/users/confirm') ||
      req.url.includes('/api/v1/crl/web') ||
      req.url.includes('/api/v1/users/refresh');

    if (!isApi || isAuthEndpoint) {
      return next.handle(req);
    }

    return auth.ensureValidAccessToken().pipe(
      switchMap(() => {
        const token = auth.accessToken;
        const authReq = token
          ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
          : req;

        let retried = false;
        return next.handle(authReq).pipe(
          catchError((err: HttpErrorResponse) => {
            const shouldRetry = !retried && err.status === 401;
            retried = true;

            if (shouldRetry) {
              return auth.ensureValidAccessToken().pipe(
                switchMap(() => {
                  const token2 = auth.accessToken;
                  const retryReq = token2
                    ? authReq.clone({ setHeaders: { Authorization: `Bearer ${token2}` } })
                    : authReq;
                  return next.handle(retryReq);
                })
              );
            }
            return throwError(() => err);
          })
        );
      })
    );
  }
}
