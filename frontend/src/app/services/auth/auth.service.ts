import {HttpClient} from '@angular/common/http';
import {inject, Injectable} from '@angular/core';
import {AuthState} from '../../models/AuthState';
import {BasicUser} from '../../models/BasicUser';
import {LoginRequest} from '../../models/LoginRequest';
import {LoginResponse} from '../../models/LoginResponse';
import {RegisterRequest} from '../../models/RegisterRequest';
import {RefreshRequest} from '../../models/RefreshRequest';
import {RefreshResponse} from '../../models/RefreshResponse';
import {
  BehaviorSubject,
  Observable,
  map,
  tap,
  throwError,
  of,
  from,
} from 'rxjs';
import {finalize, shareReplay, catchError} from 'rxjs/operators';
import { Role } from '../../models/Role';
import {ConfirmEmailResponse} from '../../models/ConfirmEmailResponse';
import {CreateCaUser} from '../../models/CreateCaUser';
import {RegisterResponse} from '../../models/RegisterResponse';
import {HttpErrorResponse} from '@angular/common/http';

@Injectable({providedIn: 'root'})
export class AuthService {
  httpClient = inject(HttpClient);
  urlCore = 'https://localhost:8081/api/v1/users';

  private static STORAGE_KEY = 'auth.state.v1';

  private readonly _state$ = new BehaviorSubject<AuthState>({
    accessToken: null,
    accessExpiresAt: null,
    refreshToken: null,
    refreshExpiresAt: null,
    user: null,
  });

  state$ = this._state$.asObservable();

  isLoggedIn$ = this.state$.pipe(map((s) => !!s.accessToken && !!s.user));
  userId$ = this.state$.pipe(map((s) => s.user?.id ?? null));
  role$ = this.state$.pipe(map((s) => s.user?.role ?? null));
  user$ = this.state$;

  private bc?: BroadcastChannel;

  // --- SSR guards & fallbacks ---
  private get isBrowser(): boolean {
    return typeof window !== 'undefined' && typeof document !== 'undefined';
  }
  private get storage(): Storage | null {
    try {
      return this.isBrowser && typeof localStorage !== 'undefined' ? localStorage : null;
    } catch { return null; }
  }
  private safeAtob(input: string): string {
    try {
      return typeof atob !== 'undefined'
        ? atob(input)
        : Buffer.from(input, 'base64').toString('utf-8'); // Node fallback
    } catch { return ''; }
  }
  private safeReload(): void {
    if (this.isBrowser && typeof location !== 'undefined' && typeof location.reload === 'function') {
      location.reload();
    }
  }
  private get tabId(): string {
    const g = (globalThis as any);
    const rnd = g?.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);
    return rnd;
  }
  private get supportsBroadcastChannel(): boolean {
    return this.isBrowser && 'BroadcastChannel' in window;
  }
  private get supportsWebLocks(): boolean {
    const nav: any = this.isBrowser ? navigator : undefined;
    return !!(nav?.locks && typeof nav.locks.request === 'function');
  }
  private postBroadcast(msg: any) {
    try { this.bc?.postMessage(msg); } catch { /* ignore */ }
  }
  private storageGet(key: string): string | null {
    try { return this.storage?.getItem(key) ?? null; } catch { return null; }
  }
  private storageSet(key: string, val: string): void {
    try { this.storage?.setItem(key, val); } catch { /* ignore */ }
  }
  private storageRemove(key: string): void {
    try { this.storage?.removeItem(key); } catch { /* ignore */ }
  }

  constructor() {
    this.hydrateFromStorage();
    this.initCrossTabSync();
  }

  private initCrossTabSync() {
    if (!this.isBrowser) return;

    window.addEventListener('storage', (e) => {
      if (e.key !== AuthService.STORAGE_KEY) return;

      if (e.newValue) {
        try {
          const next: AuthState = JSON.parse(e.newValue);
          this._state$.next(next);
        } catch { /* ignore */ }
      } else {
        this._state$.next({
          accessToken: null,
          accessExpiresAt: null,
          refreshToken: null,
          refreshExpiresAt: null,
          user: null,
        });
      }
    });

    if (this.supportsBroadcastChannel) {
      this.bc = new BroadcastChannel('auth');
      this.bc.onmessage = (ev) => {
        const msg = ev.data;
        if (!msg || msg.origin === this.tabId) return;

        if (msg.type === 'auth-state' && msg.state) {
          this._state$.next(msg.state as AuthState);
        } else if (msg.type === 'auth-logout') {
          this._state$.next({
            accessToken: null,
            accessExpiresAt: null,
            refreshToken: null,
            refreshExpiresAt: null,
            user: null,
          });
        }
      };
    }
  }

  get isLoggedIn(): boolean {
    return !!this._state$.value.accessToken && !!this._state$.value.user;
  }

  get userId(): string | null {
    return this._state$.value.user?.id ?? null;
  }

  get role(): Role | null {
    return this._state$.value.user?.role ?? null;
  }

  get accessToken(): string | null {
    return this._state$.value.accessToken;
  }

  register(body: RegisterRequest): Observable<RegisterResponse> {
    return this.httpClient.post<RegisterResponse>(
      `${this.urlCore}/register`,
      body
    );
  }

  registerCaUser(body: CreateCaUser): Observable<RegisterResponse> {
    return this.httpClient.post<RegisterResponse>(
      `${this.urlCore}/register-ca`,
      body
    );
  }

  login(body: LoginRequest): Observable<BasicUser> {
    return this.httpClient
      .post<LoginResponse>(`${this.urlCore}/login`, body)
      .pipe(
        tap((res) => this.applyLoginResponse(res)),
        map(() => this._state$.value.user!)
      );
  }

  refresh(): Observable<void> {
    const rt = this._state$.value.refreshToken;
    if (!rt) return throwError(() => new Error('Missing refresh token'));

    const body: RefreshRequest = {refreshToken: rt};
    return this.httpClient
      .post<RefreshResponse>(`${this.urlCore}/refresh`, body)
      .pipe(
        tap((res) => this.applyRefreshResponse(res)),
        map(() => void 0)
      );
  }

  logout(): Observable<void> {
    return this.httpClient
      .post<void>(`${this.urlCore}/logout`, {}, {})
      .pipe(finalize(() => this.clearState(/* broadcast */ true)));
  }

  private applyLoginResponse(res: LoginResponse) {
    const state: AuthState = {
      accessToken: res.accessToken,
      accessExpiresAt: res.accessExpiresAt,
      refreshToken: res.refreshToken,
      refreshExpiresAt: res.refreshExpiresAt,
      user: {
        id: res.userId,
        role: res.role as Role,
        name: res.name ?? null,
        surname: res.surname ?? null,
      },
    };
    this.setState(state, /* broadcast */ true);
  }

  private applyRefreshResponse(res: RefreshResponse) {
    const claims = this.decodeJwt(res.accessToken);
    const roleFromJwt = (claims['role'] ||
      claims['http://schemas.microsoft.com/ws/2008/06/identity/claims/role']
      ) as string | undefined;

    const prevUser = this._state$.value.user;
    const state: AuthState = {
      accessToken: res.accessToken,
      accessExpiresAt: res.accessExpiresAt,
      refreshToken: res.refreshToken,
      refreshExpiresAt: res.refreshExpiresAt,
      user: {
        id: res.userId,
        role: (roleFromJwt ?? prevUser?.role ?? '') as Role,
        name: prevUser?.name ?? null,
        surname: prevUser?.surname ?? null,
      },
    };
    this.setState(state, /* broadcast */ true);
  }

  private setState(state: AuthState, broadcast = false) {
    this._state$.next(state);
    this.storageSet(AuthService.STORAGE_KEY, JSON.stringify(state));
    if (broadcast) {
      this.postBroadcast({type: 'auth-state', state, origin: this.tabId});
    }
  }

  private clearState(broadcast = false) {
    this._state$.next({
      accessToken: null,
      accessExpiresAt: null,
      refreshToken: null,
      refreshExpiresAt: null,
      user: null,
    });
    this.storageRemove(AuthService.STORAGE_KEY);
    if (broadcast) {
      this.postBroadcast({type: 'auth-logout', origin: this.tabId});
    }
  }

  private hydrateFromStorage() {
    const raw = this.storageGet(AuthService.STORAGE_KEY);
    if (!raw) return;
    try {
      const saved: AuthState = JSON.parse(raw);
      if (saved?.accessToken && saved?.accessExpiresAt) {
        const msLeft = new Date(saved.accessExpiresAt).getTime() - Date.now();
        this._state$.next(saved);
        if (msLeft <= 0 && saved.refreshToken) {
          this.refresh().subscribe({
            error: (err) => {
              if (this.shouldLogoutOnRefreshError(err)) {
                this.clearState(true);
              }
            },
          });
        } else if (msLeft <= 0) {
          this.clearState(false);
        }
      }
    } catch {
      this.clearState(false);
    }
  }

  // Pull the newest tokens from localStorage (used before refresh to avoid stale RT)
  private rehydrateLatestFromStorage() {
    const raw = this.storageGet(AuthService.STORAGE_KEY);
    if (!raw) return;
    try {
      const saved: AuthState = JSON.parse(raw);
      const cur = this._state$.value;
      if (
        saved.accessToken !== cur.accessToken ||
        saved.refreshToken !== cur.refreshToken ||
        saved.accessExpiresAt !== cur.accessExpiresAt ||
        saved.refreshExpiresAt !== cur.refreshExpiresAt
      ) {
        this._state$.next(saved);
      }
    } catch { /* ignore */ }
  }

  private decodeJwt(token: string): Record<string, unknown> {
    try {
      const [, payload] = token.split('.');
      const json = this.safeAtob(this.base64UrlToBase64(payload));
      return JSON.parse(json || '{}');
    } catch {
      return {};
    }
  }

  private base64UrlToBase64(input: string): string {
    let b64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad === 2) b64 += '==';
    else if (pad === 3) b64 += '=';
    else if (pad !== 0) b64 += '===';
    return b64;
  }

  private refreshInFlight$?: Observable<void>;

  private msUntilAccessExpiry(): number {
    const expIso = this._state$.value.accessExpiresAt;
    return expIso ? new Date(expIso).getTime() - Date.now() : -Infinity;
  }

  isAccessTokenFresh(skewMs = 30_000): boolean {
    return this.msUntilAccessExpiry() > skewMs;
  }

  // Ensure there's a fresh access token, refreshing if needed
  ensureValidAccessToken(skewMs = 30_000): Observable<void> {
    this.rehydrateLatestFromStorage();

    if (this.isAccessTokenFresh(skewMs)) return of(void 0);
    if (this.refreshInFlight$) return this.refreshInFlight$;

    const doRefresh$ = this.refresh().pipe(
      catchError((err) => {
        if (this.shouldLogoutOnRefreshError(err)) {
          this.clearState(true);
        }
        return throwError(() => err);
      }),
      finalize(() => {
        this.refreshInFlight$ = undefined;
      }),
      shareReplay({bufferSize: 1, refCount: true})
    );

    if (this.supportsWebLocks) {
      const p: Promise<void> = (navigator as any).locks
        .request('auth-refresh', async () => {
          this.rehydrateLatestFromStorage();
          if (this.isAccessTokenFresh(skewMs)) return;

          await new Promise<void>((resolve, reject) => {
            const sub = doRefresh$.subscribe({
              complete: () => resolve(),
              error: (e) => reject(e),
            });
          });
        })
        .catch((e: unknown) => {
          if (this.shouldLogoutOnRefreshError(e)) {
            this.clearState(true);
          }
          throw e;
        });

      this.refreshInFlight$ = from(p);
      return this.refreshInFlight$;
    }

    this.refreshInFlight$ = doRefresh$;
    return this.refreshInFlight$;
  }

  confirmEmail(token: string): Observable<ConfirmEmailResponse> {
    return this.httpClient.get<ConfirmEmailResponse>(`${this.urlCore}/confirm`, {params: {token}});
  }

  private shouldLogoutOnRefreshError(err: unknown): boolean {
    if (err instanceof HttpErrorResponse) {
      if ([400, 401, 403].includes(err.status)) {
        this.clearState(true);
        this.safeReload();
        return true;
      }
    }
    return false;
  }
}
