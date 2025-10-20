import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { AuthService } from './auth.service';
import { Role } from '../../models/Role';

export const authGuard: CanActivateFn = (_route, state): boolean | UrlTree => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.isLoggedIn) return true;
  return router.createUrlTree(['/login'], {
    queryParams: { returnUrl: state.url },
  });
};

export const roleGuard: CanActivateFn = (route, state): boolean | UrlTree => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (!auth.isLoggedIn) {
    return router.createUrlTree(['/login'], {
      queryParams: { returnUrl: state.url },
    });
  }

  const allowed = (route.data?.['roles'] as Role[] | undefined) ?? [];
  if (allowed.length === 0) return true;

  const role = auth.role as Role | null;
  if (role && allowed.includes(role)) return true;

  return router.createUrlTree(['/login']);
};

export const noAuthGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.isLoggedIn) {
    const role = auth.role as Role | null;
    if (role === 'Admin') router.navigate(['/all-certificates']);
    else if (role === 'CaUser') router.navigate(['/signed-certificates']);
    else if (role === 'EeUser') router.navigate(['/my-certificates']);
    return false;
  }

  return true;
};
