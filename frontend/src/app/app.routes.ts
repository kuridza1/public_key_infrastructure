import { Routes } from '@angular/router';
// import {IssueCertificateComponent} from './components/common/issue-certificate/issue-certificate.component';
// import {AllCertificatesComponent} from './components/admin/all-certificates/all-certificates.component';
// import {CaUserManagementComponent} from './components/admin/ca-user-management/ca-user-management.component';
// import {LoginComponent} from './components/anonymous/login/login.component';
// import {RegistrationComponent} from './components/anonymous/registration/registration.component';
// import {MyCertificatesComponent} from './components/common/my-certificates/my-certificates.component';
// import {RequestCertificateComponent} from './components/ee-user/request-certificate/request-certificate.component';
// import {CertificateRequestsComponent} from './components/ca-user/certificate-requests/certificate-requests.component';
// import {SignedCertificatesComponent} from './components/ca-user/signed-certificates/signed-certificates.component';
// import {CrlPageComponent} from './components/common/crl-page/crl-page.component';

import {authGuard, noAuthGuard, roleGuard} from './services/auth/auth.guard';
import { LoginComponent } from './components/user/login/login.component';
import { RegistrationComponent } from './components/user/registration/registration.component';
// import type { Role } from './models/Role';
// import {RoleRedirectComponent} from './components/common/role-redirect/role-redirect.component';
// import {EmailConfirmationComponent} from './components/anonymous/email-confirmation/email-confirmation/email-confirmation.component';

export const routes: Routes = [
  // Public
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegistrationComponent, canActivate: [noAuthGuard] },
//   { path: 'crl', component: CrlPageComponent },

]
  // EeUser
//   {
//     path: 'my-certificates',
//     component: MyCertificatesComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['EeUser', 'CaUser'] as Role[] }, // CaUser as well
//   },
//   {
//     path: 'request-certificate',
//     component: RequestCertificateComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['EeUser'] as Role[] },
//   },

//   // CaUser
//   {
//     path: 'signed-certificates',
//     component: SignedCertificatesComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['CaUser'] as Role[] },
//   },
//   {
//     path: 'certificate-requests',
//     component: CertificateRequestsComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['CaUser'] as Role[] },
//   },
//   {
//     path: 'issue-certificate',
//     component: IssueCertificateComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['CaUser', 'Admin'] as Role[] }, // both CaUser and Admin
//   },

//   // Admin
//   {
//     path: 'all-certificates',
//     component: AllCertificatesComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['Admin'] as Role[] },
//   },
//   {
//     path: 'manage-ca-users',
//     component: CaUserManagementComponent,
//     canActivate: [authGuard, roleGuard],
//     data: { roles: ['Admin'] as Role[] },
//   },

//   { path: 'confirm', component: EmailConfirmationComponent },
//   { path: '**', component: RoleRedirectComponent, canActivate: [authGuard] }
// ];
