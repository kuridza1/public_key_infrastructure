import {Component, inject, OnInit} from '@angular/core';
import {Router} from '@angular/router';
import { Role } from '../../models/Role';
import { AuthService } from '../../services/auth/auth.service';

@Component({
  selector: 'app-role-redirect',
  template: '',
  standalone: true
})
export class RoleRedirectComponent implements OnInit {
  authService = inject(AuthService);
  router = inject(Router);

  ngOnInit() {
    const role: Role | null = this.authService.role;

    if (role === 'Admin')
      this.router.navigate(['/all-certificates']);
    else if (role === 'CaUser')
      this.router.navigate(['/signed-certificates']);
    else if (role === 'EeUser')
      this.router.navigate(['/my-certificates']);
    else
      this.router.navigate(['/login']);
  }
}
