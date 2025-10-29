import {Component, inject, OnInit} from '@angular/core';
import {Router} from '@angular/router';
import {NgOptimizedImage} from '@angular/common';
import {FormBuilder, Validators, ReactiveFormsModule, FormGroup} from '@angular/forms';
import {MatFormField, MatLabel} from '@angular/material/form-field';
import {MatInput} from '@angular/material/input';
import {AuthService} from "../../../services/auth/auth.service";
import {ToastrService} from "../../helpers/toastr/toastr.service";


@Component({
  selector: 'app-login',
  standalone: true,
  imports: [MatFormField, MatInput, MatLabel, ReactiveFormsModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent implements OnInit {
  toast = inject(ToastrService);
  auth = inject(AuthService);
  fb = inject(FormBuilder);
  router = inject(Router);
  loading = false;
  form!: FormGroup;

  ngOnInit(): void {
    this.form = this.fb.group({
      email: ['', [Validators.required]],
      password: ['', [Validators.required]],
    });
  }

  submit() {
    if (this.form.invalid) {
      this.toast.info('Check fields', 'Please enter a valid email and password.');
      return;
    }

    const {email, password} = this.form.value as { email: string; password: string };

    this.loading = true;
    this.auth.login({email, password}).subscribe({
      next: (user) => {
        this.toast.success('Welcome', 'You are now logged in.');

        const returnUrl = new URLSearchParams(location.search).get('returnUrl');
        const target = returnUrl ?? this.defaultRouteForRole(user.role);

        this.router.navigateByUrl(target).then(() => {
          if (this.router.url === '/login')
            this.router.navigateByUrl(this.defaultRouteForRole(user.role));
        });

        this.loading = false
      },
      error: (err) => {
        const msg = this.extractError(err);
        this.toast.error('Login failed', msg);
        this.loading = false;
      },
    });
  }

  goRegister() {
    this.router.navigate(['/register']);
  }

  private defaultRouteForRole(role: string): string {
    switch (role) {
      case 'EeUser':
        return '/my-certificates';
      case 'CaUser':
        return '/signed-certificates';
      case 'Admin':
        return '/all-certificates';
      default:
        return '/';
    }
  }

  private extractError(err: any): string {
    const msg =
      err?.error?.error ||
      err?.error?.message ||
      err?.message ||
      'Unexpected error. Please try again.';
    return typeof msg === 'string' ? msg : 'Unexpected error. Please try again.';
  }
}