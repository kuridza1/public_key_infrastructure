import {Component, inject, OnInit} from '@angular/core';
import {MatFormField, MatLabel} from "@angular/material/form-field";
import {MatInput} from "@angular/material/input";
import {NgFor, NgForOf, NgIf, NgOptimizedImage} from "@angular/common";
import {AbstractControl, FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, ValidatorFn, Validators} from '@angular/forms';
import zxcvbn from 'zxcvbn';
import {AuthService} from "../../../services/auth/auth.service";
import {Router, RouterLink} from '@angular/router';
import {ToastrService} from "../../helpers/toastr/toastr.service";

const passwordsMatch = (): ValidatorFn => {
  return (group: AbstractControl) => {
    const p = group.get('password')?.value ?? '';
    const r = group.get('repeatPassword')?.value ?? '';
    return p === r ? null : {passwordsMismatch: true};
  };
};

@Component({
  selector: 'app-registration',
  standalone: true,
  imports: [
    MatFormField,
    MatInput,
    MatLabel,
    NgForOf,
    NgIf,
    FormsModule,
    NgFor,
    ReactiveFormsModule,
    RouterLink,
  ],
  templateUrl: './registration.component.html',
  styleUrl: './registration.component.css'
})
export class RegistrationComponent implements OnInit {
  toast = inject(ToastrService);
  auth = inject(AuthService);
  fb = inject(FormBuilder);
  router = inject(Router);
  bars = [0, 1, 2, 3];
  submitted = false;
  loading = false;
  strength = 0;
  form!: FormGroup;

  ngOnInit(): void {
    this.form = this.fb.group({
      name: ['', Validators.required],
      surname: ['', Validators.required],
      organization: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8), Validators.maxLength(64)]],
      repeatPassword: ['', Validators.required],
    }, {validators: passwordsMatch()});

    this.form.get('password')!.valueChanges.subscribe((pwd: string) => {
      this.strength = pwd ? zxcvbn(pwd).score : 0;
    });
  }

  get emailCtrl() {
    return this.form.get('email')!;
  }

  get passwordCtrl() {
    return this.form.get('password')!;
  }

  get repeatPasswordCtrl() {
    return this.form.get('repeatPassword')!;
  }

  get someRequiredMissing(): boolean {
    const v = this.form.value as Record<string, string>;
    return ['name', 'surname', 'organization', 'email', 'password', 'repeatPassword']
      .some(k => !v[k] || v[k].trim().length === 0);
  }

  get invalidEmailFormat(): boolean {
    const ctrl = this.emailCtrl;
    return !!ctrl.value && ctrl.hasError('email');
  }

  get badPasswordLength(): boolean {
    return this.passwordCtrl.hasError('minlength') || this.passwordCtrl.hasError('maxlength');
  }

  get passwordsDontMatch(): boolean {
    return this.form.hasError('passwordsMismatch');
  }

  async submit() {
    this.submitted = true;

    if (this.form.invalid) {
      this.toast.info('Fix form', 'Please resolve the issues listed below.');
      return;
    }

    const {name, surname, organization, email, password} = this.form.value as {
      name: string; surname: string; organization: string; email: string; password: string;
    };

    this.loading = true;
    this.auth.register({
      name, surname, organization, email,
      password,
      confirmPassword: password
    } as any).subscribe({
      next: () => {
        this.toast.success('Registered', 'Check your email to confirm your account.');
        this.router.navigate(['/login']);
        this.loading = false;
      },
      error: (err) => {
        const msg = err?.error?.error || err?.error?.message || err?.message || 'Unexpected error.';
        this.toast.error('Registration failed', msg);
        this.loading = false;
      },
      complete: () => this.loading = false
    });
  }

  goLogin() {
    this.router.navigate(['/login']);
  }
}
