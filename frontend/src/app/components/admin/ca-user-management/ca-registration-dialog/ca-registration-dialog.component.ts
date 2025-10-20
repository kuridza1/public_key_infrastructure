import {Component, inject} from '@angular/core';
import {MatFormField, MatLabel} from '@angular/material/form-field';
import {MatOption, MatSelect} from '@angular/material/select';
import {MAT_DIALOG_DATA, MatDialogRef} from '@angular/material/dialog';
import {FormsModule} from '@angular/forms';
import {MatInput} from '@angular/material/input';
import {NgForOf, NgIf} from '@angular/common';
import {MatIconButton} from '@angular/material/button';
import {Certificate} from '../../../../models/Certificate';
import {ToastrService} from '../../../common/toastr/toastr.service';
import {MatProgressSpinner} from '@angular/material/progress-spinner';
import {CreateCaUser} from '../../../../models/CreateCaUser';
import {AuthService} from '../../../../services/auth/auth.service';
import {CaUser} from '../../../../models/CaUser';

@Component({
  selector: 'app-ca-registration-dialog',
  standalone: true,
  imports: [
    MatFormField,
    MatSelect,
    MatOption,
    FormsModule,
    MatInput,
    MatLabel,
    MatIconButton,
    NgForOf,
    MatProgressSpinner,
    NgIf
  ],
  templateUrl: './ca-registration-dialog.component.html',
  styleUrl: './ca-registration-dialog.component.scss'
})
export class CaRegistrationDialogComponent {
  dialogRef = inject(MatDialogRef<CaRegistrationDialogComponent, CaUser | null | undefined>);
  data = inject(MAT_DIALOG_DATA) as { allSigningCertificates: Certificate[] };
  toast = inject(ToastrService);
  auth = inject(AuthService);

  loading = false;

  signingCertificate: Certificate | null = null;
  name = ''
  surname = ''
  organization = ''
  email = ''
  password = ''

  onNoClick() {
    this.dialogRef.close();
  }

  onSubmit() {
    this.loading = true;

    if (this.signingCertificate === null) {
      return;
    }

    const createCaUser: CreateCaUser = {
      email: this.email,
      initialSigningCertificateId: this.signingCertificate.serialNumber,
      name: this.name,
      organization: this.organization,
      password: this.password,
      surname: this.surname
    }

    this.auth.registerCaUser(createCaUser).subscribe({
      next: value => {
        this.toast.success('Registered', 'A new CA user has been registered.');
        this.loading = false;
        this.dialogRef.close({ name: value.name, id: value.id, email: value.email, surname: value.surname, organization: value.organization });
      },
      error: (err) => {
        const msg = err?.error?.error || err?.error?.message || err?.message || 'Unexpected error.';
        this.toast.error('Registration failed: ', msg);
        this.loading = false;
      },
      complete: () => this.loading = false
    });
  }
}
