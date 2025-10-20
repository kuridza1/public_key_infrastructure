import {Component, inject} from '@angular/core';
import {MatDialogRef} from '@angular/material/dialog';
import {MatFormField, MatLabel} from '@angular/material/form-field';
import {MatIconButton} from '@angular/material/button';
import {MatInput} from '@angular/material/input';
import {FormsModule} from '@angular/forms';

@Component({
  selector: 'app-download-certificate-pw-dialog',
  standalone: true,
  imports: [
    MatFormField,
    MatLabel,
    MatIconButton,
    MatInput,
    FormsModule
  ],
  templateUrl: './download-certificate-pw-dialog.component.html',
  styleUrl: './download-certificate-pw-dialog.component.scss'
})
export class DownloadCertificatePwDialogComponent {
  dialogRef = inject(MatDialogRef<DownloadCertificatePwDialogComponent, string | undefined | null>)
  password: string | null = null;

  closeDialog() {
    this.dialogRef.close(this.password);
  }

  onNoClick() {
    this.dialogRef.close(undefined);
  }
}
