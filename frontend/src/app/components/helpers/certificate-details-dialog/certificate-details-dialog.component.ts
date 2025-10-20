import {Component, inject} from '@angular/core';
import {MatFormField, MatLabel} from '@angular/material/form-field';
import {MatIconButton} from '@angular/material/button';
import {MatInput} from '@angular/material/input';
import {MAT_DIALOG_DATA, MatDialogRef} from '@angular/material/dialog';
import {ToastrService} from "../toastr/toastr.service";
import {CdkCopyToClipboard} from '@angular/cdk/clipboard';

@Component({
  selector: 'app-certificate-details-dialog',
  standalone: true,
  imports: [
    MatFormField,
    MatIconButton,
    MatInput,
    MatLabel,
    CdkCopyToClipboard
  ],
  templateUrl: './certificate-details-dialog.component.html',
  styleUrl: './certificate-details-dialog.component.scss'
})
export class CertificateDetailsDialogComponent {
  dialogRef = inject(MatDialogRef<CertificateDetailsDialogComponent, null>);
  data = inject(MAT_DIALOG_DATA) as { encodedCertificate: string };
  encodedCertificate = this.data.encodedCertificate;
  toastr = inject(ToastrService);

  onNoClick() {
    this.dialogRef.close();
  }

  onCopied() {
    this.toastr.success('Success', 'Certificate copied to clipboard');
  }
}
