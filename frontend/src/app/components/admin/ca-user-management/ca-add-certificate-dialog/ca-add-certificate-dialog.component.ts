import {Component, inject} from '@angular/core';
import {MatFormField, MatLabel} from "@angular/material/form-field";
import {MatIconButton} from "@angular/material/button";
import {MatOption} from "@angular/material/core";
import {MatSelect} from "@angular/material/select";
import {MAT_DIALOG_DATA, MatDialogRef} from '@angular/material/dialog';
import {Certificate} from '../../../../models/Certificate';
import {NgForOf} from '@angular/common';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';

@Component({
  selector: 'app-ca-add-certificate-dialog',
  standalone: true,
  imports: [
    MatFormField,
    MatIconButton,
    MatLabel,
    MatOption,
    MatSelect,
    NgForOf,
    ReactiveFormsModule,
    FormsModule
  ],
  templateUrl: './ca-add-certificate-dialog.component.html',
  styleUrl: './ca-add-certificate-dialog.component.scss'
})
export class CaAddCertificateDialogComponent {
  dialogRef = inject(MatDialogRef<CaAddCertificateDialogComponent, Certificate | null>)
  data = inject(MAT_DIALOG_DATA) as { availableCertificates: Certificate[] };

  chosenCertificate: Certificate | null = null;

  closeDialog() {
    this.dialogRef.close(this.chosenCertificate);
  }

  onNoClick() {
    this.dialogRef.close();
  }
}
