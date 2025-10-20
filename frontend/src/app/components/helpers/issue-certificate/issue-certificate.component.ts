import { Component, inject, OnInit, ViewChild } from '@angular/core';
import { FormsModule, NgForm, NgModel, ReactiveFormsModule } from '@angular/forms';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatNativeDateModule } from '@angular/material/core';
import { MatSelect, MatSelectModule } from '@angular/material/select';
import { NgForOf, NgIf } from '@angular/common';
import { MatChipsModule } from '@angular/material/chips';
import { MatProgressSpinner } from '@angular/material/progress-spinner';

import { CreateCertificate } from '../../../models/CreateCertificate';
import { KeyUsageValue } from '../../../models/KeyUsageValue';
import { ExtendedKeyUsageValue } from '../../../models/ExtendedKeyUsageValue';
import { CertificatesService } from '../../../services/certificates/certificate.service';
import { ToastrService } from '../toastr/toastr.service';
import { Certificate } from '../../../models/Certificate';
import { AuthService } from '../../../services/auth/auth.service';

@Component({
  selector: 'app-issue-certificate',
  standalone: true,
  imports: [
    FormsModule,
    ReactiveFormsModule,
    MatDatepickerModule,
    MatInputModule,
    MatFormFieldModule,
    MatButtonModule,
    MatSelectModule,
    NgForOf,
    NgIf,
    MatChipsModule,
    MatProgressSpinner,
    MatNativeDateModule
  ],
  templateUrl: './issue-certificate.component.html',
  styleUrl: './issue-certificate.component.scss'
})
export class IssueCertificateComponent implements OnInit {
  @ViewChild('notBeforeModel') dateNotBeforeModel!: NgModel;
  @ViewChild('notAfterModel') dateNotAfterModel!: NgModel;
  @ViewChild('certForm') certForm!: NgForm;

  certificatesService = inject(CertificatesService);
  auth = inject(AuthService);
  toast = inject(ToastrService);

  protected readonly ExtendedKeyUsageValue = ExtendedKeyUsageValue;
  protected readonly KeyUsageValue = KeyUsageValue;

  loading = true;
  noSigningCertificates = false;
  signingCertificates: { key: string | Certificate, value: string }[] = [];
  extensions: { key: string, value: any }[] = [];
  dateNotBefore: Date | null = null;
  dateNotAfter: Date | null = null;
  signingCertificate: string | Certificate = '';
  commonName = '';
  organization = '';
  organizationalUnit = '';
  email = '';
  country = '';

  allExtensionKeys = [
    { value: 'keyUsage', label: 'Key Usage' },
    { value: 'extendedKeyUsage', label: 'Extended Key Usage' },
    { value: 'subjectAlternativeNames', label: 'Subject Alternative Names' },
    { value: 'issuerAlternativeNames', label: 'Issuer Alternative Names' },
    { value: 'nameConstraints', label: 'Name Constraints' },
    { value: 'basicConstraints', label: 'Basic Constraints' },
    { value: 'certificatePolicies', label: 'Certificate Policies' }
  ];

  ngOnInit() {
    if (this.auth.role === 'CaUser') {
      this.loadCaSigningCertificates();
    } else if (this.auth.role === 'Admin') {
      this.loadAdminSigningCertificates();
    }
  }

  loadCaSigningCertificates() {
    this.signingCertificates = [];
    this.certificatesService.getMyValidCertificates().subscribe({
      next: value => {
        if (value.length === 0) this.noSigningCertificates = true;
        value.sort((a, b) => a.prettySerialNumber.localeCompare(b.prettySerialNumber));
        value.forEach(cert => this.signingCertificates.push({ key: cert, value: cert.prettySerialNumber }));
        this.loading = false;
      },
      error: () => this.toast.error("Error", "Unable to get signing certificates")
    });
  }

  loadAdminSigningCertificates() {
    this.signingCertificates = [{ key: 'SelfSign', value: 'Self signing' }];
    this.certificatesService.getValidSigningCertificates().subscribe({
      next: value => {
        value.sort((a, b) => a.prettySerialNumber.localeCompare(b.prettySerialNumber));
        value.forEach(cert => this.signingCertificates.push({ key: cert, value: cert.prettySerialNumber }));
        this.loading = false;
      },
      error: () => this.toast.error("Error", "Unable to get signing certificates")
    });
  }

  onCountryInput(e: Event) {
    const input = e.target as HTMLInputElement;
    const pos = input.selectionStart!;
    this.country = input.value.replace(/[^A-Za-z]/g, '').toUpperCase();
    input.value = this.country;
    input.setSelectionRange(pos, pos);
  }

  addExtension() {
    if (this.extensions.length < this.allExtensionKeys.length) this.extensions.push({ key: '', value: '' });
  }

  removeExtension(index: number) {
    this.extensions.splice(index, 1);
  }

  generalNamesToString(list: { prefix: string, value: string }[]) {
    return list.map(item => `${item.prefix}:${item.value}`).join(',');
  }

  onSubmit(form: NgForm) {
    if (!form.valid) return;
    this.loading = true;

    const signCert = typeof this.signingCertificate === 'string' ? this.signingCertificate : this.signingCertificate.serialNumber;

    const dto: CreateCertificate = {
      signingCertificate: signCert,
      commonName: this.commonName,
      organization: this.organization,
      organizationalUnit: this.organizationalUnit,
      email: this.email,
      country: this.country,
      notBefore: this.dateNotBefore || undefined,
      notAfter: this.dateNotAfter || undefined
    };

    this.extensions.forEach(extension => {
      if (extension.key === 'keyUsage') dto.keyUsage = extension.value.map((v: number) => KeyUsageValue[v]);
      else if (extension.key === 'extendedKeyUsage') dto.extendedKeyUsage = extension.value.map((v: number) => ExtendedKeyUsageValue[v]);
      else if (extension.key === 'subjectAlternativeNames' && this.generalNamesToString(extension.value))
        dto.subjectAlternativeNames = { value: this.generalNamesToString(extension.value) };
      else if (extension.key === 'issuerAlternativeNames' && this.generalNamesToString(extension.value))
        dto.issuerAlternativeNames = { value: this.generalNamesToString(extension.value) };
    });

    this.certificatesService.issueCertificate(dto).subscribe({
      next: () => {
        this.loading = false;
        this.toast.success("Success", "Certificate successfully created");
        if (this.auth.role === 'CaUser') this.loadCaSigningCertificates();
        else if (this.auth.role === 'Admin') this.loadAdminSigningCertificates();
        this.resetFields();
      },
      error: err => this.toast.error("Unable to issue the certificate", `Error: ${err}`)
    });
  }

  private resetFields() {
    this.extensions = [];
    this.certForm.resetForm();
    this.dateNotBefore = null;
    this.dateNotAfter = null;
  }
}
