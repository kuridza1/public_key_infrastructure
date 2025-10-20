import { Component, inject, OnInit, ViewChild } from '@angular/core';
import { FormsModule, NgForm, NgModel } from '@angular/forms';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatNativeDateModule } from '@angular/material/core';
import { MatSelect, MatSelectModule } from '@angular/material/select';
import { NgForOf, NgIf } from '@angular/common';
import { MatTab, MatTabContent, MatTabGroup } from '@angular/material/tabs';
import { MatDialog } from '@angular/material/dialog';
import { KeysDialogComponent } from './keys-dialog/keys-dialog.component';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { MatChipRemove, MatChipRow, MatChipSet } from '@angular/material/chips';

import { UsersService } from '../../../services/users/users.service';
import { CaUser } from '../../../models/CaUser';
import { ToastrService } from '../../helpers/toastr/toastr.service';
import { KeyUsageValue } from '../../../models/KeyUsageValue';
import { ExtendedKeyUsageValue } from '../../../models/ExtendedKeyUsageValue';
import { AuthService } from '../../../services/auth/auth.service';
import { CertificateRequest } from '../../../models/CertificateRequest';
import { CertificateRequestsService } from '../../../services/certificates/certificate-requests.service';

@Component({
  selector: 'app-request-certificate',
  standalone: true,
  imports: [
    FormsModule,
    MatDatepickerModule,
    MatInputModule,
    MatNativeDateModule,
    MatFormFieldModule,
    MatButtonModule,
    MatIconModule,
    MatSelectModule,
    NgForOf,
    NgIf,
    MatTabGroup,
    MatTab,
    MatTabContent,
    MatProgressSpinner,
    MatChipRemove,
    MatChipRow,
    MatChipSet
  ],
  templateUrl: './request-certificate.component.html',
  styleUrl: './request-certificate.component.css'
})
export class RequestCertificateComponent implements OnInit {
  @ViewChild('notAfterCSRModel') dateNotAfterCSRModel!: NgModel;
  @ViewChild('notBeforeModel') dateNotBeforeModel!: NgModel;
  @ViewChild('notAfterModel') dateNotAfterModel!: NgModel;
  @ViewChild('requestForm') requestForm!: NgForm;
  @ViewChild('csrForm') csrForm!: NgForm;

  certificateRequestsService = inject(CertificateRequestsService);
  usersService = inject(UsersService);
  toast = inject(ToastrService);
  auth = inject(AuthService);
  dialog = inject(MatDialog);

  loading = true;
  caUsers: CaUser[] = [];

  protected readonly ExtendedKeyUsageValue = ExtendedKeyUsageValue;
  protected readonly KeyUsageValue = KeyUsageValue;

  extensions: { key: string, value: any }[] = [];
  dateNotBefore: Date | null = null;
  dateNotAfter: Date | null = null;
  signingOrganization: CaUser | null = null;

  commonName = '';
  organization = '';
  organizationalUnit = '';
  email = '';
  country = '';

  fileName: string | null = null;
  csrFile: File | undefined = undefined;
  isDragging = false;

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
    this.usersService.getValidCaUsers().subscribe({
      next: value => {
        this.caUsers = value;
        this.loading = false;
      },
      error: err => {
        this.toast.error("Error", "Unable to load CA users: " + err);
      }
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

  clearExtensionValue(ext: { key: string; value: any }) {
    if (ext.key === 'subjectAlternativeNames' || ext.key === 'issuerAlternativeNames')
      ext.value = [];
    else if (ext.key === 'nameConstraints')
      ext.value = [[], []];
    else if (ext.key === 'basicConstraints')
      ext.value = { isCA: null, pathLen: null };
    else if (ext.key === 'certificatePolicies')
      ext.value = { policyIdentifier: null, cpsUri: null, userNotice: null };
    else ext.value = '';
    return ext;
  }

  handleKeyDown(event: KeyboardEvent, extValue: any[], prefixRef: MatSelect) {
    if (!['Enter', ','].includes(event.key)) return;
    event.preventDefault();
    const nameInput = event.target as HTMLInputElement;
    const value = nameInput.value?.trim();
    if (!value) return;
    extValue.push({ prefix: prefixRef.value, value });
    nameInput.value = '';
  }

  removeChip(extValue: any, chip: any) {
    const index = extValue.indexOf(chip);
    if (index >= 0) extValue.splice(index, 1);
  }

  sanitizePathLen(event: Event, ext: { key: string; value: any }) {
    const input = event.target as HTMLInputElement;
    input.value = input.value.replace(/[^0-9]/g, '');
    if (input.value.length > 1 && input.value.startsWith('0')) {
      const move = input.value.length > 2;
      input.value = input.value.replace(/^0+/, '');
      if (move) input.setSelectionRange(0, 0);
    }
    ext.value.pathLen = input.value ? +input.value : null;
  }

  generalNamesToString(list: { prefix: string, value: string }[]) {
    return list.map(item => `${item.prefix}:${item.value}`).join(',');
  }

  onSubmit(form: NgForm) {
    if (!form.valid || !this.signingOrganization) return;
    this.loading = true;

    const dto: CertificateRequest = {
      signingOrganization: this.signingOrganization.id,
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

    this.certificateRequestsService.createRequest(dto).subscribe({
      next: keys => {
        this.loading = false;
        this.toast.success("Success", "Certificate request successfully created");
        this.resetFields();
        this.dialog.open(KeysDialogComponent, {
          width: '100%',
          maxWidth: '800px',
          data: keys
        });
      },
      error: err => {
        this.loading = false;
        this.toast.error("Unable to request the certificate", `Error: ${err}`);
      }
    });
  }

  onSubmitCSR(form: NgForm) {
    if (!form.valid || !this.csrFile || !this.signingOrganization) return;
    this.loading = true;

    this.certificateRequestsService.createRequestCSR(this.signingOrganization.id, this.csrFile, this.dateNotAfter).subscribe({
      next: () => {
        this.loading = false;
        this.toast.success("Success", "Certificate request successfully created");
        this.resetFields();
      },
      error: err => {
        this.loading = false;
        this.toast.error("Unable to request the certificate", `Error: ${err}`);
      }
    });
  }

  private resetFields() {
    this.extensions = [];
    this.removeFile();
    this.csrForm.resetForm();
    this.requestForm.resetForm();
    this.dateNotBefore = null;
    this.dateNotAfter = null;
  }

  onFileChosen(event: Event) {
    this.csrFile = (event.target as HTMLInputElement).files?.[0];
    if (this.csrFile) this.fileName = this.csrFile.name;
  }

  onDrop(event: DragEvent) {
    this.isDragging = false;
    event.preventDefault();
    this.csrFile = event.dataTransfer?.files[0];
    if (this.csrFile) this.fileName = this.csrFile.name;
  }

  removeFile(event: Event | undefined = undefined) {
    event?.stopPropagation();
    this.csrFile = undefined;
    this.fileName = null;
  }

  onDragOver(event: DragEvent) {
    event.preventDefault();
    this.isDragging = true;
  }

  onDragLeave(event: DragEvent) {
    event.preventDefault();
    this.isDragging = false;
  }
}
