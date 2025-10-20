import {Component, inject, OnInit, ViewChild} from '@angular/core';
import {FormsModule, NgForm, NgModel, ReactiveFormsModule} from '@angular/forms';
import {MatDatepickerModule} from '@angular/material/datepicker';
import {MatFormFieldModule} from '@angular/material/form-field';
import {MatButtonModule} from '@angular/material/button';
import {MatInputModule} from '@angular/material/input';
import {DateAdapter, MAT_DATE_FORMATS, MatNativeDateModule} from '@angular/material/core';
import {MatSelect, MatSelectModule} from '@angular/material/select';
import {NgForOf, NgIf} from '@angular/common';
import {CustomDateAdapter} from '../custom-components/custom-date/custom-date-adapter';
import {CUSTOM_DATE_FORMATS} from '../custom-components/custom-date/custom-date-formats';
import {CreateCertificate} from '../../../models/CreateCertificate';
import {MatChipsModule} from '@angular/material/chips';
import {KeyUsageValue} from '../../../models/KeyUsageValue';
import {ExtendedKeyUsageValue} from '../../../models/ExtendedKeyUsageValue';
import {CertificatesService} from '../../../services/certificates/certificates.service';
import {ToastrService} from '../toastr/toastr.service';
import {Certificate} from '../../../models/Certificate';
import {AuthService} from '../../../services/auth/auth.service';
import {MatProgressSpinner} from '@angular/material/progress-spinner';

@Component({
  selector: 'app-issue-certificate',
  standalone: true,
  imports: [
    FormsModule,
    MatDatepickerModule,
    MatInputModule,
    MatNativeDateModule,
    MatFormFieldModule,
    MatButtonModule,
    MatSelectModule,
    NgForOf,
    NgIf,
    MatChipsModule,
    ReactiveFormsModule,
    MatProgressSpinner
  ],
  providers: [
    {provide: DateAdapter, useClass: CustomDateAdapter},
    {provide: MAT_DATE_FORMATS, useValue: CUSTOM_DATE_FORMATS}
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
  toast = inject(ToastrService)

  protected readonly ExtendedKeyUsageValue = ExtendedKeyUsageValue;
  protected readonly KeyUsageValue = KeyUsageValue;
  loading = true;
  noSigningCertificates = false;
  signingCertificates: { key: string | Certificate, value: string }[] = [];
  extensions: { key: string, value: any }[] = [];
  dateNotBefore: Date | null = null;
  dateNotAfter: Date | null = null;
  signingCertificate: string | Certificate = '';
  commonName = ''
  organization = ''
  organizationalUnit = ''
  email = ''
  country = ''

  allExtensionKeys = [
    {value: 'keyUsage', label: 'Key Usage'},
    {value: 'extendedKeyUsage', label: 'Extended Key Usage'},
    {value: 'subjectAlternativeNames', label: 'Subject Alternative Names'},
    {value: 'issuerAlternativeNames', label: 'Issuer Alternative Names'},
    {value: 'nameConstraints', label: 'Name Constraints'},
    {value: 'basicConstraints', label: 'Basic Constraints'},
    {value: 'certificatePolicies', label: 'Certificate Policies'}
  ];

  ngOnInit() {
    if (this.auth.role === 'CaUser') {
      this.loadCaSigningCertificates();
    } else if (this.auth.role === 'Admin') {
      this.loadAdminSigningCertificates();
    }
  }

  loadCaSigningCertificates() {
    this.signingCertificates = []
    this.certificatesService.getMyValidCertificates().subscribe({
      next: value => {
        if (value.length === 0) {
          this.noSigningCertificates = true;
        }

        value.sort((a, b) => a.prettySerialNumber.localeCompare(b.prettySerialNumber));
        value.forEach((certificate) => {
          this.signingCertificates.push({key: certificate, value: certificate.prettySerialNumber})
        })
        this.loading = false;
      },
      error: () => {
        this.toast.error("Error", "Unable to get signing certificates");
      }
    })
  }

  loadAdminSigningCertificates() {
    this.signingCertificates = [{key: 'SelfSign', value: 'Self signing'}];
    this.certificatesService.getValidSigningCertificates().subscribe({
      next: value => {
        value.sort((a, b) => a.prettySerialNumber.localeCompare(b.prettySerialNumber));
        value.forEach((certificate) => {
          this.signingCertificates.push({key: certificate, value: certificate.prettySerialNumber})
        });
        this.loading = false;
      },
      error: () => {
        this.toast.error("Error", "Unable to get signing certificates");
      }
    })
  }

  onCountryInput(e: Event) {
    const input = e.target as HTMLInputElement;
    const pos = input.selectionStart!;
    this.country = input.value.replace(/[^A-Za-z]/g, '').toUpperCase();
    input.value = this.country;
    input.setSelectionRange(pos, pos);
  }

  getAvailableKeys(currentExt: unknown) {
    return this.allExtensionKeys.filter(
      key => !this.extensions.some(ext => ext.key === key.value && ext !== currentExt)
    );
  }

  addExtension() {
    if (this.extensions.length < this.allExtensionKeys.length) {
      this.extensions.push({key: '', value: ''});
      const content = document.querySelector('.content');
      if (content) content.scrollTop = content.scrollHeight;
    }
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
      ext.value = {isCA: null, pathLen: null};
    else if (ext.key === 'certificatePolicies')
      ext.value = {policyIdentifier: null, cpsUri: null, userNotice: null};
    else ext.value = '';
    return ext;
  }

  handleKeyDown(event: KeyboardEvent, extValue: any[], prefixRef: MatSelect) {
    if (!['Enter', ','].includes(event.key)) return;
    event.preventDefault();
    const nameInput = event.target as HTMLInputElement;
    const value = nameInput.value?.trim();
    if (!value) return;
    extValue.push({prefix: prefixRef.value, value});
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

  public revalidateDates() {
    if (this.dateNotBeforeModel) this.validateDateField(this.dateNotBefore, this.dateNotBeforeModel, 'notBefore');
    if (this.dateNotAfterModel) this.validateDateField(this.dateNotAfter, this.dateNotAfterModel, 'notAfter');
  }

  validateDateField(date: Date | null, control: NgModel, type: 'notBefore' | 'notAfter') {
    if (!date) {
      control.control.setErrors(null);
      return;
    }

    const key = `invalid${type[0].toUpperCase() + type.slice(1)}`;

    if (type === 'notBefore' && this.dateNotAfter && date >= this.dateNotAfter) {
      this.toast.error('Invalid Date', 'Not Before must be before Not After');
      control.control.setErrors({[key]: true});
      return;
    }

    if (type === 'notAfter' && this.dateNotBefore && date <= this.dateNotBefore) {
      this.toast.error('Invalid Date', 'Not After must be after Not Before');
      control.control.setErrors({[key]: true});
      return;
    }

    const cert = this.signingCertificate as Certificate;
    const certDate = type === 'notBefore' ? cert.validFrom : cert.validUntil;
    const label: string = type === 'notBefore' ? 'Not Before' : 'Not After';
    const direction: string = type === 'notBefore' ? 'after' : 'before';
    const isSelfSign = this.signingCertificate === 'SelfSign';

    if (!isSelfSign && certDate && ((type === 'notBefore' && date < new Date(certDate)) || (type === 'notAfter' && date > new Date(certDate)))) {
      this.toast.error('Invalid Date', `${label} must be ${direction} signing certificate's ${label}`);
      control.control.setErrors({[key]: true});
      return;
    }

    control.control.setErrors(null);
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
      country: this.country
    }

    if (this.dateNotBefore)
      dto.notBefore = this.dateNotBefore;
    if (this.dateNotAfter)
      dto.notAfter = this.dateNotAfter;

    this.extensions.forEach(extension => {
      if (extension.key === 'keyUsage')
        dto.keyUsage = extension.value.map((v: number) => KeyUsageValue[v]);
      else if (extension.key === 'extendedKeyUsage')
        dto.extendedKeyUsage = extension.value.map((v: number) => ExtendedKeyUsageValue[v]);
      else if (extension.key === 'subjectAlternativeNames' && this.generalNamesToString(extension.value))
        dto.subjectAlternativeNames = {value: this.generalNamesToString(extension.value)};
      else if (extension.key === 'issuerAlternativeNames' && this.generalNamesToString(extension.value))
        dto.issuerAlternativeNames = {value: this.generalNamesToString(extension.value)};
      else if (extension.key === 'nameConstraints' && (this.generalNamesToString(extension.value[0]) || this.generalNamesToString(extension.value[1])))
        dto.nameConstraints = {
          permitted: {value: this.generalNamesToString(extension.value[0])},
          excluded: {value: this.generalNamesToString(extension.value[1])}
        };
      else if (extension.key === 'basicConstraints')
        dto.basicConstraints = {
          isCa: extension.value.isCa ?? false,
          pathLen: extension.value.pathLen
        };
      else if (extension.key === 'certificatePolicy')
        dto.certificatePolicy = {
          policyIdentifier: extension.value.policyIdentifier,
          cpsUri: extension.value.cpsUri,
          userNotice: extension.value.userNotice
        };
    })

    this.certificatesService.issueCertificate(dto).subscribe({
      next: () => {
        this.loading = false;
        this.toast.success("Success", "Certificate successfully created");
        if (this.auth.role === 'CaUser') {
          this.loadCaSigningCertificates();
        } else if (this.auth.role === 'Admin') {
          this.loadAdminSigningCertificates();
        }
        this.resetFields();
      },
      error: err => {
        this.toast.error("Unable to issue the certificate", `Error: ${err}`);
      }
    });
  }

  private resetFields() {
    this.extensions = [];
    this.certForm.resetForm();
  }
}
