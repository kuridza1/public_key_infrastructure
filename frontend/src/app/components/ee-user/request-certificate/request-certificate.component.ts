import {Component, inject, OnInit, ViewChild} from '@angular/core';
import {FormsModule, NgForm, NgModel} from '@angular/forms';
import {MatDatepickerModule} from '@angular/material/datepicker';
import {MatFormFieldModule} from '@angular/material/form-field';
import {MatButtonModule} from '@angular/material/button';
import {MatInputModule} from '@angular/material/input';
import {DateAdapter, MAT_DATE_FORMATS, MatNativeDateModule} from '@angular/material/core';
import {MatSelect, MatSelectModule} from '@angular/material/select';
import {NgForOf, NgIf} from '@angular/common';
import {MatTab, MatTabContent, MatTabGroup} from '@angular/material/tabs';
import {MatDialog} from '@angular/material/dialog';
import {KeysDialogComponent} from './keys-dialog/keys-dialog.component';
import {MatIconModule} from '@angular/material/icon';
import {CustomDateAdapter} from '../../common/custom-components/custom-date/custom-date-adapter';
import {CUSTOM_DATE_FORMATS} from '../../common/custom-components/custom-date/custom-date-formats';
import {MatProgressSpinner} from '@angular/material/progress-spinner';
import {UsersService} from '../../../services/users/users.service';
import {CaUser} from '../../../models/CaUser';
import {ToastrService} from '../../common/toastr/toastr.service';
import {MatChipRemove, MatChipRow, MatChipSet} from '@angular/material/chips';
import {KeyUsageValue} from '../../../models/KeyUsageValue';
import {ExtendedKeyUsageValue} from '../../../models/ExtendedKeyUsageValue';
import {AuthService} from '../../../services/auth/auth.service';
import {CertificateRequest} from '../../../models/CertificateRequest';
import {CertificateRequestsService} from '../../../services/certificates/certificate-requests.service';

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
  providers: [
    {provide: DateAdapter, useClass: CustomDateAdapter},
    {provide: MAT_DATE_FORMATS, useValue: CUSTOM_DATE_FORMATS}
  ],
  templateUrl: './request-certificate.component.html',
  styleUrl: './request-certificate.component.scss'
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
  commonName = ''
  organization = ''
  organizationalUnit = ''
  email = ''
  country = ''

  fileName: string | null = null;
  csrFile: File | undefined = undefined;
  isDragging = false;

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
    if (this.dateNotAfterCSRModel && this.dateNotAfterCSRModel.control)
      this.validateDateField(this.dateNotAfter, this.dateNotAfterCSRModel, 'notAfter');
    if (this.dateNotBeforeModel && this.dateNotBeforeModel.control)
      this.validateDateField(this.dateNotBefore, this.dateNotBeforeModel, 'notBefore');
    if (this.dateNotAfterModel && this.dateNotAfterModel.control)
      this.validateDateField(this.dateNotAfter, this.dateNotAfterModel, 'notAfter');
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

    const caUser = this.signingOrganization as CaUser;
    if (caUser === null) {
      // this.toast.error('Invalid Date', 'You have to select CA issuer');
      control.control.setErrors({[key]: true});
      return;
    }

    const certDate = type === 'notBefore' ? caUser.minValidFrom : caUser.maxValidUntil;
    const label: string = type === 'notBefore' ? 'Not Before' : 'Not After';
    const direction: string = type === 'notBefore' ? 'after' : 'before';

    if (certDate && ((type === 'notBefore' && date < new Date(certDate)) || (type === 'notAfter' && date > new Date(certDate)))) {
      this.toast.error('Invalid Date', `${label} must be ${direction} issuer's available ${label}`);
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

    if (!this.signingOrganization) return;

    const dto: CertificateRequest = {
      signingOrganization: this.signingOrganization.id,
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
    if (!form.valid) return;
    this.loading = true;

    if (!this.csrFile) return;
    if (!this.signingOrganization) return;

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
  }

  onFileChosen(event: Event) {
    this.csrFile = (event.target as HTMLInputElement).files?.[0]
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
