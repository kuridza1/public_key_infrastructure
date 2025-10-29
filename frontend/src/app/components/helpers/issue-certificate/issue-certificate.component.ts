import {Component, inject, OnInit, ViewChild} from '@angular/core';
import {FormsModule, NgForm, NgModel, ReactiveFormsModule} from '@angular/forms';
import {MatDatepickerModule} from '@angular/material/datepicker';
import {MatFormFieldModule} from '@angular/material/form-field';
import {MatButtonModule} from '@angular/material/button';
import {MatInputModule} from '@angular/material/input';
import {DateAdapter, MAT_DATE_FORMATS, MatNativeDateModule} from '@angular/material/core';
import {MatSelect, MatSelectModule} from '@angular/material/select';
import {NgForOf, NgIf} from '@angular/common';
import {CreateCertificate} from '../../../models/CreateCertificate';
import {MatChipsModule} from '@angular/material/chips';
import {KeyUsageValue} from '../../../models/KeyUsageValue';
import {ExtendedKeyUsageValue} from '../../../models/ExtendedKeyUsageValue';
import { CertificatesService } from '../../../services/certificates/certificate.service';
import {ToastrService} from '../toastr/toastr.service';
import {Certificate} from '../../../models/Certificate';
import {AuthService} from '../../../services/auth/auth.service';
import {MatProgressSpinner} from '@angular/material/progress-spinner';
import { CertificateTemplateService, TemplateResponse } from '../../../services/certificates/certificate-templates.service';
import { MatCheckboxModule } from '@angular/material/checkbox';

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
    MatCheckboxModule,
  ],
  templateUrl: './issue-certificate.component.html',
  styleUrl: './issue-certificate.component.css'
})
export class IssueCertificateComponent implements OnInit {
  @ViewChild('notBeforeModel') dateNotBeforeModel!: NgModel;
  @ViewChild('notAfterModel') dateNotAfterModel!: NgModel;
  @ViewChild('certForm') certForm!: NgForm;

  certificatesService = inject(CertificatesService);
  templateService = inject(CertificateTemplateService); // NEW SERVICE
  auth = inject(AuthService);
  toast = inject(ToastrService)

  protected readonly ExtendedKeyUsageValue = ExtendedKeyUsageValue;
  protected readonly KeyUsageValue = KeyUsageValue;
  loading = true;
  noSigningCertificates = false;
  signingCertificates: { key: string | Certificate, value: string }[] = [];
  templates: TemplateResponse[] = [];
  useTemplate = false;
  selectedTemplate: TemplateResponse | null = null;
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

onSigningCertificateChange() {
  if (this.useTemplate && this.signingCertificate && typeof this.signingCertificate !== 'string') {
    // Load templates for the SELECTED CA CERTIFICATE, not the user
    this.loadTemplatesForCa(this.signingCertificate);
  } else {
    this.templates = [];
    this.selectedTemplate = null;
  }
}

loadTemplatesForCa(selectedCertificate: Certificate) {
  if (this.auth.role === 'CaUser') {
    // For CA Users: Get templates for this specific CA certificate
    this.templateService.getTemplatesForCa(selectedCertificate.serialNumber).subscribe({
      next: (templates) => {
        this.templates = templates;
        console.log(templates)
        this.checkTemplatesAvailability();
      },
      error: (error) => {
        console.error('Error loading templates:', error);
        this.toast.error('Error', 'Unable to load templates');
      }
    });
  } else if (this.auth.role === 'Admin') {
    // For Admins: Get all templates (or filter by CA if desired)
    this.templateService.getTemplates().subscribe({
      next: (templates) => {
        // Optional: Filter by selected CA for admins too
        this.templates = templates
        this.checkTemplatesAvailability();
      },
      error: (error) => {
        console.error('Error loading templates:', error);
        this.toast.error('Error', 'Unable to load templates');
      }
    });
  }
}

private doesTemplateMatchCertificate(template: TemplateResponse, certificate: Certificate): boolean {
  // Parse the certificate's issuedTo field to extract components
  const certComponents = this.parseIssuedTo(certificate.issuedTo);
  
  // Build a normalized issuer name from certificate components
  const certIssuerNormalized = this.buildIssuerName(
    certComponents.cn,
    certComponents.o, 
    certComponents.ou,
    certComponents.email,
    certComponents.c
  );
  
  // Compare with template's caIssuerName
  return template.caIssuerName === certIssuerNormalized;
}

// Helper to parse issuedTo field (format: "CN\nO, OU\nSE")
private parseIssuedTo(issuedTo: string): { cn: string, o: string, ou: string, email: string, c: string } {
  const lines = issuedTo.split('\n');
  const result = { cn: '', o: '', ou: '', email: '', c: '' };
  
  lines.forEach(line => {
    line = line.trim();
    
    // First line should be CN
    if (line.startsWith('CN') && !result.cn) {
      result.cn = line.replace('CN', '').trim();
    } 
    // Second line contains O and OU
    else if (line.includes('O') && line.includes(',')) {
      const parts = line.split(',');
      parts.forEach(part => {
        const trimmed = part.trim();
        if (trimmed.startsWith('O') && !result.o) {
          result.o = trimmed.replace('O', '').trim();
        } else if (trimmed.startsWith('OU') && !result.ou) {
          result.ou = trimmed.replace('OU', '').trim();
        }
      });
    }
    // Last line might be country or other components
    else if (line.length === 2) {
      // Assuming 2-letter country code
      result.c = line;
    }
  });
  
  return result;
}

// Helper to build issuer name in template format
private buildIssuerName(cn: string, o: string, ou: string, email: string, country: string): string {
  const parts = [];
  if (cn) parts.push(`CN=${cn}`);
  if (o) parts.push(`O=${o}`);
  if (ou) parts.push(`OU=${ou}`);
  if (email) parts.push(`E=${email}`);
  if (country) parts.push(`C=${country}`);
  
  return parts.join(',');
}

private checkTemplatesAvailability() {
  if (this.templates.length === 0) {
    this.toast.info('No Templates', 'No templates available for this CA certificate');
  } else {
    this.toast.success('Templates Loaded', `Found ${this.templates.length} template(s)`);
  }
}

onUseTemplateChange() {
  if (!this.useTemplate) {
    this.selectedTemplate = null;
    this.templates = [];
  } else if (this.signingCertificate && typeof this.signingCertificate !== 'string') {
    // Load templates for the selected CA certificate
    this.loadTemplatesForCa(this.signingCertificate);
  } else {
    this.toast.info('Template Usage', 'Please select a CA certificate first');
  }
}
onTemplateChange() {
  if (this.selectedTemplate) {
    this.applyTemplate(this.selectedTemplate);
  } else {
    // Clear any template-applied values when no template is selected
    this.clearTemplateValues();
  }
}
applyTemplate(template: TemplateResponse) {
  console.log('Applying template:', template);

  // 1. CLEAR existing extensions first
  this.extensions = [];

  // 2. Apply common name regex validation hint
  if (template.commonNameRegex) {
    this.toast.info('Template Applied', `Common Name must match: ${template.commonNameRegex}`);
  }

  // 3. Apply key usage if template has it
  if (template.keyUsage) {
    const keyUsageValues = this.parseKeyUsage(template.keyUsage);
    this.extensions.push({
      key: 'keyUsage',
      value: keyUsageValues
    });
  }

  // 4. Apply extended key usage if template has it
  if (template.extendedKeyUsage) {
    const extKeyUsageValues = this.parseExtendedKeyUsage(template.extendedKeyUsage);
    this.extensions.push({
      key: 'extendedKeyUsage',
      value: extKeyUsageValues
    });
  }

  // 5. Apply basic constraints if template has it
  if (template.basicConstraints) {
    const basicConstraints = this.parseBasicConstraints(template.basicConstraints);
    this.extensions.push({
      key: 'basicConstraints',
      value: basicConstraints
    });
  }

  // 6. Auto-set validity period if maxTtlDays is specified
  if (template.maxTtlDays) {
    this.dateNotBefore = new Date();
    this.dateNotAfter = new Date();
    this.dateNotAfter.setDate(this.dateNotAfter.getDate() + template.maxTtlDays);
    this.revalidateDates();
  }

  this.toast.success('Template Applied', `"${template.name}" template has been applied`);
}

// ADD THESE HELPER METHODS:

private parseKeyUsage(keyUsageString: string): KeyUsageValue[] {
  const usages: KeyUsageValue[] = [];
  const usageList = keyUsageString.split(',').map(u => u.trim());

  usageList.forEach(usage => {
    // Case-insensitive matching
    const key = Object.keys(KeyUsageValue).find(
      k => k.toLowerCase() === usage.toLowerCase()
    ) as keyof typeof KeyUsageValue;

    if (key) {
      usages.push(KeyUsageValue[key]);
    } else {
      console.warn(`Unknown key usage: ${usage}`);
    }
  });

  return usages;
}

private parseExtendedKeyUsage(extKeyUsageString: string): ExtendedKeyUsageValue[] {
  const usages: ExtendedKeyUsageValue[] = [];
  const usageList = extKeyUsageString.split(',').map(u => u.trim());

  usageList.forEach(usage => {
    // Case-insensitive matching
    const key = Object.keys(ExtendedKeyUsageValue).find(
      k => k.toLowerCase() === usage.toLowerCase()
    ) as keyof typeof ExtendedKeyUsageValue;

    if (key) {
      usages.push(ExtendedKeyUsageValue[key]);
    } else {
      console.warn(`Unknown extended key usage: ${usage}`);
    }
  });

  return usages;
}

private parseBasicConstraints(basicConstraintsString: string): { isCa: boolean, pathLen: number | null } {
  const constraints = { isCa: false, pathLen: 0 };

  // Case-insensitive parsing
  if (basicConstraintsString.toLowerCase().includes('ca:true')) {
    constraints.isCa = true;
  }

  const pathLenMatch = basicConstraintsString.match(/pathlen:(\d+)/i);
  if (pathLenMatch) {
    constraints.pathLen = parseInt(pathLenMatch[1]);
  }

  return constraints;
}
clearTemplateValues() {
  // Clear template-specific extensions but keep basic form data
  const nonTemplateExtensions = this.extensions.filter(ext =>
    !['keyUsage', 'extendedKeyUsage', 'basicConstraints'].includes(ext.key)
  );
  this.extensions = nonTemplateExtensions;

  this.toast.info('Template Removed', 'Template values have been cleared');
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

    // NEW: Template TTL validation
    if (this.selectedTemplate?.maxTtlDays && this.dateNotBefore && this.dateNotAfter) {
      const requestedDays = Math.ceil((this.dateNotAfter.getTime() - this.dateNotBefore.getTime()) / (1000 * 60 * 60 * 24));
      if (requestedDays > this.selectedTemplate.maxTtlDays) {
        this.toast.error('Invalid Date', `Certificate validity exceeds template maximum of ${this.selectedTemplate.maxTtlDays} days`);
        control.control.setErrors({invalidTtl: true});
        return;
      }
    }

    control.control.setErrors(null);
  }

  generalNamesToString(list: { prefix: string, value: string }[]) {
    return list.map(item => `${item.prefix}:${item.value}`).join(',');
  }

  onSubmit(form: NgForm) {
    if (!form.valid) return;

    // NEW: Template validation
    if (this.useTemplate && this.selectedTemplate) {
      // Validate common name against template regex
      if (this.selectedTemplate.commonNameRegex && !new RegExp(this.selectedTemplate.commonNameRegex).test(this.commonName)) {
        this.toast.error('Validation Error', `Common Name does not match template pattern: ${this.selectedTemplate.commonNameRegex}`);
        return;
      }
    }

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

    // NEW: Add template ID if using template
    if (this.useTemplate && this.selectedTemplate) {
      dto.templateId = this.selectedTemplate.id;
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

    // NEW: Choose between regular and template-based issuance
    const issueRequest = this.useTemplate && this.selectedTemplate
      ? this.certificatesService.issueCertificateWithTemplate(dto)
      : this.certificatesService.issueCertificate(dto);

    issueRequest.subscribe({
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
        this.loading = false;
        this.toast.error("Unable to issue the certificate", `Error: ${err}`);
      }
    });
  }

  private resetFields() {
    this.extensions = [];
    this.useTemplate = false;
    this.selectedTemplate = null;
    this.templates = [];
    this.certForm.resetForm();
  }
}
