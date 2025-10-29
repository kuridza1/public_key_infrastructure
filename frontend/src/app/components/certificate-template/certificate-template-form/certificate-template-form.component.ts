import { Component, Input, Output, EventEmitter, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { CertificateTemplateService } from '../../../services/certificates/certificate-templates.service';
import { CertificatesService } from '../../../services/certificates/certificate.service';
import { CreateTemplateRequest, TemplateResponse } from '../../../models/CertificateTemplate';

@Component({
  selector: 'app-certificate-template-form',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './certificate-template-form.component.html',
  styleUrls: ['./certificate-template-form.component.css']
})
export class CertificateTemplateFormComponent implements OnInit {
  @Input() template: TemplateResponse | null = null;
  @Output() saved = new EventEmitter<void>();
  @Output() closed = new EventEmitter<void>();

  templateForm: FormGroup;
  caCertificates: any[] = [];
  loading = false;
  submitting = false;

  constructor(
    private fb: FormBuilder,
    private templateService: CertificateTemplateService,
    private certificateService: CertificatesService
  ) {
    this.templateForm = this.createForm();
  }
    ngOnInit(): void {
        this.templateForm = this.createForm();
        this.loadCaCertificates();

        if (this.template) {
        this.populateForm();
        }
    }

  createForm(): FormGroup {
    return this.fb.group({
      name: ['', [Validators.required, Validators.maxLength(255)]],
      caIssuerId: ['', Validators.required],
      commonNameRegex: [''],
      sanRegex: [''],
      maxTtlDays: [365, [Validators.min(1), Validators.max(3650)]],
      keyUsage: [''],
      extendedKeyUsage: [''],
      basicConstraints: ['']
    });
  }

  populateForm(): void {
    if (this.template) {
      this.templateForm.patchValue({
        name: this.template.name,
        id: this.template.id,
        commonNameRegex: this.template.commonNameRegex,
        sanRegex: this.template.sanRegex,
        maxTtlDays: this.template.maxTtlDays,
        keyUsage: this.template.keyUsage,
        extendedKeyUsage: this.template.extendedKeyUsage,
        basicConstraints: this.template.basicConstraints
      });
    }
  }

loadCaCertificates(): void {
  this.loading = true;
  this.certificateService.getValidSigningCertificates().subscribe({
    next: (certificates) => {
      console.log('Loaded CA certificates:', certificates);
      this.caCertificates = certificates;
      this.loading = false;
    },
    error: (error) => {
      console.error('Error loading CA certificates:', error);
      this.loading = false;
    }
  });
}


  onSubmit(): void {
    if (this.templateForm.valid) {
      this.submitting = true;
      const templateData: CreateTemplateRequest = this.templateForm.value;
    console.log('Submitting templateData:', templateData);

      const request = this.template
        ? this.templateService.updateTemplate(this.template.id, templateData)
        : this.templateService.createTemplate(templateData);

      request.subscribe({
        next: () => {
          this.submitting = false;
          this.saved.emit();
        },
        error: (error) => {
          this.submitting = false;
          alert('Failed to save template');
          console.error('Error saving template:', error);
        }
      });
    }
  }

  onCancel(): void {
    this.closed.emit();
  }
}