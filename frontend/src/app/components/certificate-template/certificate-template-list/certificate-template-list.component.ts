import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { CertificateTemplateService } from '../../../services/certificates/certificate-templates.service';
import { TemplateResponse } from '../../../models/CertificateTemplate';
import { CertificateTemplateFormComponent } from '../certificate-template-form/certificate-template-form.component';

@Component({
  selector: 'app-certificate-template-list',
  standalone: true,
  imports: [
    CommonModule, 
    MatTableModule, 
    MatIconModule, 
    MatButtonModule,
    CertificateTemplateFormComponent
  ],
  templateUrl: './certificate-template-list.component.html',
  styleUrls: ['./certificate-template-list.component.css']
})
export class CertificateTemplateListComponent implements OnInit {
  templates: TemplateResponse[] = [];
  loading = false;
  error = '';
  showCreateForm = false;
  editingTemplate: TemplateResponse | null = null;

  // Table properties
  displayedColumns: string[] = [
    'name', 
    'caIssuer', 
    'commonNameRegex', 
    'maxTtl', 
    'keyUsage', 
    'createdBy', 
    'createdAt', 
    'actions'
  ];
  
  templatesDataSource: TemplateResponse[] = [];

  constructor(private templateService: CertificateTemplateService) {}

  ngOnInit(): void {
    this.loadTemplates();
  }

  loadTemplates(): void {
    this.loading = true;
    this.templateService.getTemplates().subscribe({
      next: (templates) => {
        this.templates = templates;
        this.templatesDataSource = templates;
        this.loading = false;
      },
      error: (error) => {
        this.error = 'Failed to load templates';
        this.loading = false;
        console.error('Error loading templates:', error);
      }
    });
  }

  createTemplate(): void {
    this.showCreateForm = true;
    this.editingTemplate = null;
  }

  editTemplate(template: TemplateResponse): void {
    this.editingTemplate = template;
    this.showCreateForm = true;
  }

  deleteTemplate(template: TemplateResponse): void {
    if (confirm(`Are you sure you want to delete template "${template.name}"?`)) {
      this.templateService.deleteTemplate(template.id).subscribe({
        next: () => {
          this.templates = this.templates.filter(t => t.id !== template.id);
          this.templatesDataSource = this.templates;
        },
        error: (error) => {
          alert('Failed to delete template');
          console.error('Error deleting template:', error);
        }
      });
    }
  }

  useTemplate(template: TemplateResponse): void {
    // Navigate to certificate issuance with template pre-selected
    console.log('Using template:', template);
    // You can implement navigation or emit an event here
  }

  onTemplateSaved(): void {
    this.showCreateForm = false;
    this.editingTemplate = null;
    this.loadTemplates();
  }

  onFormClosed(): void {
    this.showCreateForm = false;
    this.editingTemplate = null;
  }
}