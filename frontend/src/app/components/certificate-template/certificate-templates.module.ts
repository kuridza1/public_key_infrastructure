import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { ReactiveFormsModule } from '@angular/forms';

import { CertificateTemplateListComponent } from './certificate-template-list/certificate-template-list.component';
import { CertificateTemplateFormComponent } from './certificate-template-form/certificate-template-form.component';

const routes: Routes = [
  { path: '', component: CertificateTemplateListComponent },
  { path: 'create', component: CertificateTemplateFormComponent },
  { path: 'edit/:id', component: CertificateTemplateFormComponent }
];

@NgModule({
  declarations: [
    CertificateTemplateListComponent,
    CertificateTemplateFormComponent
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    RouterModule.forChild(routes)
  ],
  exports: [
    RouterModule
  ]
})
export class CertificateTemplatesModule { }