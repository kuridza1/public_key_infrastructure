import {EditCertificateRequestDialogComponent} from './edit-certificate-request-dialog/edit-certificate-request-dialog.component';
import {CSRResponse} from '../../../models/CSRResponse';
import {MatIconButton} from '@angular/material/button';
import {MatDialog} from '@angular/material/dialog';
import {Component, inject, OnInit} from '@angular/core';
import {
  MatCell, MatCellDef, MatColumnDef, MatHeaderCell, MatHeaderCellDef,
  MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatTable
} from '@angular/material/table';
import {CertificateRequestsService} from '../../../services/certificates/certificate-requests.service';
import {ToastrService} from '../../common/toastr/toastr.service';
import {DatePipe} from '@angular/common';

@Component({
  selector: 'app-certificate-requests',
  standalone: true,
  imports: [
    MatCell,
    MatCellDef,
    MatColumnDef,
    MatHeaderCell,
    MatHeaderRow,
    MatHeaderRowDef,
    MatIconButton,
    MatRow,
    MatRowDef,
    MatTable,
    MatHeaderCellDef,
    DatePipe
  ],
  templateUrl: './certificate-requests.component.html',
  styleUrl: './certificate-requests.component.scss'
})
export class CertificateRequestsComponent implements OnInit {
  certificateRequestService = inject(CertificateRequestsService);
  toast = inject(ToastrService);
  dialog = inject(MatDialog);

  displayedColumns: string[] = [
    'subject',
    'organization',
    'organizationalUnit',
    'submittedOn',
    'actions'
  ];

  certificateRequests: CSRResponse[] = [];

  ngOnInit(): void {
    this.loadRequests();
  }

  loadRequests() {
    this.certificateRequestService.getRequests().subscribe({
      next: data => this.certificateRequests = data,
      error: err => this.toast.error("Error", "Unable to load certificate requests: " + err)
    })
  }

  openEditCertificate(certificate: CSRResponse) {
    this.dialog.open(EditCertificateRequestDialogComponent, {
      maxWidth: '80vw',
      autoFocus: false,
      data: certificate
    }).afterClosed().subscribe(result => {
      if (result === 'reload') {
        this.loadRequests();
      }
    });
  }
}
