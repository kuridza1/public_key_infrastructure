import {Component, inject, OnInit} from '@angular/core';
import {
  MatCell,
  MatCellDef,
  MatColumnDef,
  MatHeaderCell, MatHeaderCellDef,
  MatHeaderRow,
  MatHeaderRowDef,
  MatRow, MatRowDef, MatTable, MatTableDataSource
} from '@angular/material/table';
import {MatIconButton} from '@angular/material/button';
import {MatDialog} from '@angular/material/dialog';
import {CertificateDetailsDialogComponent} from '../certificate-details-dialog/certificate-details-dialog.component';
import {Certificate} from '../../../models/Certificate';
import {RevokedCertificate} from '../../../models/RevokedCertificate';
import {CrlService} from '../../../services/crl/crl.service';
import {ToastrService} from '../toastr/toastr.service';
import {downloadFile} from '../custom-components/blob/download-file';
import {extractBlobError} from '../custom-components/blob/extract-blob-error';
import {CertificatesService} from '../../../services/certificates/certificates.service';
import {NgIf, NgSwitchCase} from '@angular/common';
import {RevocationReason} from '../../../models/RevocationReason';
import {MatProgressSpinner} from '@angular/material/progress-spinner';

@Component({
  selector: 'app-crl-page',
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
    NgSwitchCase,
    NgIf,
    MatProgressSpinner
  ],
  templateUrl: './crl-page.component.html',
  styleUrl: './crl-page.component.scss'
})
export class CrlPageComponent implements OnInit {
  dialog = inject(MatDialog);
  crlService = inject(CrlService);
  certificatesService = inject(CertificatesService);
  toast = inject(ToastrService);

  displayedColumns: string[] = [
    'issuedTo',
    'issuedBy',
    'revocationReason',
    'serialNumber',
    'actions'
  ];

  loading = true;
  revokedCertificates: RevokedCertificate[] = [];
  revokedCertificatesDataSource = new MatTableDataSource();

  ngOnInit(): void {
    this.crlService.getAllRevokedCertificates().subscribe({
      next: value => {
        this.revokedCertificates = value;
        this.revokedCertificatesDataSource.data = this.revokedCertificates;
        this.loading = false;
      },
      error: err => {
        this.toast.error("Error", "Unable to load revoked certificates: " + err);
      }
    })
  }

  openCertificateDetails(certificate: Certificate) {
    this.dialog.open(CertificateDetailsDialogComponent, {
      width: '850px',
      maxWidth: '70vw',
      data: { encodedCertificate: certificate.decryptedCertificate }
    });
  }
}
