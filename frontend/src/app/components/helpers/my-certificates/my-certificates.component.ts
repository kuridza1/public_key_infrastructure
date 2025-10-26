import { Component, inject, OnInit } from '@angular/core';
import {
  MatCell, MatCellDef, MatColumnDef, MatHeaderCell, MatHeaderCellDef,
  MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatTable, MatTableDataSource
} from '@angular/material/table';
import { MatIconButton } from '@angular/material/button';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { RevokeCertificateDialogComponent } from '../revoke-certificate-dialog/revoke-certificate-dialog.component';
import { CertificateDetailsDialogComponent } from '../certificate-details-dialog/certificate-details-dialog.component';
import { DatePipe, NgIf } from '@angular/common';
import { Certificate } from '../../../models/Certificate';
import { CertificatesService } from '../../../services/certificates/certificate.service';
import { downloadFile } from '../download-file';
import { AuthService } from '../../../services/auth/auth.service';
import { ToastrService } from '../toastr/toastr.service';
import { extractBlobError } from '../extract-blob-error';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { RevokeCertificate } from '../../../models/RevokeCertificate';
import { CrlService } from '../../../services/crl/crl.service';
import { DownloadCertificatePwDialogComponent } from '../download-certificate-pw-dialog/download-certificate-pw-dialog.component';
import { DownloadCertificateRequest } from '../../../models/DownloadCertificateRequest';

@Component({
  selector: 'app-my-certificates',
  standalone: true,
  imports: [
    MatCell, MatCellDef, MatColumnDef, MatHeaderCell, MatHeaderRow, MatHeaderRowDef,
    MatIconButton, MatRow, MatRowDef, MatTable, MatHeaderCellDef,
    DatePipe, NgIf, MatProgressSpinner
  ],
  templateUrl: './my-certificates.component.html',
  styleUrl: './my-certificates.component.css'
})
export class MyCertificatesComponent implements OnInit {
  // Backend expects one of these exact strings
  private readonly REASON_NAMES = [
    'UNSPECIFIED',
    'KEY_COMPROMISE',
    'AFFILIATION_CHANGED',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'PRIVILEGE_WITHDRAWN',
  ] as const;

  certificatesService = inject(CertificatesService);
  toast = inject(ToastrService);
  dialog = inject(MatDialog);
  auth = inject(AuthService);
  crlService = inject(CrlService);

  myCertificates: Certificate[] = [];
  loading = true;
  certificatesDataSource = new MatTableDataSource<Certificate>();
  displayedColumns: string[] = ['issuedTo', 'issuedBy', 'status', 'validFrom', 'validUntil', 'serialNumber', 'actions'];

  ngOnInit() {
    this.loadMyCertificates();
  }

  private normalizeReason(result: number | string): (typeof this.REASON_NAMES)[number] {
    if (typeof result === 'number') {
      return this.REASON_NAMES[result] ?? 'UNSPECIFIED';
    }
    const idx = this.REASON_NAMES.indexOf(result as any);
    return idx >= 0 ? this.REASON_NAMES[idx] : 'UNSPECIFIED';
  }

  private loadMyCertificates() {
    this.loading = true;
    this.certificatesService.getMyCertificates().subscribe({
      next: value => {
        this.myCertificates = value;
        this.certificatesDataSource.data = this.myCertificates;
        this.loading = false;
      },
      error: err => {
        this.loading = false;
        this.toast.error('Error', 'Error loading my certificates: ' + (err?.message ?? err));
      }
    });
  }

  openRevokeCertificate(certificate: Certificate) {
    const dialogRef: MatDialogRef<RevokeCertificateDialogComponent, number | string | null | undefined> =
      this.dialog.open(RevokeCertificateDialogComponent, { width: '30rem' });

    dialogRef.afterClosed().subscribe(result => {
      if (result === null || result === undefined) return;

      const reason = this.normalizeReason(result);

      const revokeCertificate: RevokeCertificate = {
        revocationReason: reason,               // string enum name
        serialNumber: certificate.serialNumber  // string
      };

      this.loading = true;

      this.crlService.revokeCertificate(revokeCertificate).subscribe({
        next: () => {
          this.toast.success('Success', 'Successfully revoked the certificate');
          this.loadMyCertificates(); // refresh list
        },
        error: async (err) => {
          this.loading = false;
          const msg = await extractBlobError(err).catch(() => null);
          this.toast.error('Error', 'Error revoking the certificate: ' + (msg ?? err?.message ?? err));
        }
      });
    });
  }

  openCertificateDetails(certificate: Certificate) {
    this.dialog.open(CertificateDetailsDialogComponent, {
      width: '850px',
      maxWidth: '70vw',
      data: { encodedCertificate: certificate.decryptedCertificate }
    });
  }

  downloadCertificate(certificate: Certificate) {
    const dialogRef: MatDialogRef<DownloadCertificatePwDialogComponent, string | null | undefined> =
      this.dialog.open(DownloadCertificatePwDialogComponent, { width: '30rem' });

    dialogRef.afterClosed().subscribe(result => {
      if (result === null || result === undefined) return;

      const downloadRequest: DownloadCertificateRequest = {
        certificateSerialNumber: certificate.serialNumber,
        password: result
      };

      this.certificatesService.downloadCertificate(downloadRequest).subscribe({
        next: (blob: Blob) => {
          downloadFile(blob, `certificate_${certificate.prettySerialNumber}.pfx`);
        },
        error: async (err) => {
          const errorMessage = await extractBlobError(err).catch(() => null);
          this.toast.error('Error', 'Download failed: ' + (errorMessage ?? err?.message ?? err));
        }
      });
    });
  }
}
