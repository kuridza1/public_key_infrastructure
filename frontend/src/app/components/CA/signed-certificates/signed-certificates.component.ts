import { Component, inject, OnInit } from '@angular/core';
import {
  MatCell, MatCellDef, MatColumnDef, MatHeaderCell, MatHeaderCellDef,
  MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatTable, MatTableDataSource
} from '@angular/material/table';
import { MatIconButton } from '@angular/material/button';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { RevokeCertificateDialogComponent } from '../../helpers/revoke-certificate-dialog/revoke-certificate-dialog.component';
import { CertificateDetailsDialogComponent } from '../../helpers/certificate-details-dialog/certificate-details-dialog.component';
import { DatePipe, NgIf } from '@angular/common';
import { Certificate } from '../../../models/Certificate';
import { downloadFile } from '../../helpers/download-file';
import { CertificatesService } from '../../../services/certificates/certificate.service';
import { extractBlobError } from '../../helpers/extract-blob-error';
import { AuthService } from '../../../services/auth/auth.service';
import { MatProgressSpinner } from '@angular/material/progress-spinner';
import { RevokeCertificate } from '../../../models/RevokeCertificate';
import { CrlService } from '../../../services/crl/crl.service';
import { DownloadCertificatePwDialogComponent } from '../../helpers/download-certificate-pw-dialog/download-certificate-pw-dialog.component';
import { DownloadCertificateRequest } from '../../../models/DownloadCertificateRequest';

@Component({
  selector: 'app-signed-certificates',
  standalone: true,
  imports: [
    MatCell, MatCellDef, MatColumnDef, MatHeaderCell, MatHeaderRow, MatHeaderRowDef,
    MatIconButton, MatRow, MatRowDef, MatTable, MatHeaderCellDef, DatePipe, NgIf, MatProgressSpinner
  ],
  templateUrl: './signed-certificates.component.html',
  styleUrl: './signed-certificates.component.css'
})
export class SignedCertificatesComponent implements OnInit {
  // The backend expects one of these exact strings
  private readonly REASON_NAMES = [
    'UNSPECIFIED',
    'KEY_COMPROMISE',
    'AFFILIATION_CHANGED',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'PRIVILEGE_WITHDRAWN',
  ] as const;

  certificatesService = inject(CertificatesService);
  dialog = inject(MatDialog);
  auth = inject(AuthService);
  crlService = inject(CrlService);

  signedByMeCertificates: Certificate[] = [];
  signedCertificatesDataSource = new MatTableDataSource<Certificate>();
  displayedColumns: string[] = ['issuedTo', 'issuedBy', 'status', 'validFrom', 'validUntil', 'serialNumber', 'actions'];
  loading = true;

  ngOnInit() {
    this.loadSignedCertificates();
  }

  private normalizeReason(result: number | string): (typeof this.REASON_NAMES)[number] {
    if (typeof result === 'number') {
      // dialog returned index -> map to string name
      return this.REASON_NAMES[result] ?? 'UNSPECIFIED';
    }
    // dialog returned string -> ensure it’s one of the allowed names
    const idx = this.REASON_NAMES.indexOf(result as any);
    return idx >= 0 ? this.REASON_NAMES[idx] : 'UNSPECIFIED';
  }

  loadSignedCertificates() {
    this.loading = true;
    this.certificatesService.getCertificatesSignedByMe().subscribe({
      next: value => {
        this.signedByMeCertificates = value;
        this.signedCertificatesDataSource.data = this.signedByMeCertificates;
        this.loading = false;
      },
      error: err => {
        console.error('Error loading certificates signed by me:', err);
        this.loading = false;
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
        revocationReason: reason,              // <-- string enum name
        serialNumber: certificate.serialNumber // <-- as string
      };

      this.loading = true;

      this.crlService.revokeCertificate(revokeCertificate).subscribe({
        next: () => {
          // refresh list after successful revoke
          this.loadSignedCertificates();
        },
        error: async (err) => {
          this.loading = false;
          const msg = await extractBlobError(err).catch(() => null);
          console.error('Error revoking the certificate:', msg ?? err?.message ?? err);
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
          console.error('Download failed:', errorMessage ?? err?.message ?? err);
        }
      });
    });
  }
}
