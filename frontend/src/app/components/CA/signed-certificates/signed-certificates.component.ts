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
import {MatDialog, MatDialogRef} from '@angular/material/dialog';
import {RevokeCertificateDialogComponent} from '../../helpers/revoke-certificate-dialog/revoke-certificate-dialog.component';
import {CertificateDetailsDialogComponent} from '../../helpers/certificate-details-dialog/certificate-details-dialog.component';
import {DatePipe, NgIf} from '@angular/common';
import {Certificate} from '../../../models/Certificate';
import {downloadFile} from '../../helpers/download-file';
import {CertificatesService} from '../../../services/certificates/certificate.service';
import {extractBlobError} from '../../helpers/extract-blob-error';
import {AuthService} from '../../../services/auth/auth.service';
import {MatProgressSpinner} from '@angular/material/progress-spinner';
import {RevokeCertificate} from '../../../models/RevokeCertificate';
import {CrlService} from '../../../services/crl/crl.service';
import {DownloadCertificatePwDialogComponent} from '../../helpers/download-certificate-pw-dialog/download-certificate-pw-dialog.component';
import {DownloadCertificateRequest} from '../../../models/DownloadCertificateRequest';
import { RevocationReason } from '../../../models/RevocationReason';

@Component({
  selector: 'app-signed-certificates',
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
    DatePipe,
    MatProgressSpinner,
    NgIf
  ],
  templateUrl: './signed-certificates.component.html',
  styleUrl: './signed-certificates.component.scss'
})
export class SignedCertificatesComponent implements OnInit {
  certificatesService = inject(CertificatesService);
  dialog = inject(MatDialog);
  auth = inject(AuthService);
  crlService = inject(CrlService);

  signedByMeCertificates: Certificate[] = [];
  loading = true;
  signedCertificatesDataSource = new MatTableDataSource();
  displayedColumns: string[] = ['issuedTo', 'issuedBy', 'status', 'validFrom', 'validUntil', 'serialNumber', 'actions'];

  ngOnInit() {
    this.loadSignedCertificates();
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
        console.error("Error loading certificates signed by me:", err);
        this.loading = false;
      }
    });
  }

openRevokeCertificate(certificate: Certificate) {
  const dialogRef: MatDialogRef<RevokeCertificateDialogComponent, string | null> =
    this.dialog.open(RevokeCertificateDialogComponent, { width: '30rem' });

  dialogRef.afterClosed().subscribe(result => {
    if (!result) return;

    const reason = RevocationReason[result as keyof typeof RevocationReason];

    const revokeCertificate: RevokeCertificate = {
      revocationReason: reason,
      serialNumber: certificate.serialNumber
    };

    this.loading = true;

    this.crlService.revokeCertificate(revokeCertificate).subscribe({
      next: () => {
        console.log("Successfully revoked the certificate.");
        this.loadSignedCertificates();
      },
      error: err => {
        console.error("Error revoking the certificate:", err);
        this.loading = false;
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
      if (!result) return;

      const downloadRequest: DownloadCertificateRequest = {
        certificateSerialNumber: certificate.serialNumber,
        password: result
      };

      this.certificatesService.downloadCertificate(downloadRequest).subscribe({
        next: (blob: Blob) => {
          downloadFile(blob, `certificate_${certificate.prettySerialNumber}.pfx`);
        },
        error: async (err) => {
          const errorMessage = await extractBlobError(err);
          console.error("Download failed:", errorMessage);
        }
      });
    });
  }
}
