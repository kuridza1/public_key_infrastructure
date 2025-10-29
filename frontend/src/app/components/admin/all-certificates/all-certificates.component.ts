import {Component, inject, OnInit} from '@angular/core';
import {
  MatCell, MatCellDef, MatColumnDef, MatHeaderCell, MatHeaderCellDef,
  MatHeaderRow, MatHeaderRowDef, MatRow, MatRowDef, MatTable, MatTableDataSource
} from '@angular/material/table';
import {MatIconButton} from '@angular/material/button';
import {MatDialog, MatDialogRef} from '@angular/material/dialog';
import { RevokeCertificateDialogComponent } from '../../helpers/revoke-certificate-dialog/revoke-certificate-dialog.component';
import { CertificateDetailsDialogComponent } from '../../helpers/certificate-details-dialog/certificate-details-dialog.component';
import { CertificatesService } from '../../../services/certificates/certificate.service';
import {Certificate} from '../../../models/Certificate';
import {MatProgressSpinner} from '@angular/material/progress-spinner';
import {DatePipe, NgIf} from '@angular/common';
import { ToastrService } from '../../helpers/toastr/toastr.service';
import { downloadFile } from '../../helpers/download-file';
import { extractBlobError } from '../../helpers/extract-blob-error';
import {RevokeCertificate} from '../../../models/RevokeCertificate';
import {CrlService} from '../../../services/crl/crl.service';
import { DownloadCertificateRequest } from '../../../models/DownloadCertificateRequest';
import {
  DownloadCertificatePwDialogComponent
} from '../../helpers/download-certificate-pw-dialog/download-certificate-pw-dialog.component';

@Component({
  selector: 'app-all-certificates',
  standalone: true,
  imports: [
    MatTable, MatHeaderCell, MatColumnDef, MatHeaderCellDef,
    MatCell, MatCellDef, MatIconButton, MatHeaderRow, MatRow,
    MatRowDef, MatHeaderRowDef, NgIf, DatePipe, MatProgressSpinner
  ],
  templateUrl: './all-certificates.component.html',
  styleUrl: './all-certificates.component.css'
})
export class AllCertificatesComponent implements OnInit {
  private readonly REASON_MAP = [
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
  crlService = inject(CrlService);

  displayedColumns: string[] = ['issuedTo', 'issuedBy', 'status', 'validFrom', 'validUntil', 'serialNumber', 'actions'];
  certificatesDataSource = new MatTableDataSource<Certificate>();
  certificates: Certificate[] = [];
  loading = true;

  ngOnInit() {
    this.certificatesService.getAllCertificates().subscribe({
      next: value => {
        this.certificates = value;
        this.certificatesDataSource.data = this.certificates;
        this.loading = false;
      },
      error: err => {
        this.loading = false;
        this.toast.error('Error', 'Unable to load certificates: ' + (err?.message ?? err));
      }
    });
  }

  openRevokeCertificate(certificate: Certificate) {
    // Assume dialog returns a number index (0..5). If it already returns the string, you can drop the map.
    const dialogRef: MatDialogRef<RevokeCertificateDialogComponent, number | string | null | undefined> =
      this.dialog.open(RevokeCertificateDialogComponent, { width: '30rem' });

    dialogRef.afterClosed().subscribe(result => {
      if (result === null || result === undefined) return;

      // Normalize to string enum the backend expects
      const reason =
        typeof result === 'number'
          ? this.REASON_MAP[result] // map number -> string name
          : String(result);         // already a string name

      const revokeCertificate: RevokeCertificate = {
        revocationReason: reason as (typeof this.REASON_MAP)[number],
        serialNumber: certificate.serialNumber
      };

      this.loading = true;

      this.crlService.revokeCertificate(revokeCertificate).subscribe({
        next: () => {
          // refresh table
          this.certificatesService.getAllCertificates().subscribe({
            next: value => {
              this.certificates = value;
              this.certificatesDataSource.data = this.certificates;
              this.loading = false;
              this.toast.success('Success', 'Successfully revoked the certificate');
            },
            error: err => {
              this.loading = false;
              this.toast.error('Error', 'Unable to load certificates: ' + (err?.message ?? err));
            }
          });
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
