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
import {RevokeCertificateDialogComponent} from '../revoke-certificate-dialog/revoke-certificate-dialog.component';
import {CertificateDetailsDialogComponent} from '../certificate-details-dialog/certificate-details-dialog.component';
import {DatePipe, NgIf} from '@angular/common';
import {Certificate} from '../../../models/Certificate';
import {CertificatesService} from '../../../services/certificates/certificates.service';
import {downloadFile} from '../custom-components/blob/download-file';
import {AuthService} from '../../../services/auth/auth.service';
import {ToastrService} from '../toastr/toastr.service';
import {extractBlobError} from '../custom-components/blob/extract-blob-error';
import {MatProgressSpinner} from '@angular/material/progress-spinner';
import {RevokeCertificate} from '../../../models/RevokeCertificate';
import {CrlService} from '../../../services/crl/crl.service';
import {
  DownloadCertificatePwDialogComponent
} from '../download-certificate-pw-dialog/download-certificate-pw-dialog.component';
import {DownloadCertificateRequest} from '../../../models/DownloadCertificateRequest';

@Component({
  selector: 'app-my-certificates',
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
  templateUrl: './my-certificates.component.html',
  styleUrl: './my-certificates.component.scss'
})
export class MyCertificatesComponent implements OnInit {
  certificatesService = inject(CertificatesService);
  toast = inject(ToastrService);
  dialog = inject(MatDialog);
  auth = inject(AuthService);
  crlService = inject(CrlService);

  myCertificates: Certificate[] = [];
  loading = true;
  certificatesDataSource = new MatTableDataSource();
  displayedColumns: string[] = ['issuedTo', 'issuedBy', 'status', 'validFrom', 'validUntil', 'serialNumber', 'actions'];

  ngOnInit() {
    this.certificatesService.getMyCertificates().subscribe({
      next: value => {
        this.myCertificates = value;
        this.certificatesDataSource.data = this.myCertificates;
        this.loading = false;
      },
      error: err => {
        this.toast.error("Error", "Error loading my certificates: ", err);
      }
    })
  }

  openRevokeCertificate(certificate: Certificate) {
    const dialogRef: MatDialogRef<RevokeCertificateDialogComponent, null> = this.dialog.open(RevokeCertificateDialogComponent, {
      width: '30rem'
    });

    dialogRef.afterClosed().subscribe(result => {
      if (!result) {
        return;
      }

      const revokeCertificate: RevokeCertificate = {
        revocationReason: result,
        serialNumber: certificate.serialNumber
      };

      this.loading = true;

      this.crlService.revokeCertificate(revokeCertificate).subscribe({
        next: () => {
          this.certificatesService.getMyCertificates().subscribe({
            next: value => {
              this.toast.success("Success", "Successfully revoked the certificate");
              this.myCertificates = value;
              this.certificatesDataSource.data = this.myCertificates;
              this.loading = false;
            },
            error: err => {
              this.toast.error("Error", "Error loading my certificates: ", err);
            }
          })
        },
        error: err => {
          this.loading = false;
          this.toast.error("Error", "Error revoking the certificate: ", err)
        }
      })
    })
  }

  openCertificateDetails(certificate: Certificate) {
    this.dialog.open(CertificateDetailsDialogComponent, {
      width: '850px',
      maxWidth: '70vw',
      data: { encodedCertificate: certificate.decryptedCertificate }
    });
  }

  downloadCertificate(certificate: Certificate) {
    const dialogRef: MatDialogRef<DownloadCertificatePwDialogComponent, string | null | undefined> = this.dialog.open(DownloadCertificatePwDialogComponent, {
      width: '30rem'
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result === null || result === undefined) {
        return;
      }

      const downloadRequest: DownloadCertificateRequest = {
        certificateSerialNumber: certificate.serialNumber,
        password: result
      }

      this.certificatesService.downloadCertificate(downloadRequest).subscribe({
        next: (blob: Blob) => {
          downloadFile(blob, `certificate_${certificate.prettySerialNumber}.pfx`)
        },
        error: async (err) => {
          const errorMessage = await extractBlobError(err);
          this.toast.error("Error", "Download failed: " + errorMessage);
        }
      });
    })
  }
}
