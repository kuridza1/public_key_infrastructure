import {Component, inject, OnInit} from '@angular/core';
import {
  MatCell,
  MatCellDef,
  MatColumnDef,
  MatHeaderCell, MatHeaderCellDef,
  MatHeaderRow,
  MatHeaderRowDef,
  MatRow, MatRowDef, MatTable, MatTableDataSource
} from "@angular/material/table";
import {MatIconButton} from "@angular/material/button";
import {MatDialog, MatDialogRef} from '@angular/material/dialog';
import {CaRegistrationDialogComponent} from './ca-registration-dialog/ca-registration-dialog.component';
import {CaAddCertificateDialogComponent} from './ca-add-certificate-dialog/ca-add-certificate-dialog.component';
import {CaUser} from '../../../models/CaUser';
import {UsersService} from '../../../services/users/users.service';
import {ToastrService} from '../../common/toastr/toastr.service';
import {CertificatesService} from '../../../services/certificates/certificates.service';
import {Certificate} from '../../../models/Certificate';
import {AddCertificateToCaUser} from '../../../models/AddCertificateToCaUser';

@Component({
  selector: 'app-ca-user-management',
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
    MatHeaderCellDef
  ],
  templateUrl: './ca-user-management.component.html',
  styleUrl: './ca-user-management.component.scss'
})
export class CaUserManagementComponent implements OnInit {
  usersService = inject(UsersService);
  certificateService = inject(CertificatesService);
  toast = inject(ToastrService);
  dialog = inject(MatDialog);

  loading = true;
  caUsers: CaUser[] = [];
  allSigningCertificates: Certificate[] = [];
  caUsersDataSource = new MatTableDataSource<CaUser>();

  displayedColumns: string[] = [
    'name',
    'surname',
    'organization',
    'email',
    'actions'
  ];

  ngOnInit() {
    this.usersService.getAllCaUsers().subscribe({
      next: valueUsers => {
        this.caUsers = valueUsers;
        this.caUsersDataSource.data = this.caUsers;

        this.certificateService.getValidSigningCertificates().subscribe({
          next: valueCerts => {
            this.allSigningCertificates = valueCerts;
            this.loading = false;
          },
          error: err => {
            this.toast.error("Error", "Unable to certificates: " + err);
          }
        })
      },
      error: err => {
        this.toast.error("Error", "Unable to load CA users: " + err);
      }
    });
  }

  openRegisterDialog() {
    const dialogRef: MatDialogRef<CaRegistrationDialogComponent, CaUser | undefined | null> = this.dialog.open(CaRegistrationDialogComponent, {
      width: '30rem',
      data: { allSigningCertificates: this.allSigningCertificates }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result === null || result === undefined) {
        return;
      }

      this.caUsers.push(result);
      this.caUsersDataSource.data = this.caUsers;
    })
  }

  openAssignNewCertificate(caUser: CaUser) {
    this.loading = true;

    this.certificateService.getSigningCertificatesThatCaDoesntHave(caUser.id).subscribe({
      next: value => {
        this.requestNewCaCertificateFromPool(value, caUser);
        this.loading = false;
      },
      error: err => {
        this.toast.error("Error", "Unable to load CA users: " + err);
      }
    })
  }

  requestNewCaCertificateFromPool(availableCertificates: Certificate[], caUser: CaUser) {
    availableCertificates.sort((a, b) => a.prettySerialNumber.localeCompare(b.prettySerialNumber));

    const dialogRef: MatDialogRef<CaAddCertificateDialogComponent, Certificate | null> = this.dialog.open(CaAddCertificateDialogComponent, {
      width: '30rem',
      data: { availableCertificates: availableCertificates }
    });

    dialogRef.afterClosed().subscribe(chosenCertificate => {
      if (chosenCertificate === null || chosenCertificate === undefined) {
        return;
      }

      this.assignNewCaCertificate(chosenCertificate, caUser);
    })
  }

  assignNewCaCertificate(certificate: Certificate, caUser: CaUser) {
    this.loading = true;

    const newCertToCa: AddCertificateToCaUser = {
      caUserId: caUser.id,
      newCertificateSerialNumber: certificate.serialNumber
    };

    this.certificateService.addNewCertificateToCaUser(newCertToCa).subscribe({
      next: () => {
        this.toast.success("Successful", "You successfully added a new certificate to a user");
        this.loading = false;
      },
      error: err => {
        this.toast.error("Error", "Unable to add certificate to a user: " + err);
      }
    });
  }
}
