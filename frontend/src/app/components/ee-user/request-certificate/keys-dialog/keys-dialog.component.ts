import {Component, inject} from '@angular/core';
import {MatFormField, MatLabel} from '@angular/material/form-field';
import {MatIconButton} from '@angular/material/button';
import {MAT_DIALOG_DATA, MatDialogRef} from '@angular/material/dialog';
import {CdkCopyToClipboard} from '@angular/cdk/clipboard';
import {MatInput} from '@angular/material/input';
import {KeyPair} from '../../../../models/KeyPair';
import {ToastrService} from '../../../common/toastr/toastr.service';

@Component({
  selector: 'app-keys-dialog',
  standalone: true,
  imports: [
    MatFormField,
    MatIconButton,
    CdkCopyToClipboard,
    MatLabel,
    MatInput
  ],
  templateUrl: './keys-dialog.component.html',
  styleUrl: './keys-dialog.component.scss'
})
export class KeysDialogComponent {
  dialogRef = inject(MatDialogRef<KeysDialogComponent, null>);
  keys = inject<KeyPair>(MAT_DIALOG_DATA);
  toastr = inject(ToastrService);

  onNoClick() {
    this.dialogRef.close();
  }

  onCopied(type: string) {
    this.toastr.success('Success', type + ' key copied to clipboard');
  }
}
