import { Injectable } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ToastComponent, ToastType } from './toastr.component';

@Injectable({ providedIn: 'root' })
export class ToastrService {
  constructor(private snack: MatSnackBar) {}

  private open(type: ToastType, title: string, message: string, duration = 3500) {
    this.snack.openFromComponent(ToastComponent, {
      data: { type, title, message },
      duration,
      horizontalPosition: 'right',
      verticalPosition: 'bottom',
      panelClass: ['app-toast'],
    });
  }

  success(title: string, message: string, duration?: number) {
    this.open('success', title, message, duration ?? 3000);
  }
  info(title: string, message: string, duration?: number) {
    this.open('info', title, message, duration ?? 3500);
  }
  error(title: string, message: string, duration?: number) {
    this.open('error', title, message, duration ?? 5000);
  }
}
