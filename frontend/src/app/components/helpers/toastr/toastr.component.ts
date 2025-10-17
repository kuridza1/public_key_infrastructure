import { Component, inject } from '@angular/core';
import { NgClass} from '@angular/common';
import { MAT_SNACK_BAR_DATA } from '@angular/material/snack-bar';

export type ToastType = 'success' | 'info' | 'error';
export type ToastData = { type: ToastType; title: string; message: string };

@Component({
  selector: 'app-toast',
  standalone: true,
  imports: [NgClass],
  template: `
    <div class="toast" [ngClass]="data.type">
      <span class="material-symbols-rounded icon">{{ icon }}</span>
      <div class="content">
        <div class="title">{{ data.title }}</div>
        <div class="message">{{ data.message }}</div>
      </div>
    </div>
  `,
  styles: [`
    .toast { display:flex; align-items:flex-start; gap:.75rem; padding:.75rem 1rem; }
    .icon { font-size:22px; line-height:1; margin-top:2px; }
    .title { font-weight:600; margin-bottom:2px; }
    .message { opacity:.9 }
    .success { color:#0f5132; background:#d1e7dd; border-left:4px solid #0f5132; }
    .info    { color:#084298; background:#cfe2ff; border-left:4px solid #084298; }
    .error   { color:#842029; background:#f8d7da; border-left:4px solid #842029; }
  `],
})
export class ToastComponent {
  data = inject<ToastData>(MAT_SNACK_BAR_DATA);
  icon =
    this.data.type === 'success' ? 'check_circle' :
    this.data.type === 'info'    ? 'info' :
                                   'error';
}
