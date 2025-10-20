import {Component, OnInit, inject} from '@angular/core';
import {Router, ActivatedRoute} from '@angular/router';
import { ToastrService } from '../../helpers/toastr/toastr.service';
import { AuthService } from '../../../services/auth/auth.service';

@Component({
  selector: 'app-email-confirmation',
  template: '',
  standalone: true
})
export class EmailConfirmationComponent implements OnInit {
  router = inject(Router);
  route = inject(ActivatedRoute);
  toastr = inject(ToastrService);
  authService = inject(AuthService);

  ngOnInit(): void {
    const token = this.route.snapshot.queryParamMap.get('token');

    this.router.navigate(['/']).then(() => {
      if (token) {
        this.authService.confirmEmail(token).subscribe({
          next: () => {
            this.toastr.success('Success', 'Email confirmed successfully');
          },
          error: (err) => {
            this.toastr.error('Unable to confirm the email', `Error: ${err.error.error}`);
          }
        });
      } else {
        this.toastr.error('Error', 'Invalid confirmation token');
      }
    });
  }
}
