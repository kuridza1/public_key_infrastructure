import {Component} from '@angular/core';
import {RouterOutlet} from '@angular/router';
import { NavigationComponent } from './components/helpers/navigation/navigation.component';
import {NgIf} from '@angular/common';
import { AuthService } from './services/auth/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, NavigationComponent, NgIf],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  constructor(public auth: AuthService) {}
}
