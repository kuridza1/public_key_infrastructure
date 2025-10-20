import {Component, inject, OnInit} from '@angular/core';
import {NgClass, NgFor, NgIf, NgOptimizedImage} from '@angular/common';
import {Router, RouterLink, RouterLinkActive} from '@angular/router';
import {Role} from '../../../models/Role';
import {AuthService} from '../../../services/auth/auth.service';

interface NavItem {
  label: string;
  icon: string;
  link?: string;
  roles: Role[];
  class?: string;
  action?: () => void;
}

@Component({
  selector: 'app-navigation',
  standalone: true,
  imports: [
    NgIf,
    RouterLink,
    RouterLinkActive,
    NgOptimizedImage,
    NgClass,
    NgFor
  ],
  templateUrl: './navigation.component.html',
  styleUrl: './navigation.component.css'
})
export class NavigationComponent implements OnInit {
  private auth = inject(AuthService);
  private router = inject(Router);

  currentUserRole: Role | null = null;
  sidebarItems: NavItem[] = [
    {label: 'Signed certificates', icon: 'library_books', link: '/signed-certificates', roles: ['CaUser']},
    {label: 'Certificate requests', icon: 'stacks', link: '/certificate-requests', roles: ['CaUser']},
    {label: 'All certificates', icon: 'library_books', link: '/all-certificates', roles: ['Admin']},
    {label: 'Issue a certificate', icon: 'add_notes', link: '/issue-certificate', roles: ['CaUser', 'Admin']},
    {label: 'My certificates', icon: 'library_books', link: '/my-certificates', roles: ['EeUser']},
    {label: 'My certificates', icon: 'home_storage', link: '/my-certificates', roles: ['CaUser']},
    {label: 'Request Certificate', icon: 'add_notes', link: '/request-certificate', roles: ['EeUser']},
    {label: 'Manage CA users', icon: 'group', link: '/manage-ca-users', roles: ['Admin']},
    {label: 'CRL', icon: 'contract_delete', link: '/crl', roles: ['Admin', 'CaUser', 'EeUser']},
    {label: 'Logout', icon: 'logout', roles: ['EeUser', 'CaUser', 'Admin'], class: 'logout', action: () => this.logout()},
  ];

  ngOnInit() {
    this.currentUserRole = (this.auth.role as Role) ?? null;
    this.auth.role$.subscribe(r => (this.currentUserRole = (r as Role) ?? null));
  }

  logout() {
    this.auth.logout().subscribe({
      complete: () => this.router.navigate(['/login']),
      error: () => this.router.navigate(['/login']),
    });
  }
}
