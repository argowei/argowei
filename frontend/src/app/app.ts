import { Component, computed, inject } from '@angular/core';
import { Router, RouterOutlet } from '@angular/router';

import { AuthService } from './core/auth.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  template: `
    @if (username(); as name) {
      <header>
        <span class="user">{{ name }}</span>
        <button type="button" class="secondary" (click)="logout()">Sign out</button>
      </header>
    }
    <main>
      <router-outlet />
    </main>
  `,
  styles: `
    header {
      position: fixed;
      top: 0;
      right: 0;
      display: flex;
      align-items: center;
      gap: 0.8rem;
      padding: 0.8rem 1.2rem;
      color: #aebdcc;
    }

    main {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 4rem 2rem 2rem;
    }
  `,
})
export class App {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly username = computed(() => {
    const session = this.auth.session();
    return session?.kind === 'authenticated' ? session.username : null;
  });

  protected logout(): void {
    const leave = () => void this.router.navigate(['/login']);
    // The session is gone either way; a failed request must not trap the user.
    this.auth.logout().subscribe({
      next: leave,
      error: () => {
        this.auth.markExpired();
        leave();
      },
    });
  }
}
