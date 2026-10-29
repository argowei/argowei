import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService, describeAuthError } from '../../core/auth.service';
import { safeReturnUrl } from '../../core/auth.guard';

@Component({
  host: { class: 'centered' },
  selector: 'app-login',
  imports: [FormsModule],
  template: `
    <form class="card" (ngSubmit)="submit()">
      <p class="eyebrow">Argowei</p>
      <h1>Sign in</h1>

      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required
             [(ngModel)]="username" />

      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required [(ngModel)]="password" />

      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }

      <button type="submit" [disabled]="busy() || !username() || !password()">
        {{ busy() ? 'Signing in…' : 'Sign in' }}
      </button>
    </form>
  `,
})
export class Login {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly username = signal('');
  protected readonly password = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected submit(): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);

    this.auth.login(this.username(), this.password()).subscribe({
      next: () => {
        const target = safeReturnUrl(this.route.snapshot.queryParamMap.get('returnUrl'));
        void this.router.navigateByUrl(target);
      },
      error: (error) => {
        this.password.set('');
        this.error.set(describeAuthError(error));
        this.busy.set(false);
      },
    });
  }
}
