import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { AuthService, describeAuthError } from '../../core/auth.service';

const MIN_PASSWORD_LENGTH = 12;

@Component({
  host: { class: 'centered' },
  selector: 'app-setup',
  imports: [FormsModule],
  template: `
    <form class="card" (ngSubmit)="submit()">
      <p class="eyebrow">First start</p>
      <h1>Create admin</h1>
      <p class="hint">
        Paste the setup token from the server log
        (<code>first-run setup token: …</code>).
      </p>

      <label for="token">Setup token</label>
      <input id="token" name="token" autocomplete="off" spellcheck="false" required
             [(ngModel)]="token" />

      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required
             minlength="3" maxlength="64" [(ngModel)]="username" />

      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="new-password" required [(ngModel)]="password"
             aria-describedby="password-hint" />
      <p id="password-hint" class="hint">At least {{ minLength }} characters.</p>

      <label for="confirm">Confirm password</label>
      <input id="confirm" name="confirm" type="password"
             autocomplete="new-password" required [(ngModel)]="confirm" />

      @if (error()) {
        <p class="error" role="alert">{{ error() }}</p>
      }

      <button type="submit" [disabled]="busy() || !valid()">
        {{ busy() ? 'Creating…' : 'Create admin' }}
      </button>
    </form>
  `,
})
export class Setup {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly minLength = MIN_PASSWORD_LENGTH;
  protected readonly token = signal('');
  protected readonly username = signal('');
  protected readonly password = signal('');
  protected readonly confirm = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly valid = computed(
    () =>
      this.token().trim() !== '' &&
      this.username().trim().length >= 3 &&
      this.password().length >= MIN_PASSWORD_LENGTH &&
      this.password() === this.confirm(),
  );

  protected submit(): void {
    if (this.busy() || !this.valid()) return;
    this.busy.set(true);
    this.error.set(null);

    this.auth
      .setup(this.token().trim(), this.username().trim(), this.password())
      .subscribe({
        next: () => void this.router.navigateByUrl('/'),
        error: (error) => {
          this.error.set(describeAuthError(error));
          this.busy.set(false);
        },
      });
  }
}
