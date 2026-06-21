import { HttpClient } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';

interface HealthResponse {
  status: string;
}

@Component({
  selector: 'app-root',
  imports: [],
  template: `
    <main>
      <section>
        <p class="eyebrow">Network intelligence</p>
        <h1>Argowei</h1>
        <p>Make your network visible, understandable, and manageable.</p>
        <div class="status">
          <span [class.online]="backendStatus() === 'connected'"></span>
          Backend: {{ backendStatus() }}
        </div>
      </section>
    </main>
  `,
  styles: `
    main {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 2rem;
    }

    section {
      width: min(34rem, 100%);
      padding: 2.5rem;
      border: 1px solid #263849;
      border-radius: 1rem;
      background: #111d28;
      box-shadow: 0 1.5rem 5rem #0006;
    }

    .eyebrow {
      color: #65d6ad;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }

    h1 {
      margin: 0.5rem 0;
      font-size: clamp(2.5rem, 10vw, 4.5rem);
    }

    .status {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-top: 2rem;
      color: #aebdcc;
    }

    .status span {
      width: 0.65rem;
      height: 0.65rem;
      border-radius: 50%;
      background: #ef6a6a;
    }

    .status span.online {
      background: #65d6ad;
      box-shadow: 0 0 0.8rem #65d6ad88;
    }
  `,
})
export class App {
  private readonly http = inject(HttpClient);
  protected readonly backendStatus = signal('checking…');

  constructor() {
    this.http.get<HealthResponse>('/api/health').subscribe({
      next: ({ status }) =>
        this.backendStatus.set(status === 'ok' ? 'connected' : 'unknown'),
      error: () => this.backendStatus.set('unavailable'),
    });
  }
}
