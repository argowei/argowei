import { HttpClient } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';

interface HealthResponse {
  status: string;
}

@Component({
  selector: 'app-dashboard',
  template: `
    <section class="card">
      <p class="eyebrow">Network intelligence</p>
      <h1>Argowei</h1>
      <p>Make your network visible, understandable, and manageable.</p>
      <div class="status">
        <span [class.online]="backendStatus() === 'connected'"></span>
        Backend: {{ backendStatus() }}
      </div>
    </section>
  `,
  styles: `
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
export class Dashboard {
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
