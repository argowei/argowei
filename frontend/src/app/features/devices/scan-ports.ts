import { Component, computed, input } from '@angular/core';

import { ScanPort } from '../../core/scan.models';

/** The ports one scan found: open ones first, each with what runs there. */
@Component({
  selector: 'app-scan-ports',
  template: `
    @if (sorted().length) {
      <table class="compact ports">
        <thead>
          <tr>
            <th scope="col">Port</th>
            <th scope="col">State</th>
            <th scope="col">Service</th>
          </tr>
        </thead>
        <tbody>
          @for (port of sorted(); track port.protocol + port.port) {
            <tr [class.open]="port.state === 'open'">
              <td>
                <code>{{ port.port }}/{{ port.protocol }}</code>
              </td>
              <td>{{ port.state }}</td>
              <td>{{ describe(port) }}</td>
            </tr>
          }
        </tbody>
      </table>
    } @else {
      <p class="muted">No port answered; every port nmap tried was closed or filtered.</p>
    }
  `,
  styles: `
    tr.open td:nth-child(2) {
      color: var(--accent);
      font-weight: 600;
    }
    td {
      overflow-wrap: anywhere;
    }
  `,
})
export class ScanPorts {
  readonly ports = input.required<ScanPort[]>();

  protected readonly sorted = computed(() =>
    [...this.ports()].sort(
      (a, b) => Number(b.state === 'open') - Number(a.state === 'open') || a.port - b.port,
    ),
  );

  /** "http: SimpleHTTPServer 0.6 (Python 3.14)", or "—" when nothing is known. */
  protected describe(port: ScanPort): string {
    const software = [port.product, port.version].filter(Boolean).join(' ');
    const extra = port.extra_info ? ` (${port.extra_info})` : '';
    const text = [port.service, software ? software + extra : ''].filter(Boolean).join(': ');
    return text || '—';
  }
}
