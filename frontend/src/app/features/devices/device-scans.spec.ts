import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Scan, ScanWithPorts } from '../../core/scan.models';
import { SCAN_POLL_MS } from '../../core/scans.service';
import { providePageTesting, sleep } from '../../testing';
import { DeviceScans } from './device-scans';

function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: 1,
    device_id: 7,
    target_ip: '192.168.1.20',
    profile: 'quick',
    status: 'completed',
    requested_by: 'admin',
    schedule_id: null,
    created_at: new Date(Date.now() - 120_000).toISOString(),
    started_at: new Date(Date.now() - 110_000).toISOString(),
    finished_at: new Date(Date.now() - 100_000).toISOString(),
    error: null,
    nmap_version: '7.993',
    open_ports: 1,
    ...overrides,
  };
}

function withPorts(base: Scan): ScanWithPorts {
  return {
    ...base,
    ports: [
      {
        protocol: 'tcp',
        port: 631,
        state: 'closed',
        reason: 'conn-refused',
        service: null,
        product: null,
        version: null,
        extra_info: null,
      },
      {
        protocol: 'tcp',
        port: 80,
        state: 'open',
        reason: 'syn-ack',
        service: 'http',
        product: 'SimpleHTTPServer',
        version: '0.6',
        extra_info: 'Python 3.14',
      },
    ],
  };
}

describe('DeviceScans', () => {
  let http: HttpTestingController;

  function setup(pollMs = 0): void {
    TestBed.configureTestingModule({
      providers: [...providePageTesting(), { provide: SCAN_POLL_MS, useValue: pollMs }],
    });
    http = TestBed.inject(HttpTestingController);
  }

  afterEach(() => {
    http.verify();
    vi.useRealTimers();
  });

  const settle = () => (vi.isFakeTimers() ? vi.advanceTimersByTimeAsync(5) : sleep());

  async function render(
    history: Scan[],
  ): Promise<{ fixture: ComponentFixture<DeviceScans>; el: HTMLElement }> {
    const fixture = TestBed.createComponent(DeviceScans);
    fixture.componentRef.setInput('deviceId', 7);
    fixture.detectChanges();
    await settle();
    http.expectOne('/api/devices/7/scans').flush(history);
    if (history.length) http.expectOne(`/api/scans/${history[0].id}`).flush(withPorts(history[0]));
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('shows the newest scan with open ports first', async () => {
    setup();
    const { el } = await render([scan()]);

    const rows = [...el.querySelectorAll('table.ports tbody tr')].map((r) =>
      [...r.querySelectorAll('td')].map((td) => td.textContent?.trim()),
    );
    expect(rows[0]).toEqual(['80/tcp', 'open', 'http: SimpleHTTPServer 0.6 (Python 3.14)']);
    expect(rows[1]).toEqual(['631/tcp', 'closed', '—']);
    expect(el.querySelector('.result h2')?.textContent).toContain('192.168.1.20 (quick)');
  });

  it('compares a completed scan with the previous one', async () => {
    setup();
    const newer = scan({ id: 2 });
    const older = scan({ id: 1, profile: 'full' });
    const { fixture, el } = await render([newer, older]);

    const request = http.expectOne('/api/scans/2/diff?against=1');
    request.flush({
      older,
      newer,
      diff: {
        opened: [
          {
            protocol: 'tcp',
            port: 80,
            service: { service: 'http', product: 'nginx', version: '1.27' },
          },
        ],
        closed: [
          { protocol: 'tcp', port: 631, service: { service: 'ipp', product: null, version: null } },
        ],
        changed: [],
        unchanged: 1,
        not_comparable: [
          { protocol: 'tcp', port: 8443, service: { service: null, product: null, version: null } },
        ],
        profile_mismatch: true,
        address_changed: null,
      },
    });
    fixture.detectChanges();

    const items = [...el.querySelectorAll('.changes li')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(items).toEqual(['Opened 80/tcp — http: nginx 1.27', 'Closed 631/tcp — ipp']);
    expect(el.querySelector('.banner.info')?.textContent).toContain('different profiles');
    const text = el.textContent?.replace(/\s+/g, ' ') ?? '';
    expect(text).toContain('Not comparable (only one scan looked): 8443/tcp');
    expect(text).toContain('1 other open port(s) unchanged.');
  });

  it('starts a scan with the chosen profile', async () => {
    setup();
    const { fixture, el } = await render([]);
    expect(el.textContent).toContain('not been scanned yet');

    const select = el.querySelector<HTMLSelectElement>('#scan-profile')!;
    select.value = 'service';
    select.dispatchEvent(new Event('change'));
    (el.querySelector('form.start button') as HTMLButtonElement).click();

    const request = http.expectOne('/api/devices/7/scans');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ profile: 'service' });
    const queued = scan({
      id: 2,
      status: 'queued',
      profile: 'service',
      open_ports: 0,
      finished_at: null,
    });
    request.flush(queued);
    http.expectOne('/api/scans/2').flush({ ...queued, ports: [] });
    fixture.detectChanges();

    expect(el.querySelector('[role=status]')?.textContent).toContain('Waiting for a free slot');
    expect((el.querySelector('form.start button') as HTMLButtonElement).disabled).toBe(true);
  });

  it('shows why a scan was refused', async () => {
    setup();
    const { fixture, el } = await render([]);
    (el.querySelector('form.start button') as HTMLButtonElement).click();
    http.expectOne('/api/devices/7/scans').flush(
      {
        error:
          '8.8.8.8 is not on the local network; only private and link-local addresses can be scanned',
      },
      { status: 422, statusText: 'Unprocessable Entity' },
    );
    fixture.detectChanges();
    expect(el.querySelector('.error[role=alert]')?.textContent).toContain(
      'not on the local network',
    );
  });

  it('follows a running scan until it completes, then stops polling', async () => {
    vi.useFakeTimers();
    setup(1000);
    const running = scan({ status: 'running', open_ports: 0, finished_at: null });
    const { fixture, el } = await render([running]);
    expect(el.textContent).toContain('Scanning…');

    await vi.advanceTimersByTimeAsync(1000);
    http.expectOne('/api/devices/7/scans').flush([scan()]);
    http.expectOne('/api/scans/1').flush(withPorts(scan()));
    fixture.detectChanges();
    expect(el.querySelector('table.ports')).not.toBeNull();

    await vi.advanceTimersByTimeAsync(3000);
    http.expectNone('/api/devices/7/scans'); // nothing in progress any more
    fixture.destroy();
  });

  it('compares a scan with the previous one as soon as it finishes', async () => {
    vi.useFakeTimers();
    setup(1000);
    const older = scan({ id: 1 });
    const running = scan({ id: 2, status: 'running', open_ports: 0, finished_at: null });
    const { fixture } = await render([running, older]);

    await vi.advanceTimersByTimeAsync(1000);
    const done = scan({ id: 2 });
    http.expectOne('/api/devices/7/scans').flush([done, older]);
    http.expectOne('/api/scans/2').flush(withPorts(done));
    fixture.detectChanges();

    http.expectOne('/api/scans/2/diff?against=1');
    fixture.destroy();
  });

  it('shows the real result when a scan finished before the cancel arrived', async () => {
    setup();
    const running = scan({ status: 'running', open_ports: 0, finished_at: null });
    const { fixture, el } = await render([running]);

    [...el.querySelectorAll<HTMLButtonElement>('td.actions button')]
      .find((b) => b.textContent?.trim() === 'Cancel')!
      .click();
    http
      .expectOne('/api/scans/1/cancel')
      .flush(
        { error: 'the scan is no longer queued or running' },
        { status: 409, statusText: 'Conflict' },
      );
    http.expectOne('/api/devices/7/scans').flush([scan()]);
    http.expectOne('/api/scans/1').flush(withPorts(scan()));
    fixture.detectChanges();

    expect(el.querySelector('.error[role=alert]')?.textContent).toContain(
      'no longer queued or running',
    );
    expect(el.querySelector('table.ports')).not.toBeNull();
  });

  it('cancels a running scan', async () => {
    setup();
    const running = scan({ status: 'running', open_ports: 0, finished_at: null });
    const { fixture, el } = await render([running]);

    const cancel = [...el.querySelectorAll<HTMLButtonElement>('td.actions button')].find(
      (b) => b.textContent?.trim() === 'Cancel',
    )!;
    cancel.click();
    const cancelled = scan({ status: 'cancelled', error: 'cancelled by admin', open_ports: 0 });
    const request = http.expectOne('/api/scans/1/cancel');
    expect(request.request.method).toBe('POST');
    request.flush(cancelled);
    http.expectOne('/api/scans/1').flush({ ...cancelled, ports: [] });
    fixture.detectChanges();

    expect(el.querySelector('.result .error')?.textContent).toContain(
      'cancelled: cancelled by admin',
    );
  });
});
