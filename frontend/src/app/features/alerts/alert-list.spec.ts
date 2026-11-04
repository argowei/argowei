import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, TestRequest, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { ALERT_POLL_MS } from '../../core/alerts.service';
import { Alert, AlertPage, AlertsStatus, SuggestedAction } from '../../core/alerts.models';
import { AlertList } from './alert-list';

const ACTIONS: SuggestedAction[] = [
  { action: 'trust', label: 'Trust', available: true, effect: 'Sets the trust level to trusted.' },
  { action: 'restrict', label: 'Restrict', available: true, effect: 'Sets the trust level to restricted.' },
  { action: 'block', label: 'Block', available: false, reason: 'Needs gateway or router integration, which is not set up yet.' },
  { action: 'quarantine', label: 'Quarantine', available: false, reason: 'Needs gateway or router integration, which is not set up yet.' },
];

function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 5,
    type: 'device.new',
    severity: 'warning',
    status: 'open',
    created_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    device: { id: 12, display_name: '00:80:77:aa:bb:01', mac_address: '00:80:77:aa:bb:01', vendor: 'Brother industries, LTD.' },
    payload: { mac: '00:80:77:aa:bb:01', vendor: 'Brother industries, LTD.', interface: 'eth0', ip: '192.168.1.20', suggested_actions: ACTIONS },
    ...overrides,
  };
}

const page = (items: Alert[], next_before: number | null = null): AlertPage => ({ items, next_before });

const status = (overrides: Partial<AlertsStatus['baseline']> = {}, counts = { open: 1, acknowledged: 0 }): AlertsStatus => ({
  ...counts,
  baseline: { state: 'done', window_secs: 0, ends_at: null, ...overrides },
});

interface Rendered {
  fixture: ComponentFixture<AlertList>;
  http: HttpTestingController;
  el: HTMLElement;
}

describe('AlertList', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: ALERT_POLL_MS, useValue: 0 },
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  const list = (view: string, before?: number) =>
    http.expectOne((r) => r.url === '/api/alerts' && r.params.get('status') === view && r.params.get('before') === (before?.toString() ?? null));

  function render(first: AlertPage | 'error' = page([alert()]), baseline: AlertsStatus = status()): Rendered {
    const fixture = TestBed.createComponent(AlertList);
    fixture.detectChanges();

    const request: TestRequest = list('active');
    if (first === 'error') {
      request.flush({ error: 'boom' }, { status: 503, statusText: 'Unavailable' });
    } else {
      request.flush(first);
    }
    http.expectOne('/api/alerts/status').flush(baseline);
    fixture.detectChanges();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  const buttons = (el: HTMLElement) => Array.from(el.querySelectorAll<HTMLButtonElement>('.alert button'));
  const button = (el: HTMLElement, label: string) => buttons(el).find((b) => b.textContent?.trim() === label)!;

  /** After an action the page reloads the list and the counts. */
  function flushReload(r: Rendered, items: Alert[] = []): void {
    list('active').flush(page(items));
    r.http.expectOne('/api/alerts/status').flush(status({}, { open: items.length, acknowledged: 0 }));
    r.fixture.detectChanges();
  }

  it('shows a loading state until the alerts arrive', () => {
    const fixture = TestBed.createComponent(AlertList);
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('Loading alerts');
    list('active');
    http.expectOne('/api/alerts/status');
  });

  it('shows what appeared, where, and links to the device', () => {
    const { el } = render();

    expect(el.querySelector('h2')!.textContent).toContain('New device');
    const link = el.querySelector<HTMLAnchorElement>('h2 a')!;
    expect(link.getAttribute('href')).toBe('/devices/12');
    expect(link.textContent).toContain('00:80:77:aa:bb:01');
    const meta = el.querySelector('.meta')!.textContent;
    expect(meta).toContain('Brother industries, LTD.');
    expect(meta).toContain('192.168.1.20 on eth0');
    expect(meta).toContain('5 min ago');
    expect(el.querySelector('.pill.st-open')!.textContent).toContain('open');
  });

  it('offers Trust and Restrict, and disables what needs enforcement with the reason', () => {
    const { el } = render();

    expect(button(el, 'Trust').disabled).toBe(false);
    expect(button(el, 'Restrict').disabled).toBe(false);
    for (const label of ['Block', 'Quarantine']) {
      expect(button(el, label).disabled).toBe(true);
      expect(button(el, label).title).toContain('gateway or router');
    }
  });

  it('does nothing when a disabled action is triggered', () => {
    const r = render();

    button(r.el, 'Block').click();

    // http.verify() in afterEach fails if a request was sent.
    expect(button(r.el, 'Block').disabled).toBe(true);
  });

  it('explains the empty states', () => {
    const active = render(page([]), status({}, { open: 0, acknowledged: 0 }));
    expect(active.el.textContent).toContain('No active alerts');
    expect(active.el.querySelector('.alerts')).toBeNull();
  });

  it('shows an error with a retry that loads again', () => {
    const r = render('error');

    expect(r.el.querySelector('[role=alert]')!.textContent).toContain('server is unavailable');
    r.el.querySelector<HTMLButtonElement>('[role=alert] button')!.click();
    r.fixture.detectChanges();
    list('active').flush(page([alert()]));
    r.fixture.detectChanges();

    expect(r.el.querySelectorAll('.alert')).toHaveLength(1);
  });

  describe('baseline', () => {
    it('says so while no scan has finished yet', () => {
      const { el } = render(page([]), status({ state: 'pending' }, { open: 0, acknowledged: 0 }));

      const banner = el.querySelector('.banner.info')!;
      expect(banner.getAttribute('role')).toBe('status');
      expect(banner.textContent).toContain('Baseline pending');
      expect(banner.textContent).toContain('first scan');
    });

    it('says so while the network is being learned, and until when', () => {
      const ends = new Date(Date.now() + 3_600_000).toISOString();
      const { el } = render(page([]), status({ state: 'learning', window_secs: 7200, ends_at: ends }, { open: 0, acknowledged: 0 }));

      const banner = el.querySelector('.banner.info')!;
      expect(banner.textContent).toContain('Learning your network');
      expect(banner.textContent).toContain(new Date(ends).toLocaleString());
    });

    it('shows nothing once the baseline is over', () => {
      const { el } = render();

      expect(el.querySelector('.banner.info')).toBeNull();
    });
  });

  describe('actions', () => {
    it('acknowledges an alert and reloads', () => {
      const r = render();

      button(r.el, 'Acknowledge').click();
      const request = r.http.expectOne('/api/alerts/5/acknowledge');
      expect(request.request.method).toBe('POST');
      request.flush(alert({ status: 'acknowledged', acknowledged_by: 'admin' }));
      flushReload(r, [alert({ status: 'acknowledged', acknowledged_by: 'admin' })]);

      expect(r.el.querySelector('.pill.st-acknowledged')!.textContent).toContain('acknowledged');
      expect(r.el.querySelector('.meta')!.textContent).toContain('acknowledged by admin');
      expect(buttons(r.el).some((b) => b.textContent?.trim() === 'Acknowledge')).toBe(false);
      expect(buttons(r.el).some((b) => b.textContent?.trim() === 'Resolve')).toBe(true);
    });

    it('resolves an alert, which then leaves the active list', () => {
      const r = render();

      button(r.el, 'Resolve').click();
      r.http.expectOne('/api/alerts/5/resolve').flush(alert({ status: 'resolved' }));
      flushReload(r, []);

      expect(r.el.querySelector('.alert')).toBeNull();
      expect(r.el.textContent).toContain('No active alerts');
    });

    it('trusting classifies the device as trusted and then resolves the alert', () => {
      const r = render();

      button(r.el, 'Trust').click();
      const patch = r.http.expectOne('/api/devices/12');
      expect(patch.request.method).toBe('PATCH');
      expect(patch.request.body).toEqual({ trust_level: 'trusted' });
      patch.flush({});
      r.http.expectOne('/api/alerts/5/resolve').flush(alert({ status: 'resolved' }));
      flushReload(r, []);

      expect(r.el.querySelector('.alert')).toBeNull();
    });

    it('restricting sets the trust level restricted', () => {
      const r = render();

      button(r.el, 'Restrict').click();

      const patch = r.http.expectOne('/api/devices/12');
      expect(patch.request.body).toEqual({ trust_level: 'restricted' });
      patch.flush({});
      r.http.expectOne('/api/alerts/5/resolve');
    });

    it('keeps the alert open and says why when classifying the device fails', () => {
      const r = render();

      button(r.el, 'Trust').click();
      r.http.expectOne('/api/devices/12').flush({ error: 'no such device' }, { status: 404, statusText: 'Not Found' });
      r.fixture.detectChanges();

      expect(r.el.querySelector('.alert .error')!.textContent).toContain('no longer exists');
      expect(r.el.querySelectorAll('.alert')).toHaveLength(1);
      expect(button(r.el, 'Trust').disabled).toBe(false);
    });

    it('disables the buttons of an alert while its request is running', () => {
      const r = render();

      button(r.el, 'Resolve').click();
      r.fixture.detectChanges();

      expect(buttons(r.el).every((b) => b.disabled)).toBe(true);
      r.http.expectOne('/api/alerts/5/resolve');
    });
  });

  describe('views and paging', () => {
    it('switches to resolved alerts, which have no actions', () => {
      const r = render();

      Array.from(r.el.querySelectorAll<HTMLButtonElement>('.view')).find((b) => b.textContent?.includes('Resolved'))!.click();
      r.fixture.detectChanges();
      list('resolved').flush(page([alert({ id: 3, status: 'resolved', resolved_by: 'admin' })]));
      r.fixture.detectChanges();

      expect(r.el.querySelectorAll('.alert')).toHaveLength(1);
      expect(r.el.querySelector('.meta')!.textContent).toContain('resolved by admin');
      expect(buttons(r.el)).toHaveLength(0);
      expect(r.el.querySelector('.view[aria-pressed=true]')!.textContent).toContain('Resolved');
    });

    it('shows the number of active alerts on the Active tab', () => {
      const { el } = render(page([alert()]), status({}, { open: 2, acknowledged: 1 }));

      expect(el.querySelector('.view .count')!.textContent?.trim()).toBe('3');
    });

    it('loads older alerts on request', () => {
      const r = render(page([alert({ id: 9 })], 9));

      r.el.querySelector<HTMLButtonElement>('button.more')!.click();
      list('active', 9).flush(page([alert({ id: 4 })]));
      r.fixture.detectChanges();

      expect(r.el.querySelectorAll('.alert')).toHaveLength(2);
      expect(r.el.querySelector('button.more')).toBeNull();
    });

    it('does not offer more when there is nothing older', () => {
      const { el } = render();

      expect(el.querySelector('button.more')).toBeNull();
    });
  });

  it('describes an alert whose device has since been removed', () => {
    const { el } = render(page([alert({ device: null })]));

    expect(el.querySelector('h2 a')).toBeNull();
    expect(el.querySelector('.meta')!.textContent).toContain('00:80:77:aa:bb:01');
    // Trust needs a device to act on, so clicking it sends nothing
    // (http.verify() in afterEach fails on any unexpected request).
    button(el, 'Trust').click();
  });
});
