import { HttpTestingController, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EventPage, TimelineEvent } from '../../core/event.models';
import { EVENT_POLL_MS } from '../../core/events.service';
import { device, providePageTesting, sleep } from '../../testing';
import { EventTimeline } from './event-timeline';

let nextId = 100;

function event(overrides: Partial<TimelineEvent> = {}): TimelineEvent {
  const id = overrides.id ?? nextId--;
  return {
    id,
    cursor: `c${id}`,
    occurred_at: new Date(Date.now() - 60_000).toISOString(),
    type: 'device.discovered',
    schema_version: 1,
    severity: 'info',
    device: {
      id: 3,
      display_name: 'printer',
      mac_address: '00:80:77:aa:bb:01',
      vendor: null,
    },
    payload: { ip: '192.168.1.20', interface: 'eth0', baseline: false },
    ...overrides,
  };
}

const page = (
  items: TimelineEvent[],
  next_before: string | null = null,
  truncated = false,
): EventPage => ({
  items,
  next_before,
  truncated,
});

describe('EventTimeline', () => {
  let http: HttpTestingController;

  function setup(pollMs = 0): void {
    TestBed.configureTestingModule({
      providers: [...providePageTesting(), { provide: EVENT_POLL_MS, useValue: pollMs }],
    });
    http = TestBed.inject(HttpTestingController);
  }

  afterEach(() => {
    http.verify();
    vi.useRealTimers();
  });

  /** Lets effects run; advances fake timers when a test uses them. */
  const settle = () => (vi.isFakeTimers() ? vi.advanceTimersByTimeAsync(5) : sleep());

  const listRequest = (check: (params: URLSearchParams) => boolean = () => true): TestRequest =>
    http.expectOne(
      (r) => r.url === '/api/events' && check(new URLSearchParams(r.params.toString())),
    );

  async function render(
    first: EventPage,
  ): Promise<{ fixture: ComponentFixture<EventTimeline>; el: HTMLElement }> {
    const fixture = TestBed.createComponent(EventTimeline);
    fixture.detectChanges();
    await settle();
    http.expectOne('/api/devices').flush([]);
    http
      .expectOne('/api/events/types')
      .flush([{ type: 'device.discovered', schema_version: 1, severity: 'info' }]);
    listRequest().flush(first);
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('shows events newest first with their device and a description', async () => {
    setup();
    const { el } = await render(
      page([
        event({ id: 2 }),
        event({ id: 1, type: 'device.offline', payload: { missed_scans: 3 } }),
      ]),
    );

    const rows = [...el.querySelectorAll('li.event')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(rows[0]).toContain('Discovered');
    expect(rows[0]).toContain('printer: First seen at 192.168.1.20 on eth0.');
    expect(rows[1]).toContain('Marked offline after 3 missed scans.');
    expect(el.querySelector('li.event a')?.getAttribute('href')).toBe('/devices/3');
    expect(el.querySelector('button.more')).toBeNull();
  });

  it('starts filtered to the device from the URL and sends filters to the API', async () => {
    setup();
    const fixture = TestBed.createComponent(EventTimeline);
    fixture.componentRef.setInput('device', '3');
    fixture.detectChanges();
    await settle();
    http.expectOne('/api/devices').flush([device({ id: 3, label: 'Printer' })]);
    http.expectOne('/api/events/types').flush([]);
    listRequest((p) => p.get('device') === '3').flush(page([event()]));
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const select = el.querySelector<HTMLSelectElement>('#ev-severity')!;
    select.value = 'warning';
    select.dispatchEvent(new Event('change'));
    listRequest((p) => p.get('device') === '3' && p.get('severity') === 'warning').flush(page([]));
    fixture.detectChanges();

    expect(el.textContent).toContain('No event matches these filters.');
    (el.querySelector('.state button') as HTMLButtonElement).click();
    listRequest((p) => !p.has('device') && !p.has('severity')).flush(page([]));
  });

  it('turns local datetime filters into UTC timestamps', async () => {
    setup();
    const { fixture, el } = await render(page([]));
    const from = el.querySelector<HTMLInputElement>('#ev-from')!;
    from.value = '2026-01-01T12:00';
    from.dispatchEvent(new Event('change'));
    listRequest((p) => p.get('from') === new Date('2026-01-01T12:00').toISOString()).flush(
      page([]),
    );
    fixture.detectChanges();
  });

  it('loads older pages and appends them', async () => {
    setup();
    const { fixture, el } = await render(page([event({ id: 9 })], 'c9'));

    (el.querySelector('button.more') as HTMLButtonElement).click();
    listRequest((p) => p.get('before') === 'c9').flush(page([event({ id: 8 })]));
    fixture.detectChanges();

    expect(el.querySelectorAll('li.event').length).toBe(2);
    expect(el.querySelector('button.more')).toBeNull();
  });

  it('adds new events on top while the page is open', async () => {
    vi.useFakeTimers();
    setup(1000);
    const { fixture, el } = await render(page([event({ id: 9 })]));

    await vi.advanceTimersByTimeAsync(1000);
    listRequest((p) => p.get('after') === 'c9').flush(page([event({ id: 11 }), event({ id: 10 })]));
    fixture.detectChanges();
    expect(el.querySelectorAll('li.event').length).toBe(3);

    await vi.advanceTimersByTimeAsync(1000);
    listRequest((p) => p.get('after') === 'c11').flush(page([event({ id: 12 })], null, true));
    fixture.detectChanges();
    expect(el.querySelector('.banner.info')?.textContent).toContain('More new events arrived');
    expect(el.querySelectorAll('li.event').length).toBe(3);
    fixture.destroy();
  });

  it('explains an empty timeline and a failed load', async () => {
    setup();
    const { fixture, el } = await render(page([]));
    expect(el.textContent).toContain('Nothing has happened yet.');

    (fixture.componentInstance as unknown as { load(): void }).load();
    listRequest().flush({ error: 'boom' }, { status: 503, statusText: 'Unavailable' });
    fixture.detectChanges();
    expect(el.querySelector('[role=alert]')?.textContent).toContain('The server is unavailable');
  });
});
