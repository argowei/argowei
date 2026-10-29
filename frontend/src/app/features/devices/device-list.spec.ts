import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { DEVICE_POLL_MS } from '../../core/devices.service';
import { Device, Group } from '../../core/models';
import { device, group } from '../../testing';
import { DeviceList } from './device-list';

const sleep = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));

const tv = device({ id: 1, label: 'Living room TV', vendor: 'Samsung', trust_level: 'restricted',
  group_id: 4, group: { id: 4, name: 'IoT' }, last_seen: '2026-01-01T11:00:00Z' });
const printer = device({ id: 2, label: 'Office printer', trust_level: 'normal',
  last_seen: '2026-01-01T12:00:00Z' });
const phone = device({ id: 3, label: 'Phone', is_online: false, trust_level: 'suspicious',
  last_seen: '2026-01-01T08:00:00Z' });
const groups: Group[] = [group(1, 'Unassigned'), group(4, 'IoT')];

interface Rendered {
  fixture: ComponentFixture<DeviceList>;
  http: HttpTestingController;
  el: HTMLElement;
}

describe('DeviceList', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: DEVICE_POLL_MS, useValue: 0 },
      ],
    });
  });

  afterEach(() => TestBed.inject(HttpTestingController).verify());

  async function render(devices: Device[] | 'error' = [tv, printer, phone]): Promise<Rendered> {
    const fixture = TestBed.createComponent(DeviceList);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    await sleep();

    const list = http.expectOne('/api/devices');
    // Answer groups first: forkJoin cancels the other request once one fails.
    http.expectOne('/api/groups').flush(groups);
    if (devices === 'error') {
      list.flush({ error: 'boom' }, { status: 503, statusText: 'Unavailable' });
    } else {
      list.flush(devices);
    }
    fixture.detectChanges();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  const names = (el: HTMLElement) =>
    Array.from(el.querySelectorAll('tbody th a')).map((a) => a.textContent?.trim());

  function type(r: Rendered, selector: string, value: string): void {
    const input = r.el.querySelector<HTMLInputElement>(selector)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    r.fixture.detectChanges();
  }

  function choose(r: Rendered, selector: string, value: string): void {
    const select = r.el.querySelector<HTMLSelectElement>(selector)!;
    select.value = value;
    select.dispatchEvent(new Event('change'));
    r.fixture.detectChanges();
  }

  it('shows a loading state until the devices arrive', () => {
    const fixture = TestBed.createComponent(DeviceList);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Loading devices');
  });

  it('lists devices most recently seen first, linking to each detail page', async () => {
    const r = await render();

    expect(names(r.el)).toEqual(['Office printer', 'Living room TV', 'Phone']);
    expect(r.el.querySelector<HTMLAnchorElement>('tbody th a')!.getAttribute('href')).toBe('/devices/2');
    expect(r.el.textContent).toContain('3 of 3');
  });

  it('shows status and trust as text, not just colour', async () => {
    const r = await render();
    const rows = Array.from(r.el.querySelectorAll('tbody tr')).map((row) => row.textContent);

    expect(rows[0]).toContain('Online');
    expect(rows[0]).toContain('normal');
    expect(rows[2]).toContain('Offline');
    expect(rows[2]).toContain('suspicious');
  });

  it('explains an empty installation', async () => {
    const r = await render([]);

    expect(r.el.textContent).toContain('No devices yet');
    expect(r.el.querySelector('table')).toBeNull();
  });

  it('shows an error with a retry button, and retry loads again', async () => {
    const r = await render('error');

    expect(r.el.querySelector('[role=alert]')!.textContent).toContain('server is unavailable');
    r.el.querySelector<HTMLButtonElement>('[role=alert] button')!.click();
    r.fixture.detectChanges();
    await sleep();

    r.http.expectOne('/api/devices').flush([tv]);
    r.http.expectOne('/api/groups').flush(groups);
    r.fixture.detectChanges();
    expect(names(r.el)).toEqual(['Living room TV']);
  });

  it('filters by search text', async () => {
    const r = await render();

    type(r, '#search', 'samsung');
    expect(names(r.el)).toEqual(['Living room TV']);
    expect(r.el.textContent).toContain('1 of 3');

    type(r, '#search', 'office');
    expect(names(r.el)).toEqual(['Office printer']);
  });

  it('filters by status, trust and group', async () => {
    const r = await render();

    choose(r, '#status', 'offline');
    expect(names(r.el)).toEqual(['Phone']);

    choose(r, '#status', 'all');
    choose(r, '#trust', 'restricted');
    expect(names(r.el)).toEqual(['Living room TV']);

    choose(r, '#trust', 'all');
    choose(r, '#group', '4');
    expect(names(r.el)).toEqual(['Living room TV']);

    choose(r, '#group', '1');
    expect(names(r.el)).toEqual(['Office printer', 'Phone']);
  });

  it('says when nothing matches and clears the filters', async () => {
    const r = await render();

    type(r, '#search', 'does not exist');
    expect(r.el.textContent).toContain('No device matches these filters');

    r.el.querySelector<HTMLButtonElement>('.state button')!.click();
    r.fixture.detectChanges();
    expect(names(r.el)).toHaveLength(3);
    expect(r.el.querySelector<HTMLInputElement>('#search')!.value).toBe('');
  });

  it('sorts by a column and toggles the direction, announcing it', async () => {
    const r = await render();
    const header = (label: string) =>
      Array.from(r.el.querySelectorAll<HTMLElement>('thead th')).find((th) => th.textContent?.includes(label))!;

    header('Name').querySelector('button')!.click();
    r.fixture.detectChanges();
    expect(names(r.el)).toEqual(['Living room TV', 'Office printer', 'Phone']);
    expect(header('Name').getAttribute('aria-sort')).toBe('ascending');
    expect(header('Status').getAttribute('aria-sort')).toBe('none');

    header('Name').querySelector('button')!.click();
    r.fixture.detectChanges();
    expect(names(r.el)).toEqual(['Phone', 'Office printer', 'Living room TV']);
    expect(header('Name').getAttribute('aria-sort')).toBe('descending');
  });

  it('keeps showing devices when a refresh fails', async () => {
    const r = await render();

    r.el.querySelector<HTMLButtonElement>('button.sort')!.click();
    // A manual reload that fails must not wipe the table.
    (r.fixture.componentInstance as unknown as { reload(): void }).reload();
    await sleep();
    const failing = r.http.expectOne('/api/devices');
    r.http.expectOne('/api/groups').flush(groups);
    failing.flush({}, { status: 503, statusText: 'Unavailable' });
    r.fixture.detectChanges();

    expect(names(r.el)).toHaveLength(3);
    expect(r.el.querySelector('.banner')!.textContent).toContain('last known data');
  });
});
