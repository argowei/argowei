import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { Device } from '../../core/models';
import { device, group } from '../../testing';
import { DeviceDetail, diff } from './device-detail';

const sleep = (ms = 5) => new Promise((resolve) => setTimeout(resolve, ms));

const stored = device({
  id: 7,
  name: 'aa:bb:cc:00:00:07',
  label: 'Printer',
  notes: 'Hallway',
  trust_level: 'normal',
  group_id: 4,
  group: { id: 4, name: 'IoT' },
  vendor: 'Brother Industries',
  addresses: [
    { id: 1, device_id: 7, ip_address: '192.168.1.20', protocol: 'V4', source: 'Arp',
      first_seen: '2026-01-01T10:00:00Z', last_seen: '2026-01-01T12:00:00Z' },
  ],
});
const groups = [group(4, 'IoT'), group(5, 'Guest')];

describe('diff', () => {
  const form = { label: 'Printer', group: 4, trust: 'normal' as const, notes: 'Hallway' };

  it('is empty when nothing changed, ignoring surrounding whitespace', () => {
    expect(diff(stored, form)).toEqual({});
    expect(diff(stored, { ...form, label: '  Printer ', notes: ' Hallway\n' })).toEqual({});
  });

  it('contains only the fields that changed', () => {
    expect(diff(stored, { ...form, trust: 'trusted' })).toEqual({ trust_level: 'trusted' });
    expect(diff(stored, { ...form, group: 5, notes: 'New' })).toEqual({ group_id: 5, notes: 'New' });
  });

  it('turns a blank label and "no group" into null', () => {
    expect(diff(stored, { ...form, label: '  ' })).toEqual({ label: null });
    expect(diff(stored, { ...form, group: null })).toEqual({ group_id: null });
  });
});

describe('DeviceDetail', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  async function render(id = '7', response: Device | 'missing' = stored): Promise<{ fixture: ComponentFixture<DeviceDetail>; el: HTMLElement }> {
    const fixture = TestBed.createComponent(DeviceDetail);
    fixture.componentRef.setInput('id', id);
    fixture.detectChanges();
    await sleep();

    const deviceRequest = http.expectOne(`/api/devices/${id}`);
    // Answer groups first: forkJoin cancels the other request once one fails.
    http.expectOne('/api/groups').flush(groups);
    if (response === 'missing') {
      deviceRequest.flush({ error: 'no such device' }, { status: 404, statusText: 'Not Found' });
    } else {
      deviceRequest.flush(response);
    }
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  function edit(r: { fixture: ComponentFixture<DeviceDetail>; el: HTMLElement }, selector: string, value: string): void {
    const field = r.el.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
    field.value = value;
    field.dispatchEvent(new Event('input'));
    r.fixture.detectChanges();
  }

  const saveButton = (el: HTMLElement) => el.querySelector<HTMLButtonElement>('button[type=submit]')!;

  it('shows the device profile and addresses', async () => {
    const { el } = await render();

    expect(el.querySelector('h1')!.textContent).toContain('Printer');
    expect(el.textContent).toContain('aa:bb:cc:00:00:07');
    expect(el.textContent).toContain('Brother Industries');
    expect(el.textContent).toContain('192.168.1.20');
    expect(el.querySelector<HTMLInputElement>('#label')!.value).toBe('Printer');
    expect(el.querySelector<HTMLTextAreaElement>('#notes')!.value).toBe('Hallway');
  });

  it('offers tabs for features that are still to come, disabled', async () => {
    const { el } = await render();
    const tabs = Array.from(el.querySelectorAll<HTMLButtonElement>('[role=tab]'));

    expect(tabs.map((t) => t.textContent?.trim())).toEqual(['Overview', 'Scans', 'DNS', 'CVEs', 'Policy']);
    expect(tabs[0].getAttribute('aria-selected')).toBe('true');
    expect(tabs.slice(1).every((t) => t.disabled)).toBe(true);
  });

  it('keeps Save disabled until something changes', async () => {
    const r = await render();
    expect(saveButton(r.el).disabled).toBe(true);

    edit(r, '#label', 'Office printer');
    expect(saveButton(r.el).disabled).toBe(false);

    r.el.querySelector<HTMLButtonElement>('button.secondary')!.click();
    r.fixture.detectChanges();
    await r.fixture.whenStable(); // ngModel writes values back asynchronously
    r.fixture.detectChanges();
    expect(saveButton(r.el).disabled).toBe(true);
    expect(r.el.querySelector<HTMLInputElement>('#label')!.value).toBe('Printer');
  });

  it('sends only the changed fields and shows the saved result', async () => {
    const r = await render();

    edit(r, '#label', 'Office printer');
    saveButton(r.el).click();
    r.fixture.detectChanges();

    const request = http.expectOne('/api/devices/7');
    expect(request.request.method).toBe('PATCH');
    expect(request.request.body).toEqual({ label: 'Office printer' });
    request.flush({ ...stored, label: 'Office printer', display_name: 'Office printer' });
    r.fixture.detectChanges();

    expect(r.el.querySelector('h1')!.textContent).toContain('Office printer');
    expect(r.el.querySelector('[role=status]')!.textContent).toContain('Saved');
    expect(saveButton(r.el).disabled).toBe(true);
  });

  it('clears a label by sending null', async () => {
    const r = await render();

    edit(r, '#label', '');
    saveButton(r.el).click();

    expect(http.expectOne('/api/devices/7').request.body).toEqual({ label: null });
  });

  it('shows the server message when a save is rejected and keeps the edits', async () => {
    const r = await render();

    edit(r, '#notes', 'x');
    saveButton(r.el).click();
    http.expectOne('/api/devices/7').flush({ error: 'notes must not contain control characters' }, { status: 400, statusText: 'Bad Request' });
    r.fixture.detectChanges();

    expect(r.el.querySelector('[role=alert]')!.textContent).toContain('control characters');
    expect(r.el.querySelector<HTMLTextAreaElement>('#notes')!.value).toBe('x');
    expect(saveButton(r.el).disabled).toBe(false);
  });

  it('says so when the device does not exist', async () => {
    const { el } = await render('99', 'missing');

    expect(el.querySelector('[role=alert]')!.textContent).toContain('no longer exists');
    expect(el.querySelector('form')).toBeNull();
  });
});
