import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Device } from '../../core/device.models';
import { device, group, providePageTesting, sleep } from '../../testing';
import { DeviceDetail, diff } from './device-detail';
import { SCAN_POLL_MS } from '../../core/scans.service';

const stored = device({
  id: 7,
  name: 'aa:bb:cc:00:00:07',
  label: 'Printer',
  notes: 'Hallway',
  trust_level: 'normal',
  device_type: 'printer',
  inferred: {
    device_type: 'printer',
    confidence: 70,
    evidence: [{ kind: 'vendor', detail: 'Brother Industries', type: 'printer', weight: 70 }],
  },
  group_id: 4,
  group: { id: 4, name: 'IoT' },
  vendor: 'Brother Industries',
  addresses: [
    {
      id: 1,
      device_id: 7,
      ip_address: '192.168.1.20',
      protocol: 'V4',
      source: 'Arp',
      first_seen: '2026-01-01T10:00:00Z',
      last_seen: '2026-01-01T12:00:00Z',
    },
  ],
});
const groups = [group(1, 'Unassigned'), group(4, 'IoT'), group(5, 'Guest')];

describe('diff', () => {
  const form = {
    label: 'Printer',
    group: 4,
    trust: 'normal' as const,
    type: null,
    notes: 'Hallway',
  };

  it('is empty when nothing changed, ignoring surrounding whitespace', () => {
    expect(diff(stored, form)).toEqual({});
    expect(diff(stored, { ...form, label: '  Printer ', notes: ' Hallway\n' })).toEqual({});
  });

  it('contains only the fields that changed', () => {
    expect(diff(stored, { ...form, trust: 'trusted' })).toEqual({ trust_level: 'trusted' });
    expect(diff(stored, { ...form, group: 5, notes: 'New' })).toEqual({
      group_id: 5,
      notes: 'New',
    });
  });

  it('turns a blank label into null', () => {
    expect(diff(stored, { ...form, label: '  ' })).toEqual({ label: null });
  });

  it('sets the type override, and removes it with null for automatic', () => {
    expect(diff(stored, { ...form, type: 'server' })).toEqual({ type_override: 'server' });

    const overridden = { ...stored, type_override: 'server' as const };
    expect(diff(overridden, { ...form, type: 'server' })).toEqual({});
    expect(diff(overridden, { ...form, type: null })).toEqual({ type_override: null });
    expect(diff(overridden, { ...form, type: 'unknown' })).toEqual({ type_override: 'unknown' });
  });

  it('moves a device back to Unassigned by its id, never with null', () => {
    expect(diff(stored, { ...form, group: 1 })).toEqual({ group_id: 1 });
  });
});

describe('DeviceDetail', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [...providePageTesting(), { provide: SCAN_POLL_MS, useValue: 0 }],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  async function render(
    id = '7',
    response: Device | 'missing' = stored,
  ): Promise<{ fixture: ComponentFixture<DeviceDetail>; el: HTMLElement }> {
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

  function edit(
    r: { fixture: ComponentFixture<DeviceDetail>; el: HTMLElement },
    selector: string,
    value: string,
  ): void {
    const field = r.el.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
    field.value = value;
    field.dispatchEvent(new Event('input'));
    r.fixture.detectChanges();
  }

  const saveButton = (el: HTMLElement) =>
    el.querySelector<HTMLButtonElement>('button[type=submit]')!;

  it('lists what each source called the device and marks the one in use', async () => {
    const named = device({
      ...stored,
      name: 'annas-iphone',
      name_source: 'dhcp',
      label: null,
      display_name: 'annas-iphone',
      names: [
        { source: 'dhcp', name: 'annas-iphone', last_seen: '2026-01-01T12:00:00Z' },
        { source: 'mdns', name: "Anna's iPhone", last_seen: '2026-01-01T11:00:00Z' },
        { source: 'rdns', name: 'iPhone', last_seen: '2026-01-01T10:00:00Z' },
      ],
    });
    const { el } = await render('7', named);

    const rows = Array.from(el.querySelectorAll('table.names tbody tr')).map((r) =>
      r.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(rows[0]).toContain('DHCP lease');
    expect(rows[0]).toContain('annas-iphone');
    expect(rows[0]).toContain('shown');
    expect(rows[1]).toContain('mDNS');
    expect(rows[1]).toContain("Anna's iPhone");
    expect(rows[1]).not.toContain('shown');
    expect(rows[2]).toContain('Reverse DNS');
    expect(el.textContent).toContain('DHCP beats mDNS');
  });

  it('says which source the discovered name comes from next to the label', async () => {
    const { el } = await render('7', device({ ...stored, name: 'iPhone', name_source: 'mdns' }));

    expect(el.querySelector('#label ~ .hint')!.textContent).toContain(
      'discovered name (iPhone, from mDNS)',
    );
  });

  it('does not claim a source while the name is still the MAC address', async () => {
    const { el } = await render();

    expect(el.querySelector('#label ~ .hint')!.textContent).toContain(
      'discovered name (aa:bb:cc:00:00:07)',
    );
    expect(el.querySelector('table.names')).toBeNull();
    expect(el.textContent).toContain('No name learned yet');
  });

  it('shows the label as the winner over every discovered name', async () => {
    const named = device({
      ...stored,
      name: 'iPhone',
      name_source: 'rdns',
      names: [{ source: 'rdns', name: 'iPhone', last_seen: '2026-01-01T10:00:00Z' }],
    });
    const { el } = await render('7', named);

    expect(el.textContent).toContain('Your label "Printer" is shown instead of all of them.');
  });

  it('shows the device profile and addresses', async () => {
    const { el } = await render();

    expect(el.querySelector('h1')!.textContent).toContain('Printer');
    expect(el.textContent).toContain('aa:bb:cc:00:00:07');
    expect(el.textContent).toContain('Brother Industries');
    expect(el.textContent).toContain('192.168.1.20');
    expect(el.querySelector<HTMLInputElement>('#label')!.value).toBe('Printer');
    expect(el.querySelector<HTMLTextAreaElement>('#notes')!.value).toBe('Hallway');
  });

  it('explains the automatic type and offers an override', async () => {
    const { el } = await render();
    const options = Array.from(el.querySelectorAll<HTMLOptionElement>('#type option')).map((o) =>
      o.textContent?.trim(),
    );

    expect(options[0]).toBe('Automatic (Printer, 70 %)');
    expect(options).toContain('Router');
    expect(el.querySelector<HTMLSelectElement>('#type')!.selectedOptions[0].textContent).toContain(
      'Automatic',
    );
    expect(el.textContent).toContain('70 % sure');
    const why = el.querySelector('.evidence')!.textContent;
    expect(why).toContain('Manufacturer');
    expect(why).toContain('Brother Industries');
    expect(why).toContain('+70 %');
  });

  it('says so when there is nothing to base a type on', async () => {
    const { el } = await render(
      '7',
      device({
        ...stored,
        device_type: 'unknown',
        inferred: { device_type: 'unknown', confidence: 0, evidence: [] },
      }),
    );

    expect(el.querySelector('.evidence')).toBeNull();
    expect(el.textContent).toContain('Nothing recognisable yet');
    expect(el.querySelector('#type option')!.textContent?.trim()).toBe('Automatic (unknown)');
  });

  it('sends the override when a type is picked and shows who set it', async () => {
    const r = await render();

    const select = r.el.querySelector<HTMLSelectElement>('#type')!;
    select.selectedIndex = Array.from(select.options).findIndex(
      (o) => o.textContent?.trim() === 'Server',
    );
    select.dispatchEvent(new Event('change'));
    r.fixture.detectChanges();
    saveButton(r.el).click();

    const request = http.expectOne('/api/devices/7');
    expect(request.request.body).toEqual({ type_override: 'server' });
    request.flush({
      ...stored,
      type_override: 'server',
      device_type: 'server',
      type_source: 'manual',
    });
    r.fixture.detectChanges();

    expect(r.el.textContent).toContain('set by you');
  });

  it('offers Unassigned as an ordinary group and has no "no group" option', async () => {
    const { el } = await render();
    const options = Array.from(el.querySelectorAll<HTMLOptionElement>('#group option')).map((o) =>
      o.textContent?.trim(),
    );

    expect(options).toEqual(['Unassigned', 'IoT', 'Guest']);
    expect(
      el.querySelector<HTMLSelectElement>('#group')!.selectedOptions[0].textContent?.trim(),
    ).toBe('IoT');
  });

  it('has Overview and Scans tabs, and disabled ones for features still to come', async () => {
    const { el } = await render();
    const tabs = Array.from(el.querySelectorAll<HTMLButtonElement>('[role=tab]'));

    expect(tabs.map((t) => t.textContent?.trim())).toEqual([
      'Overview',
      'Scans',
      'DNS',
      'CVEs',
      'Policy',
    ]);
    expect(tabs[0].getAttribute('aria-selected')).toBe('true');
    expect(tabs[1].disabled).toBe(false);
    expect(tabs.slice(2).every((t) => t.disabled)).toBe(true);
  });

  it('switches to the Scans tab and loads the device scans', async () => {
    const { fixture, el } = await render();
    const scansTab = el.querySelector<HTMLButtonElement>('#tab-scans')!;
    scansTab.click();
    fixture.detectChanges();
    await sleep();

    expect(scansTab.getAttribute('aria-selected')).toBe('true');
    expect(el.querySelector('#panel-overview')).toBeNull();
    http.expectOne('/api/devices/7/scans').flush([]);
    fixture.detectChanges();
    expect(el.querySelector('#panel-scans')?.textContent).toContain('not been scanned yet');
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
    http
      .expectOne('/api/devices/7')
      .flush(
        { error: 'notes must not contain control characters' },
        { status: 400, statusText: 'Bad Request' },
      );
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
