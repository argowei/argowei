import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ScanSchedule } from '../../core/schedule.models';
import { device, group, providePageTesting, sleep } from '../../testing';
import { ScheduleList } from './schedule-list';

function schedule(overrides: Partial<ScanSchedule> = {}): ScanSchedule {
  return {
    id: 1,
    name: 'Nightly',
    cron: '0 3 * * *',
    description: 'At 03:00.',
    profile: 'quick',
    target: { kind: 'group', id: 2 },
    target_name: 'Servers',
    enabled: true,
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    last_run_at: null,
    next_run_at: '2026-11-13T02:00:00Z',
    upcoming: ['2026-11-13T02:00:00Z', '2026-11-14T02:00:00Z', '2026-11-15T02:00:00Z'],
    ...overrides,
  };
}

describe('ScheduleList', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [...providePageTesting()] });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  /** Lets the cron preview's debounce pass and answers it. */
  async function answerPreview(cron = '0 3 * * *', error?: string): Promise<void> {
    await sleep(350);
    const request = http.expectOne(
      (r) => r.url === '/api/scan-schedules/preview' && r.params.get('cron') === cron,
    );
    if (error) {
      request.flush({ error }, { status: 422, statusText: 'Unprocessable Entity' });
    } else {
      request.flush({ description: 'At 03:00.', upcoming: ['2026-11-13T02:00:00Z'] });
    }
  }

  async function render(
    schedules: ScanSchedule[],
  ): Promise<{ fixture: ComponentFixture<ScheduleList>; el: HTMLElement }> {
    const fixture = TestBed.createComponent(ScheduleList);
    fixture.detectChanges();
    http.expectOne('/api/scan-schedules').flush(schedules);
    http.expectOne('/api/devices').flush([device({ id: 7, label: 'NAS' })]);
    http.expectOne('/api/groups').flush([group(2, 'Servers')]);
    await answerPreview();
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  const type = (el: HTMLElement, selector: string, value: string): void => {
    const input = el.querySelector<HTMLInputElement>(selector)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  };

  const choose = (el: HTMLElement, selector: string, value: string): void => {
    const select = el.querySelector<HTMLSelectElement>(selector)!;
    select.value = value;
    select.dispatchEvent(new Event('change'));
  };

  it('lists schedules with what, when and the target', async () => {
    const { el } = await render([
      schedule(),
      schedule({
        id: 2,
        name: 'Weekly',
        enabled: false,
        next_run_at: null,
        upcoming: [],
        target: { kind: 'all' },
        target_name: null,
      }),
    ]);

    const items = [...el.querySelectorAll('li.schedule')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(items[0]).toContain('Nightly');
    expect(items[0]).toContain('0 3 * * * · At 03:00 · quick scan of the group Servers');
    expect(items[0]).toContain('Next:');
    expect(items[1]).toContain('quick scan of all devices');
    expect(items[1]).toContain('Not planned while off');
  });

  it('creates a schedule for one device', async () => {
    const { fixture, el } = await render([]);
    expect(el.textContent).toContain('No schedules yet.');
    expect(el.querySelector('.hint')?.textContent).toContain('At 03:00. Next:');
    expect(el.querySelector('.hint')?.textContent).not.toContain('..');

    type(el, '#sched-name', 'NAS nightly');
    choose(el, '#sched-profile', 'service');
    choose(el, '#sched-target', 'device');
    fixture.detectChanges();
    const submit = el.querySelector<HTMLButtonElement>('form button[type=submit]')!;
    expect(submit.disabled).toBe(true); // no device chosen yet
    choose(el, '#sched-device', '7');
    fixture.detectChanges();
    submit.click();

    const request = http.expectOne('/api/scan-schedules');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({
      name: 'NAS nightly',
      cron: '0 3 * * *',
      profile: 'service',
      target: { kind: 'device', id: 7 },
    });
    request.flush(
      schedule({
        id: 5,
        name: 'NAS nightly',
        target: { kind: 'device', id: 7 },
        target_name: 'NAS',
      }),
    );
    fixture.detectChanges();
    expect(el.querySelector('li.schedule')?.textContent).toContain('NAS nightly');
  });

  it('explains why a cron expression is refused', async () => {
    const { fixture, el } = await render([]);
    type(el, '#sched-cron', '*/5 * * * *');
    await answerPreview('*/5 * * * *', 'a schedule may run at most every 15 minutes');
    fixture.detectChanges();
    expect(el.querySelector('.hint .error-text')?.textContent).toContain(
      'at most every 15 minutes',
    );
  });

  it('turns a schedule off, edits and deletes it', async () => {
    const { fixture, el } = await render([schedule()]);
    const button = (label: string) =>
      [...el.querySelectorAll<HTMLButtonElement>('.actions button')].find(
        (b) => b.textContent?.trim() === label,
      )!;

    button('Turn off').click();
    const off = http.expectOne('/api/scan-schedules/1');
    expect(off.request.method).toBe('PATCH');
    expect(off.request.body).toEqual({ enabled: false });
    off.flush(schedule({ enabled: false, next_run_at: null, upcoming: [] }));
    fixture.detectChanges();
    expect(el.querySelector('li.schedule .pill')?.textContent?.trim()).toBe('off');

    button('Edit').click();
    fixture.detectChanges();
    expect(el.querySelector('#form-title')?.textContent).toBe('Edit schedule');
    expect(el.querySelector<HTMLInputElement>('#sched-name')!.value).toBe('Nightly');
    expect(el.querySelector<HTMLSelectElement>('#sched-group')!.value).toBe('2');
    type(el, '#sched-name', 'Nightly servers');
    fixture.detectChanges();
    el.querySelector<HTMLButtonElement>('form button[type=submit]')!.click();
    const edit = http.expectOne('/api/scan-schedules/1');
    expect(edit.request.body).toEqual({
      name: 'Nightly servers',
      cron: '0 3 * * *',
      profile: 'quick',
      target: { kind: 'group', id: 2 },
    });
    edit.flush(schedule({ name: 'Nightly servers' }));
    fixture.detectChanges();

    button('Delete').click();
    const removed = http.expectOne('/api/scan-schedules/1');
    expect(removed.request.method).toBe('DELETE');
    removed.flush(null, { status: 204, statusText: 'No Content' });
    fixture.detectChanges();
    expect(el.textContent).toContain('No schedules yet.');
  });
});
