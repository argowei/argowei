import { TestBed } from '@angular/core/testing';

import { StatusIndicator } from './status-indicator';

describe('StatusIndicator', () => {
  function render(online: boolean): HTMLElement {
    const fixture = TestBed.createComponent(StatusIndicator);
    fixture.componentRef.setInput('online', online);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('says whether the device is online, in words and not only in color', () => {
    expect(render(true).textContent?.trim()).toBe('Online');
    expect(render(true).querySelector('.status.online')).not.toBeNull();
    expect(render(false).textContent?.trim()).toBe('Offline');
    expect(render(false).querySelector('.status.online')).toBeNull();
  });
});
