import { Component, input } from '@angular/core';

import { Device, NAME_SOURCE_LABELS } from '../../core/device.models';
import { TimeAgoPipe } from '../../shared/time-ago.pipe';

/** What each name source last called the device, and which name is shown. */
@Component({
  selector: 'app-name-sources',
  imports: [TimeAgoPipe],
  template: `
    @let d = device();
    @if (d.names.length) {
      <table class="compact names">
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Name</th>
            <th scope="col">Last answered</th>
          </tr>
        </thead>
        <tbody>
          @for (entry of d.names; track entry.source) {
            <tr>
              <td>{{ sourceLabels[entry.source] }}</td>
              <td>
                {{ entry.name }}
                @if (entry.source === d.name_source && entry.name === d.name) {
                  <span class="pill">shown</span>
                }
              </td>
              <td [title]="entry.last_seen">{{ entry.last_seen | timeAgo }}</td>
            </tr>
          }
        </tbody>
      </table>
      <p class="muted hint">
        When sources disagree, DHCP beats mDNS, NetBIOS and reverse DNS, in that order.
        @if (d.label) {
          Your label "{{ d.label }}" is shown instead of all of them.
        }
      </p>
    } @else {
      <p class="muted">
        No name learned yet. Devices are asked once they are new and then about once an hour.
      </p>
    }
  `,
})
export class NameSources {
  readonly device = input.required<Device>();

  protected readonly sourceLabels = NAME_SOURCE_LABELS;
}
