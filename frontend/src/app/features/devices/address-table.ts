import { Component, input } from '@angular/core';

import { DeviceAddress } from '../../core/device.models';
import { TimeAgoPipe } from '../../shared/time-ago.pipe';

/** Every IP address a device was seen with. */
@Component({
  selector: 'app-address-table',
  imports: [TimeAgoPipe],
  template: `
    @if (addresses().length) {
      <table class="compact">
        <thead>
          <tr>
            <th scope="col">IP address</th>
            <th scope="col">Source</th>
            <th scope="col">Last seen</th>
          </tr>
        </thead>
        <tbody>
          @for (address of addresses(); track address.id) {
            <tr>
              <td>
                <code>{{ address.ip_address }}</code>
              </td>
              <td>{{ address.source.toUpperCase() }}</td>
              <td [title]="address.last_seen">{{ address.last_seen | timeAgo }}</td>
            </tr>
          }
        </tbody>
      </table>
    } @else {
      <p class="muted">No addresses recorded.</p>
    }
  `,
})
export class AddressTable {
  readonly addresses = input.required<DeviceAddress[]>();
}
