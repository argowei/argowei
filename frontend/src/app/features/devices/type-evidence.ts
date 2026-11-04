import { Component, input } from '@angular/core';

import { DEVICE_TYPE_LABELS, Device, Evidence } from '../../core/device.models';

/** How an evidence kind is called in the explanation. */
const KIND_LABELS: Record<Evidence['kind'], string> = {
  vendor: 'Manufacturer',
  private_mac: 'MAC address',
  hostname: 'Hostname',
  port: 'Open port',
  mdns: 'Service announcement',
};

/** Why the classifier picked the device's type: every rule that fired, with its weight. */
@Component({
  selector: 'app-type-evidence',
  template: `
    @let inferred = device().inferred;
    @if (inferred.evidence.length) {
      <p class="muted hint">
        The automatic guess is {{ typeLabels[inferred.device_type] }}
        @if (inferred.device_type !== 'unknown') {
          ({{ inferred.confidence }} % sure)
        }
        based on:
      </p>
      <ul class="evidence">
        @for (item of inferred.evidence; track $index) {
          <li>
            <strong>{{ kindLabels[item.kind] }}</strong
            >: {{ item.detail }} → {{ typeLabels[item.type] }}
            <span class="muted">(+{{ item.weight }} %)</span>
          </li>
        }
      </ul>
    } @else {
      <p class="muted">Nothing recognisable yet, so the type stays unknown.</p>
    }
  `,
  styles: `
    .evidence {
      margin: 0.4rem 0 0;
      padding-left: 1.2rem;
    }
    .evidence li {
      margin: 0.25rem 0;
      overflow-wrap: anywhere;
    }
  `,
})
export class TypeEvidence {
  readonly device = input.required<Device>();

  protected readonly typeLabels = DEVICE_TYPE_LABELS;
  protected readonly kindLabels = KIND_LABELS;
}
