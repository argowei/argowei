/** Device groups as `GET /api/groups` returns them. */

/** The group a device is in, as embedded in a device. */
export interface GroupRef {
  id: number;
  name: string;
}

/** A group with its default behavior and how many devices are in it. */
export interface Group {
  id: number;
  slug: string | null;
  name: string;
  description: string;
  is_system: boolean;
  defaults: Record<string, unknown>;
  device_count: number;
  created_at: string;
}
