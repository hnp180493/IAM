import type { Clock } from '../core/Clock';
import type { Packet } from '../core/types';

export interface FlowResult {
  packets: Packet[];
  outcome: 'success' | 'attacker-won' | 'failed';
  summary: string;
}

export function httpText(body: unknown): string | undefined {
  if (body === undefined) return undefined;
  return typeof body === 'string' ? body : JSON.stringify(body, null, 2);
}

/**
 * Ghi lại từng chặng của một luồng. Mọi flow dùng chung cái này để sơ đồ và
 * inspector không cần biết flow nào đang chạy.
 */
export class HopRecorder {
  readonly packets: Packet[] = [];
  private seq = 0;

  constructor(private clock: Clock) {}

  push(p: Omit<Packet, 'id' | 'seq' | 'atSec'>): Packet {
    const packet: Packet = { ...p, id: `p${this.seq}`, seq: this.seq, atSec: this.clock.nowSec() };
    this.seq += 1;
    this.packets.push(packet);
    return packet;
  }
}
