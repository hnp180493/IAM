import { ATTACKS, attackName, attackSymptom, type AttackDef } from '../data/attacks';
import { tr } from '../i18n';
import type { Posture } from './Posture';

export interface ActiveAttack {
  def: AttackDef;
  spawnedAtSec: number;
  /** Số giây được miễn thiệt hại, để còn kịp đọc cảnh báo. */
  graceSec: number;
}

export interface RedTeamState {
  running: boolean;
  elapsedSec: number;
  integrity: number;
  score: number;
  neutralized: number;
  active: ActiveAttack[];
  /** Cảnh báo mới nhất trước, để bảng không nhảy loạn. */
  feed: { atSec: number; text: string; tone: 'attack' | 'fixed' | 'info' }[];
  gameOver: boolean;
}

/**
 * Red Team mode: tấn công tự sinh và leo thang, người chơi dùng console để phát
 * hiện rồi vá. Tương ứng Chaos Mode của k8sgames, khác chỗ "sự cố" ở đây là một
 * cờ phòng thủ bị tắt thật, và "sửa" là bật lại bằng lệnh.
 *
 * Engine không tự biết người chơi đã sửa hay chưa - nó đọc lại Posture mỗi giây.
 * Nhờ vậy không có cách nào ghi điểm mà không thật sự vá.
 */
export class RedTeamEngine {
  private state: RedTeamState = this.emptyState();
  private timer: number | null = null;
  private nextSpawnAtSec = 6;
  private rngSeed = 1;

  onUpdate?: (s: RedTeamState) => void;

  constructor(private posture: Posture) {}

  private emptyState(): RedTeamState {
    return {
      running: false,
      elapsedSec: 0,
      integrity: 100,
      score: 0,
      neutralized: 0,
      active: [],
      feed: [],
      gameOver: false,
    };
  }

  get snapshot(): RedTeamState {
    return this.state;
  }

  /** Random có hạt giống: cùng một lượt chơi lặp lại được khi cần soi lỗi. */
  private rand(): number {
    this.rngSeed = (this.rngSeed * 1103515245 + 12345) & 0x7fffffff;
    return this.rngSeed / 0x7fffffff;
  }

  start(): void {
    this.stop();
    this.posture.reset();
    this.state = this.emptyState();
    this.state.running = true;
    this.nextSpawnAtSec = 6;
    this.rngSeed = 1;
    this.push(tr('Hệ thống đang ở trạng thái siết. Giữ nó như vậy.', 'The system starts hardened. Keep it that way.'), 'info');

    this.timer = window.setInterval(() => this.tick(), 1000);
    this.onUpdate?.(this.state);
  }

  stop(): void {
    if (this.timer !== null) window.clearInterval(this.timer);
    this.timer = null;
    this.state.running = false;
  }

  private push(text: string, tone: 'attack' | 'fixed' | 'info'): void {
    this.state.feed.unshift({ atSec: this.state.elapsedSec, text, tone });
    if (this.state.feed.length > 40) this.state.feed.pop();
  }

  private tick(): void {
    const s = this.state;
    if (!s.running) return;
    s.elapsedSec += 1;

    // Sống sót là ghi điểm, nhưng chỉ khi hệ thống còn sạch.
    if (!s.active.length) s.score += 2;
    else s.score += 1;

    // Ai đã vá thì gỡ khỏi danh sách.
    for (const a of [...s.active]) {
      if (a.def.fixed(this.posture.flags)) {
        s.active = s.active.filter((x) => x !== a);
        s.neutralized += 1;
        const speed = s.elapsedSec - a.spawnedAtSec;
        const bonus = Math.max(10, 60 - speed * 2) * a.def.severity;
        s.score += bonus;
        this.push(tr(`Đã vá "${attackName(a.def)}" sau ${speed}s (+${bonus} điểm)`, `Patched "${attackName(a.def)}" in ${speed}s (+${bonus} points)`), 'fixed');
      }
    }

    // Cái nào để lâu thì trừ toàn vẹn.
    for (const a of s.active) {
      const age = s.elapsedSec - a.spawnedAtSec;
      if (age > a.graceSec) s.integrity -= a.def.drain;
    }
    s.integrity = Math.max(0, Math.round(s.integrity * 10) / 10);

    // Leo thang: càng về sau càng dày.
    if (s.elapsedSec >= this.nextSpawnAtSec) {
      this.spawn();
      const interval = Math.max(7, 22 - Math.floor(s.elapsedSec / 20) * 3);
      this.nextSpawnAtSec = s.elapsedSec + interval;
    }

    if (s.integrity <= 0) {
      s.gameOver = true;
      this.push(tr(`Hệ thống bị chiếm ở giây thứ ${s.elapsedSec}. Điểm: ${s.score}`, `System compromised at ${s.elapsedSec}s. Score: ${s.score}`), 'attack');
      this.stop();
    }

    this.onUpdate?.(s);
  }

  private spawn(): void {
    // Chỉ chọn trong những cuộc tấn công còn phá được gì.
    const candidates = ATTACKS.filter(
      (d) => d.fixed(this.posture.flags) && !this.state.active.some((a) => a.def.id === d.id),
    );
    if (!candidates.length) return;

    const def = candidates[Math.floor(this.rand() * candidates.length)]!;
    if (!def.apply(this.posture.flags)) return;

    this.state.active.push({
      def,
      spawnedAtSec: this.state.elapsedSec,
      graceSec: def.severity === 3 ? 8 : 12,
    });
    this.push(`${attackName(def)} — ${attackSymptom(def)}`, 'attack');
  }
}
