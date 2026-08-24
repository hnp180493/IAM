/**
 * Simulated wall clock. Auth is about time — exp, nbf, refresh rotation, key
 * rotation — and none of it is observable at 1x when an access token lives for
 * five minutes. Everything that reads "now" reads it from here.
 */
export class Clock {
  private simMs: number;
  private lastFrame = 0;
  private rafId: number | null = null;
  timeScale = 1;
  running = false;

  constructor(startEpochMs = Date.now()) {
    this.simMs = startEpochMs;
  }

  /** Seconds since epoch, as JWT claims count it. */
  nowSec(): number {
    return Math.floor(this.simMs / 1000);
  }

  nowMs(): number {
    return this.simMs;
  }

  start(onTick?: (nowSec: number) => void): void {
    if (this.running) return;
    this.running = true;
    this.lastFrame = performance.now();
    const loop = (ts: number) => {
      if (!this.running) return;
      const delta = Math.min(ts - this.lastFrame, 250);
      this.lastFrame = ts;
      this.simMs += delta * this.timeScale;
      onTick?.(this.nowSec());
      this.rafId = requestAnimationFrame(loop);
    };
    this.rafId = requestAnimationFrame(loop);
  }

  stop(): void {
    this.running = false;
    if (this.rafId !== null) cancelAnimationFrame(this.rafId);
    this.rafId = null;
  }

  /** Jump forward, for "what happens when this token expires?" */
  advance(seconds: number): void {
    this.simMs += seconds * 1000;
  }
}
