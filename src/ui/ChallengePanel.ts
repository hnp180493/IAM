import { t, onLangChange } from '../i18n';
import { challengeTitle, challengeBrief, challengeHints, challengeDebrief, objectiveText, knobLabel, knobHelp, knobOption } from '../i18n/content';
import type { Challenge, ChallengeContext } from '../data/challenges';

/**
 * Panel bên trái trong chế độ thử thách. Đây là phần k8sgames có mà lab này
 * thiếu ở hai lượt đầu: một danh sách mục tiêu tự tick, để người học biết mình
 * đã làm được gì chứ không phải đọc rồi đoán.
 */
export class ChallengePanel {
  private root: HTMLElement;
  private challenge: Challenge | null = null;
  private values: Record<string, string> = {};
  private lastContext: ChallengeContext | null = null;
  private revealedHints = 0;
  private solved = new Set<string>();
  private running = false;

  onRun?: () => void;
  onBack?: () => void;
  onChange?: () => void;
  onResetConsole?: () => void;

  constructor(root: HTMLElement) {
    this.root = root;
    this.root.style.display = 'none';
    onLangChange(() => {
      if (this.challenge) this.render();
    });
  }

  open(challenge: Challenge): void {
    this.challenge = challenge;
    this.values = { ...challenge.start };
    this.lastContext = null;
    this.revealedHints = 0;
    this.root.style.display = 'block';
    this.render();
  }

  close(): void {
    this.root.style.display = 'none';
  }

  get current(): Challenge | null {
    return this.challenge;
  }

  get knobValues(): Record<string, string> {
    return { ...this.values };
  }

  /** Gọi sau mỗi lần chạy để tick lại mục tiêu. */
  report(context: ChallengeContext): void {
    this.lastContext = context;
    if (this.challenge && this.challenge.objectives.every((o) => o.check(context))) {
      this.solved.add(this.challenge.id);
    }
    this.render();
  }

  /**
   * Không để người học bấm chồng lượt chạy rồi tưởng nút hỏng: lượt sau bị bỏ
   * im lặng và kết quả hiện ra lệch một nhịp so với cấu hình đang thấy.
   */
  setRunning(running: boolean): void {
    this.running = running;
    const btn = this.root.querySelector<HTMLButtonElement>('#cp-run');
    if (btn) {
      btn.disabled = running;
      btn.textContent = running ? t('cp.running') : t('cp.run');
    }
  }

  isSolved(id: string): boolean {
    return this.solved.has(id);
  }

  private render(): void {
    const ch = this.challenge;
    if (!ch) return;

    const ctx = this.lastContext;
    const done = ctx ? ch.objectives.filter((o) => o.check(ctx)).length : 0;
    const all = ctx !== null && done === ch.objectives.length;

    this.root.innerHTML = `
      <div class="cp-head">
        <button class="hud-back" id="cp-back">&larr; ${t('cp.back')}</button>
        <div class="cp-diff">${'●'.repeat(ch.difficulty)}${'○'.repeat(3 - ch.difficulty)}</div>
      </div>

      <h2 class="cp-title">${challengeTitle(ch)}</h2>
      <p class="cp-brief">${challengeBrief(ch)}</p>

      ${
        ch.knobs.length
          ? `<div class="cp-section">${t('cp.knobs')}</div>${ch.knobs.map((k) => this.knob(k)).join('')}`
          : `<div class="cp-console-note">${t('cp.consoleNote')}</div>`
      }

      <div class="cp-section">${t('cp.objectives')} ${ctx ? `<span class="cp-progress">${done}/${ch.objectives.length}</span>` : ''}</div>
      <div class="cp-objectives">
        ${ch.objectives
          .map((o) => {
            const state = !ctx ? 'pending' : o.check(ctx) ? 'done' : 'fail';
            const mark = state === 'done' ? '✓' : state === 'fail' ? '✗' : '○';
            return `<div class="cp-obj ${state}"><span class="cp-mark">${mark}</span><span>${objectiveText(ch.id, o.id, o.text)}</span></div>`;
          })
          .join('')}
      </div>

      ${
        ch.mode === 'console'
          ? `<button class="btn-ghost cp-run" id="cp-reset-console">${t('cp.resetConsole')}</button>`
          : `<button class="btn-primary cp-run" id="cp-run" ${this.running ? 'disabled' : ''}>${this.running ? t('cp.running') : t('cp.run')}</button>`
      }

      ${
        all
          ? `<div class="cp-solved">
               <div class="cp-solved-title">${t('cp.solvedTitle', { n: ch.objectives.length })}</div>
               <p>${challengeDebrief(ch)}</p>
             </div>`
          : ''
      }

      <div class="cp-section">${t('cp.hints')}</div>
      <div class="cp-hints">
        ${challengeHints(ch)
          .slice(0, this.revealedHints)
          .map((h, i) => `<div class="cp-hint">${i + 1}. ${h}</div>`)
          .join('')}
        ${
          this.revealedHints < challengeHints(ch).length
            ? `<button class="cp-hint-btn" id="cp-hint">${t('cp.openHint', { i: this.revealedHints + 1, n: challengeHints(ch).length })}</button>`
            : `<div class="cp-hint-done">${t('cp.hintsDone')}</div>`
        }
      </div>`;

    this.root.querySelector('#cp-back')!.addEventListener('click', () => this.onBack?.());
    this.root.querySelector('#cp-run')?.addEventListener('click', () => this.onRun?.());
    this.root.querySelector('#cp-reset-console')?.addEventListener('click', () => this.onResetConsole?.());
    this.root.querySelector('#cp-hint')?.addEventListener('click', () => {
      this.revealedHints += 1;
      this.render();
    });

    for (const sel of this.root.querySelectorAll<HTMLSelectElement>('.cp-knob select')) {
      sel.addEventListener('change', () => {
        this.values[sel.dataset['knob']!] = sel.value;
        // Đổi cấu hình thì kết quả cũ không còn nói lên điều gì.
        this.lastContext = null;
        this.render();
        this.onChange?.();
      });
    }
  }

  private knob(k: Challenge['knobs'][number]): string {
    const chId = this.challenge!.id;
    return `<div class="cp-knob">
      <label>${knobLabel(chId, k.id, k.label)}</label>
      <select data-knob="${k.id}">
        ${k.options
          .map((o) => `<option value="${o.value}" ${this.values[k.id] === o.value ? 'selected' : ''}>${knobOption(chId, k.id, o.value, o.label)}</option>`)
          .join('')}
      </select>
      <div class="cp-knob-help">${knobHelp(chId, k.id, k.help)}</div>
    </div>`;
  }
}
