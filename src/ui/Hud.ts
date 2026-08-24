import { t, onLangChange } from '../i18n';
import type { PkceMethod } from '../crypto/pkce';

export interface HudState {
  pkceMethod: PkceMethod;
  interceptCode: boolean;
  scope: string;
  requiredScope: string;
  timeScale: number;
}

export interface HudStats {
  activeTokens: number;
  expiresIn: number | null;
  outcome: string;
  tone: 'idle' | 'success' | 'danger' | 'failed';
}

/**
 * Top bar. Everything you can change about the run lives here, so a whole
 * experiment is one click away - that is the thing k8sgames gets right: no
 * setup screen between you and the next attempt.
 */
export class Hud {
  private root: HTMLElement;
  state: HudState = {
    pkceMethod: 'S256',
    interceptCode: false,
    scope: 'openid profile read:reports',
    requiredScope: 'read:reports',
    timeScale: 1,
  };
  onRun?: () => void;
  onReset?: () => void;
  onChange?: () => void;
  onMenu?: () => void;

  constructor(root: HTMLElement) {
    this.root = root;
    this.render();
    onLangChange(() => this.render());
  }

  private render(): void {
    this.root.innerHTML = `
      <button class="hud-back" id="h-menu" title="${t('hud.back')}">&larr; ${t('hud.back')}</button>
      <div class="hud-brand"><span class="hud-logo">ID</span> <span id="h-lesson">IAM Lab</span></div>

      <div class="hud-group" id="h-group-pkce">
        <label>PKCE
          <select id="h-pkce">
            <option value="S256">S256</option>
            <option value="plain">plain</option>
            <option value="none">none</option>
          </select>
        </label>
        <label class="hud-check">
          <input type="checkbox" id="h-intercept" /> ${t('hud.attacker')}
        </label>
      </div>

      <div class="hud-group" id="h-group-scope">
        <label>${t('hud.scope')} <input id="h-scope" type="text" size="24" /></label>
        <label>${t('hud.apiRequires')} <input id="h-req" type="text" size="14" /></label>
      </div>

      <div class="hud-group hud-speed" id="h-speed">
        ${[1, 2, 8, 60].map((s) => `<button data-speed="${s}">${s}x</button>`).join('')}
      </div>

      <div class="hud-group hud-stats">
        <span>${t('hud.tokens')} <b id="h-tokens">0</b></span>
        <span>${t('hud.expiresIn')} <b id="h-exp">--</b></span>
      </div>

      <div class="hud-group hud-actions">
        <button id="h-run" class="btn-primary">${t('hud.run')}</button>
        <button id="h-reset" class="btn-ghost">${t('hud.reset')}</button>
      </div>

      <div class="hud-outcome tone-idle" id="h-outcome">${t('hud.run')}.</div>`;

    const pkce = this.q<HTMLSelectElement>('#h-pkce');
    const intercept = this.q<HTMLInputElement>('#h-intercept');
    const scope = this.q<HTMLInputElement>('#h-scope');
    const req = this.q<HTMLInputElement>('#h-req');

    pkce.value = this.state.pkceMethod;
    intercept.checked = this.state.interceptCode;
    scope.value = this.state.scope;
    req.value = this.state.requiredScope;

    pkce.addEventListener('change', () => {
      this.state.pkceMethod = pkce.value as PkceMethod;
      this.onChange?.();
    });
    intercept.addEventListener('change', () => {
      this.state.interceptCode = intercept.checked;
      this.onChange?.();
    });
    scope.addEventListener('input', () => {
      this.state.scope = scope.value;
    });
    req.addEventListener('input', () => {
      this.state.requiredScope = req.value;
    });

    for (const b of this.root.querySelectorAll<HTMLButtonElement>('#h-speed button')) {
      b.addEventListener('click', () => {
        this.state.timeScale = Number(b.dataset['speed']);
        this.syncSpeed();
        this.onChange?.();
      });
    }
    this.syncSpeed();

    this.q<HTMLButtonElement>('#h-run').addEventListener('click', () => this.onRun?.());
    this.q<HTMLButtonElement>('#h-reset').addEventListener('click', () => this.onReset?.());
    this.q<HTMLButtonElement>('#h-menu').addEventListener('click', () => this.onMenu?.());
  }

  /** Áp nguyên cấu hình của một bài học vào thanh điều khiển. */
  applyPreset(preset: HudState, lessonTitle: string): void {
    this.state = { ...preset };
    this.render();
    this.q('#h-lesson').textContent = lessonTitle;
  }

  setLessonName(title: string): void {
    this.q('#h-lesson').textContent = title;
  }

  /**
   * Chỉ hiện những núm mà luồng đang chạy thật sự dùng. Để lộ dropdown PKCE
   * trong bài phân quyền chỉ làm người học tưởng nó có tác dụng.
   */
  setFlow(flow: string): void {
    // 'challenge' ẩn hết: trong thử thách, núm nằm ở panel bên trái để người
    // học chỉ có đúng những lựa chọn mà thử thách đó nói tới.
    const usesPkce = flow === 'authcode' || flow === 'openiddict';
    const usesScope = flow === 'authcode' || flow === 'aud-confusion' || flow === 'openiddict';
    this.root.querySelector<HTMLElement>('#h-group-pkce')!.style.display = usesPkce ? 'flex' : 'none';
    this.root.querySelector<HTMLElement>('#h-group-scope')!.style.display = usesScope ? 'flex' : 'none';
  }

  private syncSpeed(): void {
    for (const b of this.root.querySelectorAll<HTMLButtonElement>('#h-speed button')) {
      b.classList.toggle('active', Number(b.dataset['speed']) === this.state.timeScale);
    }
  }

  setStats(s: HudStats): void {
    this.q('#h-tokens').textContent = String(s.activeTokens);
    this.q('#h-exp').textContent = s.expiresIn === null ? '--' : `${s.expiresIn}s`;
    const out = this.q('#h-outcome');
    out.textContent = s.outcome;
    out.className = `hud-outcome tone-${s.tone}`;
  }

  setRunning(running: boolean): void {
    this.q<HTMLButtonElement>('#h-run').disabled = running;
  }

  private q<T extends HTMLElement>(sel: string): T {
    return this.root.querySelector<T>(sel)!;
  }
}
