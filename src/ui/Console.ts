import { t } from '../i18n';
import type { LabSession, Line } from '../engine/LabSession';

const COMMANDS = ['help', 'authorize', 'token', 'refresh', 'jwt', 'curl', 'policy', 'login', 'profile', 'revoke', 'tokens', 'jwks', 'discovery', 'pubkey', 'status', 'audit', 'harden', 'clear'];
const SUB: Record<string, string[]> = {
  jwt: ['decode', 'verify', 'forge'],
  policy: ['eval'],
  harden: ['plain', 'pkce', 'code', 'redirect', 'aud', 'aud-internal', 'signature', 'alg', 'ttl', 'logout'],
  help: ['authorize', 'token', 'jwt', 'curl', 'policy', 'session'],
};
const FLAGS: Record<string, string[]> = {
  authorize: ['--pkce', '--scope', '--redirect', '--client', '--user', '--show-verifier'],
  token: ['--code', '--verifier', '--redirect', '--client'],
  refresh: ['--reuse'],
  curl: ['--token', '--api', '--scope-required', '--no-aud-check'],
  jwt: ['--set', '--set-header', '--hs256', '--own-key', '--aud', '--iss'],
  policy: ['--model', '--hour'],
  login: ['--sid'],
  profile: ['--sid'],
  revoke: ['--sid'],
};

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Console gõ tay. Đây là phần thay thế dropdown, và là lý do thử thách khó hơn:
 * không có sẵn 3 lựa chọn để bấm thử, bạn phải tự biết cần gửi gì.
 *
 * Cùng vai trò với CommandBar của k8sgames, khác chỗ nó nói OAuth thay vì kubectl.
 */
export class Console {
  private root: HTMLElement;
  private out!: HTMLElement;
  private input!: HTMLInputElement;
  private history: string[] = [];
  private historyIndex = -1;
  private busy = false;

  onAfterCommand?: () => void;

  constructor(root: HTMLElement, private session: LabSession) {
    this.root = root;
    this.build();
  }

  private build(): void {
    this.root.innerHTML = `
      <div class="con-out" id="con-out"></div>
      <div class="con-inputline">
        <span class="con-prompt">$</span>
        <input id="con-input" type="text" spellcheck="false" autocomplete="off"
               placeholder="${t('con.placeholder')}" />
      </div>`;
    this.out = this.root.querySelector('#con-out')!;
    this.input = this.root.querySelector('#con-input')!;

    this.input.addEventListener('keydown', (e) => this.onKey(e));
    this.root.addEventListener('click', () => this.input.focus());
  }

  focus(): void {
    this.input.focus();
  }

  reset(banner = true): void {
    this.out.innerHTML = '';
    this.history = [];
    this.historyIndex = -1;
    this.session.reset();
    if (banner) {
      this.print([
        { text: t('con.banner'), tone: 'warn' },
        { text: t('con.banner2'), tone: 'dim' },
      ]);
    }
  }

  private onKey(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      e.preventDefault();
      void this.submit();
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      this.navigate(-1);
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      this.navigate(1);
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      this.complete();
      return;
    }
  }

  private navigate(dir: number): void {
    if (!this.history.length) return;
    if (this.historyIndex === -1) this.historyIndex = this.history.length;
    this.historyIndex = Math.max(0, Math.min(this.history.length, this.historyIndex + dir));
    this.input.value = this.history[this.historyIndex] ?? '';
  }

  /** Hoàn tất lệnh, lệnh con, rồi tới cờ - theo đúng thứ tự người ta gõ. */
  private complete(): void {
    const value = this.input.value;
    const parts = value.split(' ');
    const last = parts[parts.length - 1] ?? '';
    const head = parts[0] ?? '';

    let pool: string[];
    if (parts.length === 1) pool = COMMANDS;
    else if (parts.length === 2 && SUB[head]) pool = [...(SUB[head] ?? []), ...(FLAGS[head] ?? [])];
    else pool = FLAGS[head] ?? [];

    const matches = pool.filter((c) => c.startsWith(last));
    if (!matches.length) return;

    if (matches.length === 1) {
      parts[parts.length - 1] = matches[0]!;
      this.input.value = parts.join(' ') + ' ';
      return;
    }
    this.print([{ text: matches.join('   '), tone: 'dim' }]);
  }

  private async submit(): Promise<void> {
    const raw = this.input.value.trim();
    if (!raw || this.busy) return;

    this.input.value = '';
    this.history.push(raw);
    this.historyIndex = -1;
    this.print([{ text: raw, tone: 'echo' }]);

    if (raw === 'clear') {
      this.out.innerHTML = '';
      return;
    }

    this.busy = true;
    try {
      const lines = await this.session.run(raw);
      this.print(lines);
    } finally {
      this.busy = false;
      this.onAfterCommand?.();
    }
  }

  print(lines: Line[]): void {
    for (const l of lines) {
      const div = document.createElement('div');
      div.className = `con-line con-${l.tone}`;
      div.innerHTML = l.tone === 'echo' ? `<span class="con-prompt">$</span> ${esc(l.text)}` : esc(l.text);
      this.out.appendChild(div);
    }
    this.out.scrollTop = this.out.scrollHeight;
  }
}
