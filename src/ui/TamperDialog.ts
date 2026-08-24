import { b64uJson, b64uToJson } from '../util/base64url';
import { decodeJwt, type Check } from '../crypto/jose';
import { tr, onLangChange } from '../i18n';

export interface TamperOutcome {
  token: string;
  status: number;
  statusText: string;
  reason: string;
  checks: Check[];
  valid: boolean;
}

export type Replayer = (token: string) => Promise<TamperOutcome>;

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Sửa token rồi bắn lại. Không ký lại - đó chính là điểm của bài học: payload
 * sửa được tuỳ ý, còn chữ ký thì không, nên API phải bắt được.
 *
 * Hai nút tấn công sẵn có là hai lỗ hổng JWT kinh điển nhất, để người học không
 * phải tự nghĩ ra cú đánh đầu tiên.
 */
export class TamperDialog {
  private root: HTMLElement;
  private original = '';
  private replay: Replayer | null = null;

  constructor(root: HTMLElement) {
    this.root = root;
    this.root.style.display = 'none';
    onLangChange(() => {
      if (this.root.style.display !== 'none' && this.original) this.open(this.original, this.replay!);
    });
  }

  open(token: string, replay: Replayer): void {
    this.original = token;
    this.replay = replay;
    const decoded = decodeJwt(token);
    if (!decoded) return;

    this.root.style.display = 'grid';
    this.root.innerHTML = `
      <div class="tamper-card">
        <div class="tamper-head">
          <div>
            <div class="tut-kicker">${tr('Sửa và bắn lại', 'Tamper & replay')}</div>
            <h2>${tr('Tự tay phá token này', 'Break this token yourself')}</h2>
          </div>
          <button class="btn-ghost" id="tam-close">${tr('Đóng', 'Close')}</button>
        </div>

        <p class="tamper-intro">
          ${tr(
            'Sửa header hoặc payload bên dưới rồi bấm "Bắn lại". Token sẽ được ghép lại với <strong>chữ ký cũ giữ nguyên</strong> - đúng như những gì một kẻ tấn công có thể làm, vì họ không có private key. Sau đó API thật sẽ verify và cho biết nó bắt được ở đâu.',
            'Edit the header or payload below then press "Replay". The token gets reassembled with <strong>the original signature kept as-is</strong> — exactly what an attacker can do, since they have no private key. The real API then verifies it and tells you exactly where it caught the forgery.',
          )}
        </p>

        <div class="tamper-presets">
          <button class="preset-btn" data-attack="admin">${tr('Nâng roles lên admin', 'Escalate roles to admin')}</button>
          <button class="preset-btn" data-attack="alg-none">${tr('Đổi alg thành "none"', 'Switch alg to "none"')}</button>
          <button class="preset-btn" data-attack="exp">${tr('Gia hạn exp thêm 10 năm', 'Extend exp by 10 years')}</button>
          <button class="preset-btn" data-attack="aud">${tr('Đổi aud sang API nội bộ', 'Switch aud to the internal API')}</button>
          <button class="preset-btn ghost" data-attack="reset">${tr('Khôi phục nguyên bản', 'Restore original')}</button>
        </div>

        <label class="tamper-label">Header</label>
        <textarea id="tam-header" rows="5" spellcheck="false"></textarea>
        <label class="tamper-label">Payload</label>
        <textarea id="tam-payload" rows="12" spellcheck="false"></textarea>

        <div class="tamper-actions">
          <span class="tamper-sig">${tr('chữ ký: giữ nguyên bản gốc (không ký lại)', 'signature: kept from the original (not re-signed)')}</span>
          <button class="btn-primary" id="tam-send">${tr('Bắn lại vào API', 'Replay against the API')}</button>
        </div>

        <div id="tam-result"></div>
      </div>`;

    this.fill(JSON.stringify(decoded.header, null, 2), JSON.stringify(decoded.claims, null, 2));

    this.root.querySelector('#tam-close')!.addEventListener('click', () => this.close());
    this.root.querySelector('#tam-send')!.addEventListener('click', () => void this.send());
    for (const b of this.root.querySelectorAll<HTMLButtonElement>('.preset-btn')) {
      b.addEventListener('click', () => this.applyAttack(b.dataset['attack']!));
    }
  }

  private fill(header: string, payload: string): void {
    this.q<HTMLTextAreaElement>('#tam-header').value = header;
    this.q<HTMLTextAreaElement>('#tam-payload').value = payload;
  }

  private applyAttack(attack: string): void {
    const decoded = decodeJwt(this.original);
    if (!decoded) return;

    if (attack === 'reset') {
      this.fill(JSON.stringify(decoded.header, null, 2), JSON.stringify(decoded.claims, null, 2));
      this.q('#tam-result').innerHTML = '';
      return;
    }

    const header = { ...decoded.header };
    const claims = { ...decoded.claims };

    if (attack === 'admin') claims['roles'] = ['admin', 'superuser'];
    if (attack === 'alg-none') header.alg = 'none';
    if (attack === 'exp') claims.exp = (claims.exp ?? 0) + 60 * 60 * 24 * 365 * 10;
    if (attack === 'aud') claims.aud = 'https://api-internal.example.com';

    this.fill(JSON.stringify(header, null, 2), JSON.stringify(claims, null, 2));
  }

  private async send(): Promise<void> {
    const out = this.q('#tam-result');
    let header: unknown;
    let claims: unknown;
    try {
      header = JSON.parse(this.q<HTMLTextAreaElement>('#tam-header').value);
      claims = JSON.parse(this.q<HTMLTextAreaElement>('#tam-payload').value);
    } catch (e) {
      out.innerHTML = `<div class="tamper-verdict bad">${tr('JSON không hợp lệ', 'Invalid JSON')}: ${esc(String(e))}</div>`;
      return;
    }

    // Ghép lại token với đúng chữ ký cũ. Đây là toàn bộ khả năng của kẻ tấn công.
    const originalSig = this.original.split('.')[2] ?? '';
    const forged = `${b64uJson(header)}.${b64uJson(claims)}.${originalSig}`;

    const changed = this.diff(claims as Record<string, unknown>);
    const result = await this.replay!(forged);

    out.innerHTML = `
      ${changed.length ? `<div class="tamper-diff">${tr('Đã sửa', 'Edited')}: ${changed.map((c) => `<code>${esc(c)}</code>`).join(', ')}</div>` : ''}
      <div class="tamper-verdict ${result.status === 200 ? 'bad' : 'good'}">
        ${tr('API trả về', 'The API returned')} <strong>${result.status} ${esc(result.statusText)}</strong>
        ${
          result.status === 200
            ? tr(' — token giả được CHẤP NHẬN. Nếu thấy dòng này thì có một phép kiểm tra đã bị tắt.', ' — the forged token was ACCEPTED. If you see this, some check has been turned off.')
            : tr(' — token giả bị chặn.', ' — the forged token was blocked.')
        }
      </div>
      <div class="tamper-reason">${esc(result.reason)}</div>
      <div class="checks ${result.valid ? 'all-ok' : 'has-fail'}">
        <div class="checks-head">${result.valid ? tr('Chấp nhận', 'Accepted') : tr('Từ chối', 'Rejected')} &middot; ${tr(`đạt ${result.checks.filter((c) => c.ok).length}/${result.checks.length} phép kiểm tra`, `${result.checks.filter((c) => c.ok).length}/${result.checks.length} checks passed`)}</div>
        ${result.checks
          .map(
            (c) =>
              `<div class="check ${c.ok ? 'ok' : 'bad'}"><span class="check-mark">${c.ok ? '+' : '!'}</span><code>${esc(c.name)}</code><span class="check-detail">${esc(c.detail)}</span></div>`,
          )
          .join('')}
      </div>
      <pre class="wire jwt tamper-token">${esc(forged.slice(0, 300))}${forged.length > 300 ? '...' : ''}</pre>`;
  }

  /** So với bản gốc để nói rõ người học vừa đổi những gì. */
  private diff(claims: Record<string, unknown>): string[] {
    const parts = this.original.split('.');
    if (parts.length !== 3) return [];
    let originalClaims: Record<string, unknown>;
    try {
      originalClaims = b64uToJson<Record<string, unknown>>(parts[1]!);
    } catch {
      return [];
    }
    const keys = new Set([...Object.keys(originalClaims), ...Object.keys(claims)]);
    return [...keys].filter((k) => JSON.stringify(originalClaims[k]) !== JSON.stringify(claims[k]));
  }

  close(): void {
    this.root.style.display = 'none';
  }

  private q<T extends HTMLElement>(sel: string): T {
    return this.root.querySelector<T>(sel)!;
  }
}
