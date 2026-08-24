import { t, tr, onLangChange } from '../i18n';
import { decodeJwt, type Check, type VerifyResult } from '../crypto/jose';
import { claimDoc } from '../data/claims';
import type { Packet } from '../core/types';

type Tab = 'http' | 'token';

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Right-hand panel: the raw wire, and the token taken apart. */
export class Inspector {
  private root: HTMLElement;
  private tab: Tab = 'http';
  private packet: Packet | null = null;
  private verification: VerifyResult | null = null;
  /** Bật nút "Sửa và bắn lại" cho token nào đó. */
  onTamper?: (token: string) => void;

  constructor(root: HTMLElement) {
    this.root = root;
    this.render();
    onLangChange(() => this.render());
  }

  show(packet: Packet, verification: VerifyResult | null = null): void {
    this.packet = packet;
    this.verification = verification;
    // Land on whichever tab actually has something to say.
    this.tab = packet.tokens?.length ? 'token' : 'http';
    this.render();
  }

  private render(): void {
    if (!this.packet) {
      this.root.innerHTML = `
        <div class="ins-empty">
          <h3>${t('ins.empty.title')}</h3>
          <p>${t('ins.empty.body')}</p>
        </div>`;
      return;
    }
    const p = this.packet;
    const hasToken = Boolean(p.tokens?.length);
    this.root.innerHTML = `
      <div class="ins-head">
        <div class="ins-seq">${t('ins.hop')} ${p.seq + 1}</div>
        <div class="ins-title">${esc(p.label)}</div>
        <div class="ins-route">${p.from} &rarr; ${p.to}</div>
      </div>
      <div class="ins-note tone-${p.tone}">${esc(p.note)}</div>
      <div class="ins-tabs">
        <button data-tab="http" class="${this.tab === 'http' ? 'active' : ''}">${t('ins.tab.http')}</button>
        <button data-tab="token" class="${this.tab === 'token' ? 'active' : ''}" ${hasToken ? '' : 'disabled'}>Token${hasToken ? ` (${p.tokens!.length})` : ''}</button>
      </div>
      <div class="ins-body">${this.tab === 'http' ? this.renderHttp() : this.renderTokens()}</div>`;

    for (const btn of this.root.querySelectorAll<HTMLButtonElement>('.ins-tabs button')) {
      btn.addEventListener('click', () => {
        this.tab = btn.dataset['tab'] as Tab;
        this.render();
      });
    }
    for (const btn of this.root.querySelectorAll<HTMLButtonElement>('.tok-tamper')) {
      btn.addEventListener('click', () => this.onTamper?.(btn.dataset['token']!));
    }
  }

  private renderHttp(): string {
    const h = this.packet!.http;
    const start =
      h.kind === 'request' ? `${h.method} ${h.url}` : `HTTP/1.1 ${h.status} ${h.statusText}`;
    const headers = Object.entries(h.headers)
      .map(([k, v]) => `<span class="hk">${esc(k)}:</span> ${esc(v)}`)
      .join('\n');
    return `<pre class="wire"><span class="start">${esc(start)}</span>
${headers}${h.body ? `\n\n${esc(h.body)}` : ''}</pre>`;
  }

  private renderTokens(): string {
    return this.packet!.tokens!.map((t) => this.renderToken(t.label, t.value)).join('');
  }

  private renderToken(label: string, value: string): string {
    const decoded = decodeJwt(value);
    if (!decoded) {
      return `<div class="tok">
        <div class="tok-label">${esc(label)}</div>
        <pre class="wire opaque">${esc(value)}</pre>
        <p class="tok-hint">${tr(
          'Đây không phải JWT mà là reference token dạng đục. Nó không chứa claim nào đọc được, muốn biết gì về nó thì phải hỏi lại bên phát (token introspection). Đó là điểm mạnh: server nói huỷ là huỷ được ngay.',
          "This isn't a JWT — it's an opaque reference token. It carries no readable claims; the only way to learn anything about it is to ask the issuer (token introspection). That's a strength: the server can revoke it instantly.",
        )}</p>
      </div>`;
    }

    const [h, p, s] = decoded.parts;
    return `<div class="tok">
      <div class="tok-head">
        <div class="tok-label">${esc(label)}</div>
        <button class="tok-tamper" data-token="${esc(value)}">${t('ins.tamper')} &rarr;</button>
      </div>
      <pre class="wire jwt"><span class="jwt-h">${esc(h)}</span>.<span class="jwt-p">${esc(p)}</span>.<span class="jwt-s">${esc(s)}</span></pre>
      <div class="tok-section"><span class="dot jwt-h"></span>Header</div>
      ${this.renderClaims(decoded.header as Record<string, unknown>, 'header')}
      <div class="tok-section"><span class="dot jwt-p"></span>Payload</div>
      ${this.renderClaims(decoded.claims as Record<string, unknown>, 'claim')}
      <div class="tok-section"><span class="dot jwt-s"></span>${tr('Signature (chữ ký)', 'Signature')}</div>
      ${this.renderChecks()}
    </div>`;
  }

  private renderClaims(obj: Record<string, unknown>, table: 'claim' | 'header'): string {
    return `<div class="claims">${Object.entries(obj)
      .map(([k, v]) => {
        const doc = claimDoc(k, table);
        const val = typeof v === 'object' ? JSON.stringify(v) : String(v);
        const time = ['exp', 'iat', 'nbf', 'auth_time'].includes(k) ? ` <span class="claim-abs">${new Date(Number(v) * 1000).toISOString().slice(11, 19)}Z</span>` : '';
        return `<div class="claim${doc ? ' has-doc' : ''}">
          <div class="claim-row"><code class="claim-k">${esc(k)}</code><span class="claim-v">${esc(val)}</span>${time}</div>
          ${doc ? `<div class="claim-doc"><strong>${esc(doc.title)}</strong> &mdash; ${esc(doc.why)}</div>` : ''}
        </div>`;
      })
      .join('')}</div>`;
  }

  private renderChecks(): string {
    const v = this.verification;
    if (!v) {
      return `<p class="tok-hint">${tr(
        'Chặng này không có ai verify token. Bản thân mấy byte chữ ký không nói lên điều gì - JWT chỉ đáng tin sau khi có server đối chiếu nó với public key đã công bố. Đi tới chặng của Resource API để xem đủ các phép kiểm tra chạy.',
        'No one verified the token at this hop. The signature bytes alone say nothing — a JWT is only trustworthy after a server checks it against a published public key. Go to the Resource API hop to see every check run.',
      )}</p>`;
    }
    const rows = v.checks
      .map(
        (c: Check) =>
          `<div class="check ${c.ok ? 'ok' : 'bad'}"><span class="check-mark">${c.ok ? '+' : '!'}</span><code>${esc(c.name)}</code><span class="check-detail">${esc(c.detail)}</span></div>`,
      )
      .join('');
    return `<div class="checks ${v.valid ? 'all-ok' : 'has-fail'}">
      <div class="checks-head">${v.valid ? tr('Chấp nhận', 'Accepted') : tr('Từ chối', 'Rejected')} &middot; ${tr(`đạt ${v.checks.filter((c) => c.ok).length}/${v.checks.length} phép kiểm tra`, `${v.checks.filter((c) => c.ok).length}/${v.checks.length} checks passed`)}</div>
      ${rows}
    </div>`;
  }
}
