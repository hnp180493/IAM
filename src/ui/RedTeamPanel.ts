import { t } from '../i18n';
import type { RedTeamState } from '../engine/RedTeamEngine';
import { attackName, attackSymptom, attackExplain } from '../data/attacks';
import { onLangChange, tr } from '../i18n';

/**
 * Bảng điều khiển Red Team mode: đồng hồ, thanh toàn vẹn, điểm, và danh sách
 * cảnh báo đang mở.
 *
 * Cảnh báo chỉ nói TRIỆU CHỨNG, không nói cách sửa - muốn biết cách sửa thì phải
 * tự chạy audit, hoặc mở gợi ý và mất điểm thời gian.
 */
export class RedTeamPanel {
  private root: HTMLElement;
  private expanded = new Set<string>();
  private lastState: RedTeamState | null = null;

  onBack?: () => void;
  onStart?: () => void;

  constructor(root: HTMLElement) {
    this.root = root;
    this.root.style.display = 'none';
    onLangChange(() => this.render(this.lastState));
  }

  open(): void {
    this.root.style.display = 'block';
    this.render(null);
  }

  close(): void {
    this.root.style.display = 'none';
  }

  render(s: RedTeamState | null): void {
    this.lastState = s;
    if (!s || !s.running && s.elapsedSec === 0) {
      this.root.innerHTML = `
        <div class="cp-head">
          <button class="hud-back" id="rt-back">&larr; ${t('cp.back')}</button>
        </div>
        <h2 class="cp-title">${t('rtp.title')}</h2>
        <p class="cp-brief">${t('rtp.intro')}</p>
        <div class="rt-brief-list">
          <div><code>audit</code> — ${t('rtp.detect')}</div>
          <div><code>status</code></div>
          <div><code>harden &lt;setting&gt; on</code> — ${t('rtp.fix')}</div>
        </div>
        <button class="btn-primary cp-run" id="rt-start">${t('rtp.start')}</button>`;
      this.bind();
      return;
    }

    const bar = Math.max(0, Math.min(100, s.integrity));
    const tone = bar > 60 ? 'good' : bar > 30 ? 'warn' : 'bad';

    this.root.innerHTML = `
      <div class="cp-head">
        <button class="hud-back" id="rt-back">&larr; ${t('cp.back')}</button>
        <div class="rt-clock">${String(Math.floor(s.elapsedSec / 60)).padStart(2, '0')}:${String(s.elapsedSec % 60).padStart(2, '0')}</div>
      </div>

      <div class="rt-stats">
        <div class="rt-stat"><span>${t('rtp.integrity')}</span><b class="rt-${tone}">${bar}</b></div>
        <div class="rt-stat"><span>${t('rtp.score')}</span><b>${s.score}</b></div>
        <div class="rt-stat"><span>${t('rtp.patched')}</span><b>${s.neutralized}</b></div>
      </div>
      <div class="rt-bar"><div class="rt-bar-fill rt-${tone}" style="width:${bar}%"></div></div>

      ${
        s.gameOver
          ? `<div class="rt-over">
               <div class="rt-over-title">${t('rtp.over')}</div>
               <p>${s.elapsedSec}s · ${s.neutralized} ${t('rtp.patched').toLowerCase()} · ${s.score} ${t('rtp.score').toLowerCase()}</p>
               <button class="btn-primary" id="rt-start">${t('rtp.replay')}</button>
             </div>`
          : ''
      }

      <div class="cp-section">${t('rtp.active')} <span class="cp-progress">${s.active.length}</span></div>
      ${
        s.active.length
          ? s.active
              .map((a) => {
                const age = s.elapsedSec - a.spawnedAtSec;
                const grace = Math.max(0, a.graceSec - age);
                const open = this.expanded.has(a.def.id);
                return `<div class="rt-alert sev-${a.def.severity}" data-alert="${a.def.id}">
                  <div class="rt-alert-top">
                    <span class="rt-sev">${'●'.repeat(a.def.severity)}</span>
                    <span class="rt-name">${attackName(a.def)}</span>
                    <span class="rt-age">${grace > 0 ? tr(`còn ${grace}s`, `${grace}s left`) : `-${a.def.drain}/s`}</span>
                  </div>
                  <div class="rt-symptom">${attackSymptom(a.def)}</div>
                  ${
                    open
                      ? `<div class="rt-help">
                           <div>${t('rtp.detect')}: <code>${a.def.detect}</code></div>
                           <div>${t('rtp.fix')}: <code>${a.def.fix}</code></div>
                           <div class="rt-why">${attackExplain(a.def)}</div>
                         </div>`
                      : `<button class="rt-hint-btn">${t('rtp.openHint')}</button>`
                  }
                </div>`;
              })
              .join('')
          : `<div class="rt-clean">${t('rtp.clean')}</div>`
      }

      <div class="cp-section">${t('rtp.feed')}</div>
      <div class="rt-feed">
        ${s.feed
          .map(
            (f) =>
              `<div class="rt-feed-line rt-f-${f.tone}"><span class="rt-feed-t">${String(Math.floor(f.atSec / 60)).padStart(2, '0')}:${String(f.atSec % 60).padStart(2, '0')}</span> ${f.text}</div>`,
          )
          .join('')}
      </div>`;
    this.bind();
  }

  private bind(): void {
    this.root.querySelector('#rt-back')?.addEventListener('click', () => this.onBack?.());
    this.root.querySelector('#rt-start')?.addEventListener('click', () => {
      this.expanded.clear();
      this.onStart?.();
    });
    for (const btn of this.root.querySelectorAll<HTMLButtonElement>('.rt-hint-btn')) {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = (btn.closest('[data-alert]') as HTMLElement | null)?.dataset['alert'];
        if (id) this.expanded.add(id);
      });
    }
  }
}
