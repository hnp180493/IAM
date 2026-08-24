import { CHAPTERS, LESSONS, type Lesson } from '../data/lessons';
import { CHALLENGES, type Challenge } from '../data/challenges';
import { t, getLang, setLang, onLangChange } from '../i18n';
import {
  lessonTitle, lessonTagline, lessonQuestion, challengeTitle, challengeBrief,
  chapterTitle, chapterBlurb, challengeSectionTitle,
} from '../i18n/content';

/**
 * Màn hình đầu tiên. k8sgames làm đúng một việc ở đây: cho thấy toàn bộ nội
 * dung có những gì, rồi vào chơi trong một click. Không có màn hình cấu hình
 * nào chen giữa.
 */
export class Menu {
  private root: HTMLElement;
  onPick?: (lesson: Lesson) => void;
  onPickChallenge?: (challenge: Challenge) => void;
  onPickRedTeam?: () => void;
  /**
   * id các thử thách đã giải. Lưu vào localStorage, vì mất tiến độ mỗi lần tải
   * lại trang là lý do chính đáng để bỏ giữa chừng.
   */
  solved = Menu.loadSolved();

  private static readonly STORE = 'iamlab.solved';

  static loadSolved(): Set<string> {
    try {
      const raw = localStorage.getItem(Menu.STORE);
      return new Set<string>(raw ? (JSON.parse(raw) as string[]) : []);
    } catch {
      return new Set<string>();
    }
  }

  markSolved(id: string): void {
    this.solved.add(id);
    try {
      localStorage.setItem(Menu.STORE, JSON.stringify([...this.solved]));
    } catch {
      // Trình duyệt chặn localStorage thì thôi, không phải lỗi đáng chặn app.
    }
  }

  constructor(root: HTMLElement) {
    this.root = root;
    this.render();
    // Đổi ngôn ngữ thì vẽ lại menu.
    onLangChange(() => this.render());
  }

  /** Public vì menu phải vẽ lại khi số thử thách đã giải thay đổi. */
  render(): void {
    const ready = LESSONS.filter((l) => l.status === 'ready').length;
    const solvedCount = CHALLENGES.filter((c) => this.solved.has(c.id)).length;
    this.root.innerHTML = `
      <div class="menu-inner">
        <header class="menu-head">
          <div class="menu-top">
            <div class="menu-title"><span class="hud-logo">ID</span> IAM Lab</div>
            <button class="lang-toggle" id="lang-toggle" title="${t('lang.title')}">${t('lang.label')}</button>
          </div>
          <p class="menu-sub">${t('menu.sub')}</p>
          <div class="menu-count">${CHALLENGES.length} ${t('menu.count.challenges')} (${t('menu.count.solved')} ${solvedCount}) &middot; ${ready} ${t('menu.count.lessons')}</div>
        </header>
        ${this.redTeamSection()}
        ${this.challengeSection('ex', 'Khai thác lỗ hổng', t('sec.exploit'))}
        ${this.challengeSection('cc', 'Thử thách gõ tay', t('sec.console'))}
        ${this.challengeSection('ch', 'Thử thách cấu hình', t('sec.knobs'))}
        ${CHAPTERS.map((c) => this.chapter(c.id, c.title, c.blurb)).join('')}
        <footer class="menu-foot">${t('menu.foot')}</footer>
      </div>`;

    this.root.querySelector('#lang-toggle')?.addEventListener('click', () => setLang(getLang() === 'vi' ? 'en' : 'vi'));
    this.root.querySelector('#rt-enter')?.addEventListener('click', () => this.onPickRedTeam?.());

    // Bấm tiêu đề để mở/đóng. Mặc định đóng, trừ Red Team (chỉ một thẻ).
    for (const head of this.root.querySelectorAll<HTMLElement>('.chapter-head[data-collapsible]')) {
      head.addEventListener('click', () => head.closest('.menu-chapter')!.classList.toggle('collapsed'));
    }

    for (const card of this.root.querySelectorAll<HTMLElement>('.ch-card[data-ch]')) {
      card.addEventListener('click', () => {
        const c = CHALLENGES.find((x) => x.id === card.dataset['ch']);
        if (c) this.onPickChallenge?.(c);
      });
    }

    for (const card of this.root.querySelectorAll<HTMLElement>('.lesson-card[data-id]')) {
      card.addEventListener('click', () => {
        const lesson = LESSONS.find((l) => l.id === card.dataset['id']);
        if (lesson && lesson.status === 'ready') this.onPick?.(lesson);
      });
    }
  }

  /**
   * Thử thách đứng trước bài học, cố ý. Người học vào lab để làm, không phải để
   * đọc - và cái gì đứng đầu trang thì được bấm.
   */
  /** Chế độ vô hạn, đứng riêng vì nó không phải một bài có đáp án. */
  private redTeamSection(): string {
    return `
      <section class="menu-chapter">
        <div class="chapter-head">
          <span class="chapter-num">${t('menu.section.mode')}</span>
          <h2>Red Team</h2>
          <span class="chapter-blurb">${t('rt.card.blurb')}</span>
        </div>
        <div class="lesson-grid">
          <article class="lesson-card rt-card" id="rt-enter">
            <div class="lesson-q">${t('rt.card.q')}</div>
            <h3>Red Team</h3>
            <p>${t('rt.card.p')}</p>
            <div class="lesson-foot"><span class="badge-go">${t('rt.enter')} &rarr;</span></div>
          </article>
        </div>
      </section>`;
  }

  /** Một nhóm thử thách theo tiền tố id (ex- / cc- / ch-). Mặc định đóng. */
  private challengeSection(prefix: string, title: string, blurb: string): string {
    const items = CHALLENGES.filter((c) => c.id.startsWith(`${prefix}-`));
    if (!items.length) return '';
    const done = items.filter((c) => this.solved.has(c.id)).length;
    return `
      <section class="menu-chapter ch-section collapsed">
        <div class="chapter-head" data-collapsible>
          <span class="chapter-caret">▸</span>
          <span class="chapter-num">${t('menu.section.practice')}</span>
          <h2>${challengeSectionTitle(prefix, title)}</h2>
          <span class="chapter-blurb">${blurb}</span>
          <span class="chapter-badge">${done}/${items.length}</span>
        </div>
        <div class="lesson-grid">${items.map((c) => this.chCard(c)).join('')}</div>
      </section>`;
  }

  private chCard(c: Challenge): string {
    const done = this.solved.has(c.id);
    return `
      <article class="lesson-card ch-card ${done ? 'is-done' : ''}" data-ch="${c.id}">
        <div class="ch-top">
          <span class="ch-diff">${'●'.repeat(c.difficulty)}${'○'.repeat(3 - c.difficulty)}</span>
          ${done ? `<span class="ch-done">${t('card.done')}</span>` : ''}
        </div>
        <h3>${challengeTitle(c)}</h3>
        <p>${challengeBrief(c).slice(0, 105)}...</p>
        <div class="lesson-foot"><span class="badge-go">${done ? t('card.redo') : t('card.start')} &rarr;</span></div>
      </article>`;
  }

  private chapter(id: number, title: string, blurb: string): string {
    const items = LESSONS.filter((l) => l.chapter === id);
    if (!items.length) return '';
    const ready = items.filter((l) => l.status === 'ready').length;
    return `
      <section class="menu-chapter collapsed">
        <div class="chapter-head" data-collapsible>
          <span class="chapter-caret">▸</span>
          <span class="chapter-num">${t('menu.chapter')} ${id}</span>
          <h2>${chapterTitle(id, title)}</h2>
          <span class="chapter-blurb">${chapterBlurb(id, blurb)}</span>
          <span class="chapter-badge">${ready} ${t('menu.lessonsWord')}</span>
        </div>
        <div class="lesson-grid">${items.map((l) => this.card(l)).join('')}</div>
      </section>`;
  }

  private card(l: Lesson): string {
    const soon = l.status === 'soon';
    return `
      <article class="lesson-card ${soon ? 'is-soon' : ''}" data-id="${l.id}">
        <div class="lesson-q">${lessonQuestion(l)}</div>
        <h3>${lessonTitle(l)}</h3>
        <p>${lessonTagline(l)}</p>
        <div class="lesson-foot">${soon ? `<span class="badge-soon">${t('card.soon')}</span>` : `<span class="badge-go">${t('card.openLesson')} &rarr;</span>`}</div>
      </article>`;
  }

  show(): void {
    this.root.style.display = 'block';
  }

  hide(): void {
    this.root.style.display = 'none';
  }
}
