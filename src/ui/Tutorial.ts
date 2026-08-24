import { GLOSSARY, glossaryTerm } from '../data/glossary';
import type { Lesson } from '../data/lessons';
import { t } from '../i18n';
import { lessonTitle, lessonTagline, lessonGoal, lessonSteps, lessonWatch } from '../i18n/content';

/**
 * Overlay hiện trước khi vào bài. k8sgames có cái này cho từng mode và nó là
 * thứ mình đã bỏ sót ở lần đầu: không có nó thì người học bị quăng thẳng vào
 * một cái dropdown ghi "S256 / plain / none" mà không hiểu đó là gì.
 */
export class Tutorial {
  private root: HTMLElement;
  onStart?: () => void;
  onBack?: () => void;

  constructor(root: HTMLElement) {
    this.root = root;
    this.root.style.display = 'none';
  }

  show(lesson: Lesson): void {
    this.root.style.display = 'grid';
    this.root.innerHTML = `
      <div class="tut-card">
        <div class="tut-kicker">${t('menu.chapter')} ${lesson.chapter}</div>
        <h1>${lessonTitle(lesson)}</h1>
        <p class="tut-tagline">${lessonTagline(lesson)}</p>

        <div class="tut-block">
          <h4>${t('tut.goal')}</h4>
          <p>${lessonGoal(lesson)}</p>
        </div>

        ${
          lesson.terms.length
            ? `<div class="tut-block">
                 <h4>${t('tut.terms')}</h4>
                 <dl class="tut-terms">
                   ${lesson.terms
                     .map((key) => {
                       const g = GLOSSARY[key];
                       return g ? `<dt>${g.term}</dt><dd>${glossaryTerm(key, 'short')}<span class="tut-long">${glossaryTerm(key, 'long')}</span></dd>` : '';
                     })
                     .join('')}
                 </dl>
                 <div class="tut-hint">${t('tut.termsHint')}</div>
               </div>`
            : ''
        }

        ${
          lessonSteps(lesson).length
            ? `<div class="tut-block">
                 <h4>${t('tut.steps')}</h4>
                 <ol class="tut-steps">${lessonSteps(lesson).map((s) => `<li>${s}</li>`).join('')}</ol>
               </div>`
            : ''
        }

        ${
          lessonWatch(lesson)
            ? `<div class="tut-block tut-watch">
                 <h4>${t('tut.watch')}</h4>
                 <p>${lessonWatch(lesson)}</p>
               </div>`
            : ''
        }

        <div class="tut-actions">
          <button class="btn-ghost" id="tut-back">${t('tut.back')}</button>
          <button class="btn-primary" id="tut-start">${t('tut.start')}</button>
        </div>
      </div>`;

    this.root.querySelector('#tut-start')!.addEventListener('click', () => {
      this.hide();
      this.onStart?.();
    });
    this.root.querySelector('#tut-back')!.addEventListener('click', () => {
      this.hide();
      this.onBack?.();
    });
  }

  hide(): void {
    this.root.style.display = 'none';
  }
}
