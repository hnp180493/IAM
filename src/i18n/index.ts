/**
 * Đa ngôn ngữ. Thiết kế để thêm ngôn ngữ mới chỉ là thêm một bảng dịch, và mọi
 * chỗ trong UI đọc chuỗi qua t('key') hoặc pick({ vi, en }).
 *
 * Nội dung dữ liệu (bài học, thử thách, từ điển) mang cả hai ngôn ngữ trong
 * cùng một object qua kiểu Localized; thiếu bản dịch thì tự lùi về tiếng Việt.
 */
export type Lang = 'vi' | 'en';

export interface Localized {
  vi: string;
  en?: string;
}

const STORE = 'iamlab.lang';

let current: Lang = load();
const listeners = new Set<() => void>();

function load(): Lang {
  try {
    const v = localStorage.getItem(STORE);
    return v === 'en' ? 'en' : 'vi';
  } catch {
    return 'vi';
  }
}

export function getLang(): Lang {
  return current;
}

export function setLang(lang: Lang): void {
  if (lang === current) return;
  current = lang;
  try {
    localStorage.setItem(STORE, lang);
  } catch {
    // localStorage bị chặn thì thôi.
  }
  document.documentElement.setAttribute('lang', lang);
  for (const fn of [...listeners]) fn();
}

export function onLangChange(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Chọn theo ngôn ngữ hiện tại, lùi về vi nếu thiếu en. */
export function pick(text: Localized | string): string {
  if (typeof text === 'string') return text;
  return current === 'en' ? text.en ?? text.vi : text.vi;
}

/**
 * Chọn nhanh cho chuỗi sinh động (template literal có biến nội suy). Dùng ngay
 * tại chỗ tạo ra chuỗi, thay vì tra bảng theo key - vì nội dung phụ thuộc biến
 * runtime (tên user, mã lỗi, số giây...) nên không tra bảng tĩnh được.
 */
export function tr(vi: string, en: string): string {
  return current === 'en' ? en : vi;
}

/** Chuỗi UI cố định (chrome). key -> { vi, en }. */
const STRINGS: Record<string, Localized> = {
  // menu
  'menu.sub': {
    vi: 'Học xác thực và phân quyền bằng cách chạy thật rồi phá thật. Mọi token trong đây được ký bằng RSA 2048-bit sinh ngay trong máy bạn, mọi lần từ chối là một phép kiểm tra thật sự thất bại.',
    en: 'Learn authentication and authorization by running it for real, then breaking it. Every token here is signed with a 2048-bit RSA key generated in your browser; every rejection is a real check that failed.',
  },
  'menu.foot': {
    vi: 'Bấm tiêu đề để mở/đóng từng mục. Bấm vào bài nào cũng được.',
    en: 'Click a heading to open or close a section. Click any item to start.',
  },
  'menu.count.challenges': { vi: 'thử thách', en: 'challenges' },
  'menu.count.solved': { vi: 'đã giải', en: 'solved' },
  'menu.count.lessons': { vi: 'bài học', en: 'lessons' },
  'menu.section.practice': { vi: 'Thực hành', en: 'Practice' },
  'menu.section.mode': { vi: 'Chế độ', en: 'Mode' },
  'menu.chapter': { vi: 'Chương', en: 'Chapter' },
  'menu.lessonsWord': { vi: 'bài', en: 'lessons' },

  // red team card
  'rt.card.q': {
    vi: 'Cấu hình phòng thủ bị tắt từng cái một, không báo trước cái nào.',
    en: 'Defensive settings are turned off one by one, and it never tells you which.',
  },
  'rt.card.p': {
    vi: 'Dùng console phát hiện và vá trước khi toàn vẹn về 0. Vá nhanh thì nhiều điểm.',
    en: 'Use the console to detect and patch before integrity hits zero. Patch fast for more points.',
  },
  'rt.card.blurb': { vi: 'Tấn công dồn dập và leo thang. Sống được bao lâu?', en: 'Relentless, escalating attacks. How long can you last?' },
  'rt.enter': { vi: 'Vào chế độ', en: 'Enter mode' },

  // section blurbs
  'sec.exploit': { vi: 'Hack một lỗ có thật, rồi vá.', en: 'Hack a real hole, then patch it.' },
  'sec.web': { vi: 'OWASP Top 10: SQLi, XSS, SSRF, traversal, RCE.', en: 'OWASP Top 10: SQLi, XSS, SSRF, traversal, RCE.' },
  'sec.console': { vi: 'Console thật, không có đáp án để bấm thử.', en: 'A real console, no answers to click through.' },
  'sec.knobs': { vi: 'Sửa cấu hình bằng dropdown, máy kiểm tra.', en: 'Fix config with dropdowns; the machine checks.' },
  'sec.exploit.title': { vi: 'Khai thác lỗ hổng', en: 'Exploit a vulnerability' },
  'sec.web.title': { vi: 'OWASP web', en: 'OWASP web' },
  'sec.console.title': { vi: 'Thử thách gõ tay', en: 'Hands-on console challenges' },
  'sec.knobs.title': { vi: 'Thử thách cấu hình', en: 'Configuration challenges' },

  // card footers
  'card.openLesson': { vi: 'Mở bài', en: 'Open lesson' },
  'card.soon': { vi: 'đang làm', en: 'coming soon' },
  'card.done': { vi: 'đã giải', en: 'solved' },
  'card.redo': { vi: 'Làm lại', en: 'Redo' },
  'card.start': { vi: 'Bắt tay vào', en: 'Get started' },

  // tutorial
  'tut.goal': { vi: 'Mục tiêu', en: 'Goal' },
  'tut.terms': { vi: 'Thuật ngữ cần biết trước', en: 'Terms to know first' },
  'tut.termsHint': { vi: 'Hover vào từng dòng để đọc kỹ hơn.', en: 'Hover each row to read more.' },
  'tut.steps': { vi: 'Làm gì', en: 'What to do' },
  'tut.watch': { vi: 'Điều đáng chú ý nhất', en: 'The key thing to watch' },
  'tut.back': { vi: 'Quay lại danh sách', en: 'Back to list' },
  'tut.start': { vi: 'Vào bài', en: 'Start lesson' },

  // hud
  'hud.back': { vi: 'Bài học', en: 'Lessons' },
  'hud.attacker': { vi: 'Kẻ tấn công trộm code', en: 'Attacker steals the code' },
  'hud.scope': { vi: 'scope xin', en: 'scope requested' },
  'hud.apiRequires': { vi: 'API yêu cầu', en: 'API requires' },
  'hud.tokens': { vi: 'token sống', en: 'live tokens' },
  'hud.expiresIn': { vi: 'hết hạn sau', en: 'expires in' },
  'hud.run': { vi: 'Chạy luồng', en: 'Run flow' },
  'hud.reset': { vi: 'Xoá', en: 'Reset' },
  'hud.runStart': { vi: 'bấm "Chạy luồng" để bắt đầu.', en: 'press "Run flow" to begin.' },
  'hud.cleared': { vi: 'Đã xoá. Chưa phát token nào.', en: 'Cleared. No tokens issued.' },

  // inspector
  'ins.empty.title': { vi: 'Chưa chọn chặng nào', en: 'Nothing selected' },
  'ins.empty.body': {
    vi: 'Chạy luồng rồi click vào bất kỳ mũi tên nào trên sơ đồ để xem HTTP thật đã chạy trên dây, và mổ token mà chặng đó mang theo.',
    en: 'Run a flow, then click any arrow on the diagram to see the raw HTTP that crossed the wire and take apart the tokens it carried.',
  },
  'ins.hop': { vi: 'chặng', en: 'hop' },
  'ins.tab.http': { vi: 'HTTP thật', en: 'Raw HTTP' },
  'ins.tamper': { vi: 'Sửa và bắn lại', en: 'Tamper & replay' },

  // console
  'con.banner': {
    vi: 'IAM Lab console — mọi lệnh chạy trên auth server thật của lab.',
    en: 'IAM Lab console — every command runs against the lab’s real auth server.',
  },
  'con.banner2': {
    vi: 'help để xem lệnh, help <lệnh> để xem chi tiết. Tab để hoàn tất.',
    en: 'help lists commands, help <cmd> shows detail. Tab to complete.',
  },
  'con.placeholder': { vi: 'gõ help rồi Enter', en: 'type help then Enter' },

  // challenge panel
  'cp.back': { vi: 'Thử thách', en: 'Challenges' },
  'cp.knobs': { vi: 'Cấu hình bạn sửa được', en: 'Settings you can change' },
  'cp.consoleNote': {
    vi: 'Thử thách này gõ tay. Console ở dưới, gõ <code>help</code> để bắt đầu. Mục tiêu tự tick sau mỗi lệnh.',
    en: 'This challenge is hands-on. Console below — type <code>help</code> to start. Objectives tick after each command.',
  },
  'cp.objectives': { vi: 'Mục tiêu', en: 'Objectives' },
  'cp.run': { vi: 'Chạy kiểm tra', en: 'Run check' },
  'cp.running': { vi: 'Đang chạy...', en: 'Running...' },
  'cp.resetConsole': { vi: 'Xoá console và làm lại', en: 'Clear console and retry' },
  'cp.solvedTitle': { vi: 'Xong. Cả {n} mục tiêu đều đạt.', en: 'Done. All {n} objectives met.' },
  'cp.hints': { vi: 'Gợi ý', en: 'Hints' },
  'cp.openHint': { vi: 'Mở gợi ý {i}/{n}', en: 'Reveal hint {i}/{n}' },
  'cp.hintsDone': { vi: 'Đã mở hết gợi ý.', en: 'All hints revealed.' },

  // red team panel
  'rtp.title': { vi: 'Red Team', en: 'Red Team' },
  'rtp.intro': {
    vi: 'Hệ thống bắt đầu ở trạng thái siết. Cứ vài giây lại có một cấu hình phòng thủ bị tắt — và tấn công dồn dập hơn theo thời gian. Việc của bạn là phát hiện và vá bằng console trước khi toàn vẹn về 0.',
    en: 'The system starts hardened. Every few seconds a defensive setting is turned off — and attacks come faster over time. Your job: detect and patch from the console before integrity hits zero.',
  },
  'rtp.start': { vi: 'Bắt đầu', en: 'Start' },
  'rtp.replay': { vi: 'Chơi lại', en: 'Play again' },
  'rtp.integrity': { vi: 'Toàn vẹn', en: 'Integrity' },
  'rtp.score': { vi: 'Điểm', en: 'Score' },
  'rtp.patched': { vi: 'Đã vá', en: 'Patched' },
  'rtp.active': { vi: 'Đang mở', en: 'Open' },
  'rtp.clean': { vi: 'Không có cảnh báo nào. Hệ thống đang sạch.', en: 'No alerts. The system is clean.' },
  'rtp.feed': { vi: 'Diễn biến', en: 'Activity' },
  'rtp.openHint': { vi: 'Mở gợi ý', en: 'Reveal hint' },
  'rtp.detect': { vi: 'phát hiện', en: 'detect' },
  'rtp.fix': { vi: 'vá', en: 'fix' },
  'rtp.over': { vi: 'Hệ thống bị chiếm', en: 'System compromised' },

  // lang toggle
  'lang.label': { vi: 'EN', en: 'VI' },
  'lang.title': { vi: 'Switch to English', en: 'Chuyển sang Tiếng Việt' },
};

export function t(key: string, vars?: Record<string, string | number>): string {
  const entry = STRINGS[key];
  let s = entry ? pick(entry) : key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, String(v));
  return s;
}
