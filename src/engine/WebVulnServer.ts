import { tr } from '../i18n';

/**
 * Một web app CỐ TÌNH dễ tổn thương, mô phỏng năm lỗ OWASP kinh điển nằm ngoài
 * phạm vi Auth/IAM: SQL injection, XSS, SSRF, path traversal, command injection.
 *
 * Mỗi lỗ có một cờ phòng thủ thật trong Posture. Tắt cờ = lỗ mở, payload chạy
 * được thật; bật cờ = lỗ đóng, cùng payload đó bị chặn. Không có gì chỉ để trưng:
 * server này thực sự "diễn giải" payload đủ để cho thấy vì sao nó nguy hiểm.
 */

export interface WebVulnFlags {
  /** Dùng tham số hoá truy vấn (chống SQL injection). */
  paramQueries: boolean;
  /** Escape HTML khi render dữ liệu người dùng (chống XSS). */
  escapeOutput: boolean;
  /** Chặn địa chỉ nội bộ / metadata khi fetch (chống SSRF). */
  ssrfGuard: boolean;
  /** Giam đường dẫn trong thư mục gốc (chống path traversal). */
  pathConfine: boolean;
  /** Truyền tham số dạng mảng, không nối chuỗi shell (chống command injection). */
  cmdSafeArgs: boolean;
}

export const WEB_HARDENED: WebVulnFlags = {
  paramQueries: true,
  escapeOutput: true,
  ssrfGuard: true,
  pathConfine: true,
  cmdSafeArgs: true,
};

export interface WebResult {
  status: number;
  /** Dữ liệu có cấu trúc để mục tiêu thử thách kiểm tra. */
  data: Record<string, unknown>;
  /** Các dòng in ra console. */
  lines: { text: string; tone: 'out' | 'dim' | 'ok' | 'err' | 'warn' }[];
}

// --- "Cơ sở dữ liệu" tí hon, đủ để injection có cái để lấy ------------------

interface UserRow {
  id: number;
  username: string;
  password: string;
  role: string;
}

const USERS: UserRow[] = [
  { id: 1, username: 'alice', password: 'correct-horse-battery-staple', role: 'user' },
  { id: 2, username: 'admin', password: 'S3cr3t-Adm1n-Pw!', role: 'admin' },
];

const ARTICLES = ['Welcome to the portal', 'Q3 roadmap', 'Office party photos'];

// --- Hệ thống tệp ảo cho path traversal ------------------------------------

const FS: Record<string, string> = {
  '/var/www/public/index.html': '<h1>Public site</h1>',
  '/var/www/public/logo.svg': '<svg>...</svg>',
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:...',
  '/app/config/secrets.env': 'DB_PASSWORD=prod-db-pw-8813\nJWT_SIGNING_KEY=hunter2',
};
const WEB_ROOT = '/var/www/public';

export class WebVulnServer {
  constructor(private getFlags: () => WebVulnFlags) {}

  private flags(): WebVulnFlags {
    return this.getFlags();
  }

  // ------------------------------------------------------ SQL injection

  /** Đăng nhập: query nối chuỗi vs tham số hoá. */
  login(username: string, password: string): WebResult {
    const safe = this.flags().paramQueries;

    if (safe) {
      const row = USERS.find((u) => u.username === username && u.password === password);
      const query = `SELECT * FROM users WHERE username = ? AND password = ?  -- params: [${username}, ${'*'.repeat(password.length)}]`;
      if (row) {
        return this.ok('app login', 200, { bypassed: false, safe: true, role: row.role }, [
          { text: query, tone: 'dim' },
          { text: tr('200 OK — đăng nhập đúng bằng mật khẩu thật.', '200 OK — logged in correctly with the real password.'), tone: 'ok' },
          { text: tr(`Vai trò: ${row.role}. Truy vấn tham số hoá coi input là DỮ LIỆU, không phải mã.`, `Role: ${row.role}. A parameterized query treats input as DATA, never as code.`), tone: 'dim' },
        ]);
      }
      return this.ok('app login', 401, { bypassed: false, safe: true }, [
        { text: query, tone: 'dim' },
        { text: tr('401 — sai mật khẩu. Payload injection cũng chỉ là một chuỗi username vô nghĩa.', '401 — wrong password. An injection payload is just a meaningless username string here.'), tone: 'err' },
      ]);
    }

    // Lỗ mở: query dựng bằng nối chuỗi.
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const injected = this.evalSqlLogin(username, password);
    if (injected) {
      return this.ok('app login', 200, { bypassed: true, safe: false, role: injected.role, asUser: injected.username }, [
        { text: query, tone: 'dim' },
        { text: tr(`200 OK — VÀO ĐƯỢC dưới danh nghĩa "${injected.username}" (${injected.role}) mà KHÔNG cần mật khẩu.`, `200 OK — got IN as "${injected.username}" (${injected.role}) with NO valid password.`), tone: 'warn' },
        { text: tr("Dấu ' đóng chuỗi sớm, phần còn lại của payload trở thành logic SQL. Đây là auth bypass.", "The ' closes the string early, and the rest of the payload becomes SQL logic. This is an auth bypass."), tone: 'dim' },
      ]);
    }
    const row = USERS.find((u) => u.username === username && u.password === password);
    return this.ok('app login', row ? 200 : 401, { bypassed: false, safe: false, ...(row ? { role: row.role } : {}) }, [
      { text: query, tone: 'dim' },
      { text: row ? tr('200 OK — mật khẩu thật khớp.', '200 OK — the real password matched.') : tr('401 — payload chưa phá được query. Thử một injection khác.', "401 — the payload didn't break the query. Try a different injection."), tone: row ? 'ok' : 'err' },
    ]);
  }

  /** Tìm kiếm: chỗ để demo UNION-based exfiltration. */
  search(term: string): WebResult {
    const safe = this.flags().paramQueries;

    if (safe) {
      const hits = ARTICLES.filter((a) => a.toLowerCase().includes(term.toLowerCase().replace(/%/g, '')));
      return this.ok('app search', 200, { exfiltrated: false, safe: true, count: hits.length }, [
        { text: `SELECT title FROM articles WHERE title LIKE ?  -- param: [%${term}%]`, tone: 'dim' },
        { text: tr(`Tìm thấy ${hits.length} bài. UNION trong input chỉ là văn bản cần khớp, không phải SQL.`, `Found ${hits.length} article(s). A UNION in the input is just text to match, not SQL.`), tone: 'ok' },
        ...hits.map((h) => ({ text: `  - ${h}`, tone: 'out' as const })),
      ]);
    }

    const query = `SELECT title FROM articles WHERE title LIKE '%${term}%'`;
    // UNION SELECT ... FROM users -> lấy được mật khẩu.
    if (/union\s+select/i.test(term) && /(password|users|pass)/i.test(term)) {
      const dump = USERS.map((u) => `${u.username}:${u.password}`);
      return this.ok('app search', 200, { exfiltrated: true, safe: false, rows: dump }, [
        { text: query, tone: 'dim' },
        { text: tr('200 OK — UNION nối kết quả từ bảng users vào danh sách bài viết:', '200 OK — the UNION grafts rows from the users table onto the article list:'), tone: 'warn' },
        ...dump.map((d) => ({ text: `  - ${d}`, tone: 'err' as const })),
        { text: tr('Mật khẩu vừa rò rỉ qua một ô tìm kiếm. Đó là sức mạnh của UNION-based SQLi.', 'Passwords just leaked through a search box. That is the power of UNION-based SQLi.'), tone: 'dim' },
      ]);
    }
    const hits = ARTICLES.filter((a) => a.toLowerCase().includes(term.toLowerCase().replace(/%/g, '')));
    return this.ok('app search', 200, { exfiltrated: false, safe: false, count: hits.length }, [
      { text: query, tone: 'dim' },
      { text: tr(`Tìm thấy ${hits.length} bài. Query đang nối chuỗi — thử payload UNION SELECT.`, `Found ${hits.length} article(s). The query concatenates strings — try a UNION SELECT payload.`), tone: hits.length ? 'ok' : 'warn' },
      ...hits.map((h) => ({ text: `  - ${h}`, tone: 'out' as const })),
    ]);
  }

  /** Phát hiện injection kinh điển ở login. Trả về hàng "đăng nhập được" hoặc null. */
  private evalSqlLogin(username: string, password: string): UserRow | undefined {
    const commentAs = /^(\w+)'\s*(--|#)/.exec(username.trim());
    if (commentAs) {
      const u = USERS.find((x) => x.username === commentAs[1]);
      if (u) return u; // username='admin'-- : bỏ qua kiểm tra mật khẩu
    }
    const tautology = /'\s*or\s*'?\s*1'?\s*=\s*'?\s*1|'\s*or\s+1\s*=\s*1|'\s*or\s*'[^']*'\s*=\s*'[^']*/i;
    if (tautology.test(username) || tautology.test(password)) {
      // WHERE luôn đúng: trả về hàng đầu tiên, thường là tài khoản quyền cao nhất.
      return USERS.find((u) => u.role === 'admin') ?? USERS[0];
    }
    return undefined;
  }

  // -------------------------------------------------------------- XSS

  private comments: string[] = [];

  comment(text: string): WebResult {
    this.comments.push(text);
    return this.ok('app comment', 200, { stored: text }, [
      { text: tr(`Đã lưu bình luận (${this.comments.length} cái). Gõ: app render`, `Comment stored (${this.comments.length} total). Type: app render`), tone: 'ok' },
    ]);
  }

  render(): WebResult {
    const safe = this.flags().escapeOutput;
    if (!this.comments.length) {
      return this.ok('app render', 200, { xssFired: false }, [{ text: tr('Chưa có bình luận nào. Gõ: app comment "<text>"', 'No comments yet. Type: app comment "<text>"'), tone: 'dim' }]);
    }

    const dangerous = /<script|onerror\s*=|onload\s*=|<img[^>]+onerror|javascript:/i;
    const firing = this.comments.filter((c) => dangerous.test(c));

    if (safe) {
      const escaped = this.comments.map((c) => this.escapeHtml(c));
      return this.ok('app render', 200, { xssFired: false, safe: true, hadPayload: firing.length > 0 }, [
        { text: tr('Trang render (đã escape HTML):', 'Page rendered (HTML escaped):'), tone: 'out' },
        ...escaped.map((e) => ({ text: `  <li>${e}</li>`, tone: 'out' as const })),
        { text: firing.length
            ? tr('Payload <script> hiện ra dưới dạng văn bản, KHÔNG chạy. Trình duyệt thấy &lt;script&gt;, không phải thẻ.', 'The <script> payload shows up as literal text and does NOT run. The browser sees &lt;script&gt;, not a tag.')
            : tr('Không có payload nào; dữ liệu vẫn được escape đúng cách.', 'No payload present; the data is still escaped correctly.'),
          tone: 'dim' },
      ]);
    }

    return this.ok('app render', 200, { xssFired: firing.length > 0, safe: false }, [
      { text: tr('Trang render (nhúng thô, KHÔNG escape):', 'Page rendered (raw, NOT escaped):'), tone: 'out' },
      ...this.comments.map((c) => ({ text: `  <li>${c}</li>`, tone: (dangerous.test(c) ? 'err' : 'out') as 'err' | 'out' })),
      ...(firing.length
        ? [
            { text: tr(`⚠ ${firing.length} payload vừa THỰC THI trong trình duyệt nạn nhân.`, `⚠ ${firing.length} payload(s) just EXECUTED in the victim's browser.`), tone: 'warn' as const },
            { text: tr('Script này có thể trộm cookie phiên, gõ bàn phím, hoặc gửi request thay nạn nhân.', "This script could steal the session cookie, log keystrokes, or send requests as the victim."), tone: 'dim' as const },
          ]
        : [{ text: tr('Chưa có payload chạy được. Thử: app comment "<script>steal()</script>"', 'No executing payload yet. Try: app comment "<script>steal()</script>"'), tone: 'dim' as const }]),
    ]);
  }

  private escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ------------------------------------------------------------- SSRF

  fetch(url: string): WebResult {
    const safe = this.flags().ssrfGuard;
    let host = '';
    try {
      host = new URL(url).hostname;
    } catch {
      return this.ok('app fetch', 400, { reachedInternal: false }, [{ text: tr(`URL không hợp lệ: ${url}`, `Invalid URL: ${url}`), tone: 'err' }]);
    }

    const isMetadata = host === '169.254.169.254';
    const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0';
    const isPrivate = /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    const internal = isMetadata || isLoopback || isPrivate;

    if (safe && internal) {
      return this.ok('app fetch', 403, { reachedInternal: false, safe: true, blockedHost: host }, [
        { text: tr(`403 — chặn: ${host} nằm trong dải nội bộ/metadata.`, `403 — blocked: ${host} is in a private/metadata range.`), tone: 'ok' },
        { text: tr('Guard SSRF phân giải host rồi từ chối địa chỉ link-local, loopback và private.', 'The SSRF guard resolves the host and refuses link-local, loopback and private addresses.'), tone: 'dim' },
      ]);
    }

    if (isMetadata) {
      return this.ok('app fetch', 200, { reachedInternal: true, safe, kind: 'metadata' }, [
        { text: `GET ${url}`, tone: 'dim' },
        { text: tr('200 OK — endpoint metadata của cloud trả về credential tạm thời:', '200 OK — the cloud metadata endpoint returned temporary credentials:'), tone: 'warn' },
        { text: '  { "AccessKeyId": "ASIA...", "SecretAccessKey": "wJalr...", "Token": "IQoJb3..." }', tone: 'err' },
        { text: tr('Server tự đi lấy URL do người dùng đưa, và nó chạm được vào 169.254.169.254. Đây là SSRF cổ điển.', 'The server fetched a user-supplied URL and could reach 169.254.169.254. This is classic SSRF.'), tone: 'dim' },
      ]);
    }
    if (isLoopback || isPrivate) {
      return this.ok('app fetch', 200, { reachedInternal: true, safe, kind: 'internal' }, [
        { text: `GET ${url}`, tone: 'dim' },
        { text: tr(`200 OK — chạm được dịch vụ nội bộ ${host} (không hề lộ ra internet).`, `200 OK — reached the internal service ${host} (never exposed to the internet).`), tone: 'warn' },
        { text: '  <h1>Internal admin console</h1>', tone: 'err' },
      ]);
    }
    return this.ok('app fetch', 200, { reachedInternal: false, safe, kind: 'external' }, [
      { text: `GET ${url}`, tone: 'dim' },
      { text: tr(`200 OK — ${host} là host bên ngoài, hợp lệ.`, `200 OK — ${host} is a legitimate external host.`), tone: 'ok' },
    ]);
  }

  // --------------------------------------------------- path traversal

  download(path: string): WebResult {
    const safe = this.flags().pathConfine;
    const resolved = this.resolvePath(WEB_ROOT, path);
    const inside = resolved.startsWith(WEB_ROOT + '/') || resolved === WEB_ROOT;

    if (safe && !inside) {
      return this.ok('app download', 403, { escaped: false, safe: true, resolved }, [
        { text: tr(`Đường dẫn xin: ${path}`, `Requested path: ${path}`), tone: 'dim' },
        { text: tr(`Chuẩn hoá thành: ${resolved}`, `Canonicalized to: ${resolved}`), tone: 'dim' },
        { text: tr('403 — nằm ngoài thư mục gốc, từ chối. Guard chuẩn hoá TRƯỚC rồi mới kiểm tra.', '403 — outside the web root, refused. The guard canonicalizes FIRST, then checks.'), tone: 'ok' },
      ]);
    }

    const content = FS[resolved];
    if (content === undefined) {
      return this.ok('app download', 404, { escaped: !inside, safe }, [
        { text: tr(`404 — không có tệp ${resolved}`, `404 — no file at ${resolved}`), tone: 'err' },
      ]);
    }
    const secret = !inside;
    return this.ok('app download', 200, { escaped: secret, safe, resolved }, [
      { text: tr(`Đường dẫn xin: ${path}  ->  ${resolved}`, `Requested path: ${path}  ->  ${resolved}`), tone: 'dim' },
      { text: `200 OK`, tone: secret ? 'warn' : 'ok' },
      { text: content, tone: secret ? 'err' : 'out' },
      ...(secret
        ? [{ text: tr('Vừa đọc một tệp NGOÀI thư mục web bằng chuỗi ../ — path traversal.', 'Just read a file OUTSIDE the web root using ../ — path traversal.'), tone: 'dim' as const }]
        : []),
    ]);
  }

  /** Chuẩn hoá ../ như một hệ tệp thật, để đường dẫn thoát ra được. */
  private resolvePath(root: string, path: string): string {
    const combined = path.startsWith('/') ? path : `${root}/${path}`;
    const parts = combined.split('/');
    const stack: string[] = [];
    for (const part of parts) {
      if (part === '' || part === '.') continue;
      if (part === '..') stack.pop();
      else stack.push(part);
    }
    return '/' + stack.join('/');
  }

  // ------------------------------------------------ command injection

  ping(host: string): WebResult {
    const safe = this.flags().cmdSafeArgs;
    const metachar = /[;|&`$(){}<>\n]|\|\|/;

    if (safe) {
      if (metachar.test(host)) {
        return this.ok('app ping', 400, { injected: false, safe: true }, [
          { text: tr(`execFile("ping", ["-c1", ${JSON.stringify(host)}])`, `execFile("ping", ["-c1", ${JSON.stringify(host)}])`), tone: 'dim' },
          { text: tr('400 — host chứa ký tự không hợp lệ, từ chối. Tham số là MẢNG nên không có shell để chèn lệnh.', '400 — the host contains invalid characters, refused. Args are an ARRAY, so there is no shell to inject into.'), tone: 'ok' },
        ]);
      }
      return this.ok('app ping', 200, { injected: false, safe: true }, [
        { text: `execFile("ping", ["-c1", "${host}"])`, tone: 'dim' },
        { text: tr(`64 bytes from ${host}: time=11.4 ms`, `64 bytes from ${host}: time=11.4 ms`), tone: 'ok' },
      ]);
    }

    const cmd = `sh -c "ping -c1 ${host}"`;
    const inj = /[;&|]\s*(\S.*)|`([^`]+)`|\$\(([^)]+)\)/.exec(host);
    if (inj) {
      const payload = (inj[1] ?? inj[2] ?? inj[3] ?? '').trim();
      const output = this.fakeShell(payload);
      return this.ok('app ping', 200, { injected: true, safe: false, payload }, [
        { text: cmd, tone: 'dim' },
        { text: tr(`ping tới phần đầu chạy, rồi shell chạy TIẾP lệnh chèn: ${payload}`, `the ping runs, then the shell ALSO runs the injected command: ${payload}`), tone: 'warn' },
        { text: output, tone: 'err' },
        { text: tr('Nối chuỗi vào "sh -c" biến một ô nhập host thành thực thi lệnh tuỳ ý.', 'Concatenating into "sh -c" turns a host input box into arbitrary command execution.'), tone: 'dim' },
      ]);
    }
    return this.ok('app ping', 200, { injected: false, safe: false }, [
      { text: cmd, tone: 'dim' },
      { text: tr(`64 bytes from ${host}: time=11.4 ms`, `64 bytes from ${host}: time=11.4 ms`), tone: 'ok' },
      { text: tr('Query đang nối thẳng vào shell. Thử payload: 8.8.8.8; cat /etc/shadow', 'The command concatenates into a shell. Try a payload: 8.8.8.8; cat /etc/shadow'), tone: 'dim' },
    ]);
  }

  private fakeShell(payload: string): string {
    if (/cat\s+\/etc\/shadow/.test(payload)) return 'root:$6$rounds=...:19500:0:99999:7:::';
    if (/cat\s+\/etc\/passwd/.test(payload)) return FS['/etc/passwd']!;
    if (/whoami/.test(payload)) return 'www-data';
    if (/id\b/.test(payload)) return 'uid=33(www-data) gid=33(www-data)';
    if (/ls/.test(payload)) return 'index.html  logo.svg  ../  config/';
    return `(${payload}) -> [output]`;
  }

  private ok(cmd: string, status: number, data: Record<string, unknown>, lines: WebResult['lines']): WebResult {
    void cmd;
    return { status, data, lines };
  }

  reset(): void {
    this.comments = [];
  }
}
