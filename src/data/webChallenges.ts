import type { Challenge } from './challenges';

/**
 * Track OWASP: năm lỗ web kinh điển ngoài phạm vi Auth/IAM. Cùng vòng "tấn công
 * rồi phòng ngừa" như các thử thách khai thác khác — khai thác cho ra kết quả,
 * rồi vá bằng lệnh harden và xác nhận cùng payload đó bị chặn.
 *
 * Tất cả chạy trên web app dễ tổn thương (lệnh `app` trong console).
 */

const log = (c: { log: unknown[] }) => c.log as { cmd: string; ok: boolean; status?: number; data: Record<string, unknown> }[];

/** Có một lệnh khai thác thành công TRƯỚC khi vá, và cùng lệnh đó bị chặn SAU khi vá. */
const exploitedThenPatched = (
  c: { log: unknown[] },
  cmd: string,
  exploited: (e: { status?: number; data: Record<string, unknown> }) => boolean,
  hardenName: string,
  blocked: (e: { status?: number; data: Record<string, unknown> }) => boolean,
): { didExploit: boolean; didPatch: boolean } => {
  const l = log(c);
  const hardenIdx = l.findIndex((e) => e.cmd === 'harden' && e.data['name'] === hardenName && (e.data['value'] === 'on' || e.data['value'] === 'true'));
  const didExploit = l.some((e, i) => e.cmd === cmd && exploited(e) && (hardenIdx < 0 || i < hardenIdx));
  const didPatch = hardenIdx >= 0 && l.slice(hardenIdx).some((e) => e.cmd === cmd && blocked(e));
  return { didExploit, didPatch };
};

export const WEB_CHALLENGES: Challenge[] = [
  {
    id: 'web-sqli',
    title: 'Khai thác: SQL injection',
    difficulty: 2,
    mode: 'console',
    flow: 'authcode',
    setupPosture: (h) => h('sqli', 'off'),
    brief:
      'Form đăng nhập của web app dựng câu SQL bằng cách nối chuỗi. Đăng nhập với quyền admin mà KHÔNG biết ' +
      'mật khẩu, rồi rò rỉ toàn bộ mật khẩu qua ô tìm kiếm. Sau đó bật truy vấn tham số hoá và cho thấy cùng ' +
      'payload đó vô dụng.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'bypass',
        text: 'Đăng nhập admin không cần mật khẩu (auth bypass)',
        check: (c) => log(c).some((e) => e.cmd === 'app login' && e.data['bypassed'] === true),
      },
      {
        id: 'exfil',
        text: 'Rò rỉ mật khẩu qua UNION ở ô tìm kiếm',
        check: (c) => log(c).some((e) => e.cmd === 'app search' && e.data['exfiltrated'] === true),
      },
      {
        id: 'patched',
        text: 'Vá (harden sqli on), sau đó login injection bị từ chối (401)',
        check: (c) => exploitedThenPatched(c, 'app login', (e) => e.data['bypassed'] === true, 'sqli', (e) => e.status === 401).didPatch,
      },
    ],
    hints: [
      'app login "admin\'--" "x"  — dấu \' đóng chuỗi username, -- comment nốt phần kiểm tra mật khẩu.',
      'app search "x%\' UNION SELECT password FROM users --"  — nối kết quả bảng users vào danh sách bài viết.',
      'Vá: harden sqli on. Rồi app login "admin\'--" "x" lại — giờ nó là 401.',
    ],
    debrief:
      'Cách vá gốc rễ không phải lọc dấu nháy, mà là KHÔNG nối input vào câu lệnh. Truy vấn tham số hoá gửi ' +
      'câu lệnh và dữ liệu qua hai đường riêng, nên input không bao giờ được diễn giải là SQL. Trong .NET đó là ' +
      'tham số hoá (Dapper/EF Core) — đừng bao giờ dựng SQL bằng string interpolation.',
  },

  {
    id: 'web-xss',
    title: 'Khai thác: stored XSS',
    difficulty: 2,
    mode: 'console',
    flow: 'authcode',
    setupPosture: (h) => h('xss', 'off'),
    brief:
      'Trang bình luận nhúng thẳng văn bản người dùng vào HTML. Gài một bình luận chứa <script>, render trang, ' +
      'và cho thấy script chạy trong trình duyệt nạn nhân. Rồi bật escape đầu ra và render lại.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'fired',
        text: 'Payload <script> thực thi khi render (stored XSS)',
        check: (c) => log(c).some((e) => e.cmd === 'app render' && e.data['xssFired'] === true),
      },
      {
        id: 'patched',
        text: 'Vá (harden xss on), render lại thì payload KHÔNG còn chạy',
        check: (c) => {
          const l = log(c);
          const hardenIdx = l.findIndex((e) => e.cmd === 'harden' && e.data['name'] === 'xss' && e.data['value'] === 'on');
          return hardenIdx >= 0 && l.slice(hardenIdx).some((e) => e.cmd === 'app render' && e.data['xssFired'] === false && e.data['hadPayload'] === true);
        },
      },
    ],
    hints: [
      'app comment "<script>steal(document.cookie)</script>"  — lưu payload.',
      'app render  — trang nhúng thô nên script chạy.',
      'Vá: harden xss on. app render lại — payload hiện ra dưới dạng &lt;script&gt;, không chạy.',
    ],
    debrief:
      'XSS được vá ở đầu RA, không phải đầu vào: escape dữ liệu theo đúng ngữ cảnh (HTML, attribute, JS) ngay ' +
      'khi render. Đừng tin "đã lọc lúc lưu" — cùng một dữ liệu có thể hiển thị ở nhiều ngữ cảnh khác nhau. ' +
      'Kèm CSP để giảm thiệt hại khi có sót.',
  },

  {
    id: 'web-ssrf',
    title: 'Khai thác: SSRF tới cloud metadata',
    difficulty: 3,
    mode: 'console',
    flow: 'authcode',
    setupPosture: (h) => h('ssrf', 'off'),
    brief:
      'Tính năng "xem trước ảnh từ URL" để server tự đi fetch URL người dùng đưa. Ép nó gọi tới endpoint ' +
      'metadata nội bộ của cloud (169.254.169.254) và lấy credential tạm thời. Rồi bật guard và cho thấy bị chặn.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'metadata',
        text: 'Chạm được endpoint metadata và lấy credential',
        check: (c) => log(c).some((e) => e.cmd === 'app fetch' && e.data['reachedInternal'] === true && e.data['kind'] === 'metadata'),
      },
      {
        id: 'patched',
        text: 'Vá (harden ssrf on), cùng URL đó bị chặn (403)',
        check: (c) => exploitedThenPatched(c, 'app fetch', (e) => e.data['reachedInternal'] === true, 'ssrf', (e) => e.status === 403).didPatch,
      },
    ],
    hints: [
      'app fetch "http://169.254.169.254/latest/meta-data/iam/security-credentials/"  — địa chỉ link-local của cloud metadata.',
      'Khi guard tắt, server đi tới bất kỳ đâu — kể cả mạng nội bộ mà internet không với tới.',
      'Vá: harden ssrf on. Fetch lại URL đó — 403 vì host nằm trong dải link-local.',
    ],
    debrief:
      'SSRF biến server thành proxy tấn công mạng nội bộ. Vá bằng cách phân giải host rồi từ chối loopback, ' +
      'private (10/8, 172.16/12, 192.168/16) và link-local (169.254/16) — kiểm TRÊN IP đã phân giải, không phải ' +
      'chuỗi URL (tránh né bằng DNS rebinding, redirect, hay biểu diễn IP lạ). Tốt nhất là allowlist đích.',
  },

  {
    id: 'web-traversal',
    title: 'Khai thác: path traversal',
    difficulty: 2,
    mode: 'console',
    flow: 'authcode',
    setupPosture: (h) => h('traversal', 'off'),
    brief:
      'Endpoint tải file nối tên file người dùng vào thư mục web mà không kiểm tra. Dùng chuỗi ../ để đọc ' +
      'một tệp bí mật ngoài thư mục web (ví dụ /etc/passwd hoặc file secrets). Rồi bật giam đường dẫn và thử lại.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'escaped',
        text: 'Đọc được tệp NGOÀI thư mục web bằng ../',
        check: (c) => log(c).some((e) => e.cmd === 'app download' && e.data['escaped'] === true && e.status === 200),
      },
      {
        id: 'patched',
        text: 'Vá (harden traversal on), cùng đường dẫn đó bị chặn (403)',
        check: (c) => exploitedThenPatched(c, 'app download', (e) => e.data['escaped'] === true && e.status === 200, 'traversal', (e) => e.status === 403).didPatch,
      },
    ],
    hints: [
      'app download "../../../etc/passwd"  — mỗi ../ leo lên một cấp khỏi thư mục web.',
      'app download "../../app/config/secrets.env"  — hoặc nhắm thẳng file secrets.',
      'Vá: harden traversal on. Cùng đường dẫn đó giờ 403 vì bị chuẩn hoá rồi kiểm tra biên.',
    ],
    debrief:
      'Path traversal vá bằng cách CHUẨN HOÁ đường dẫn trước (giải hết ../), rồi kiểm tra kết quả có nằm trong ' +
      'thư mục gốc cho phép không — kiểm sau khi chuẩn hoá, không phải trước. Lọc chuỗi "../" thô là không đủ ' +
      '(có encoding, ....//, đường dẫn tuyệt đối). Tốt nhất là ánh xạ tên file sang một allowlist id.',
  },

  {
    id: 'web-cmdi',
    title: 'Khai thác: command injection',
    difficulty: 3,
    mode: 'console',
    flow: 'authcode',
    setupPosture: (h) => h('cmdi', 'off'),
    brief:
      'Công cụ "kiểm tra kết nối" chạy ping bằng cách nối host người dùng vào chuỗi shell. Chèn một lệnh thứ ' +
      'hai để đọc /etc/shadow. Rồi chuyển sang truyền tham số dạng mảng và cho thấy payload bị vô hiệu.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'injected',
        text: 'Chèn và chạy được lệnh thứ hai (RCE)',
        check: (c) => log(c).some((e) => e.cmd === 'app ping' && e.data['injected'] === true),
      },
      {
        id: 'patched',
        text: 'Vá (harden cmdi on), cùng payload bị từ chối (400)',
        check: (c) => exploitedThenPatched(c, 'app ping', (e) => e.data['injected'] === true, 'cmdi', (e) => e.status === 400).didPatch,
      },
    ],
    hints: [
      'app ping "8.8.8.8; cat /etc/shadow"  — dấu ; kết thúc lệnh ping rồi chạy lệnh của bạn.',
      'Cũng thử: app ping "8.8.8.8 && whoami"  hoặc  app ping "$(id)".',
      'Vá: harden cmdi on. Cùng payload giờ 400 vì host được truyền như tham số mảng, không qua shell.',
    ],
    debrief:
      'Command injection biến mất khi KHÔNG có shell để chèn: dùng execFile/exec với mảng tham số ' +
      '(["ping","-c1",host]) thay vì dựng một chuỗi cho sh -c. Nếu buộc phải qua shell, validate đầu vào theo ' +
      'allowlist chặt (chỉ hostname/IP). Lọc ký tự đen là cuộc đua thua sẵn.',
  },
];
