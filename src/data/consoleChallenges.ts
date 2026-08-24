import type { Challenge } from './challenges';

/**
 * Thử thách gõ tay. Khác biệt so với loại có dropdown: ở đây không có sẵn đáp án
 * để bấm thử, nên không brute-force được - phải biết cần gửi cái gì.
 *
 * Mục tiêu được kiểm tra từ log lệnh, tick ngay sau mỗi lệnh chứ không cần bấm
 * "chạy kiểm tra".
 */

const log = (c: { log: unknown[] }) => c.log as { cmd: string; ok: boolean; status?: number; data: Record<string, unknown> }[];
const find = (c: { log: unknown[] }, cmd: string, pred?: (e: { ok: boolean; status?: number; data: Record<string, unknown> }) => boolean) =>
  log(c).filter((e) => e.cmd === cmd && (!pred || pred(e)));

export const CONSOLE_CHALLENGES: Challenge[] = [
  {
    id: 'cc-manual',
    title: 'Tự tay đăng nhập',
    difficulty: 1,
    mode: 'console',
    flow: 'authcode',
    brief:
      'Không có nút "Chạy luồng" ở đây. Tự gõ từng bước của Authorization Code + PKCE cho tới khi ' +
      'gọi được API. Gõ help để xem lệnh.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'authorized',
        text: 'Lấy được authorization code với PKCE S256',
        check: (c) => find(c, 'authorize', (e) => e.ok && e.data['method'] === 'S256').length > 0,
      },
      {
        id: 'got-token',
        text: 'Đổi code thành access token',
        check: (c) => find(c, 'token', (e) => e.ok).length > 0,
      },
      {
        id: 'called-api',
        text: 'Gọi API thành công (200)',
        check: (c) => find(c, 'curl', (e) => e.status === 200).length > 0,
      },
    ],
    hints: [
      'Ba lệnh, theo thứ tự: authorize, token, curl.',
      'authorize mặc định đã là S256. token tự dùng code và verifier mới nhất. curl /me --token @access',
    ],
    debrief:
      'Đó là toàn bộ luồng, gõ bằng tay. Chú ý bạn không phải tự tính SHA-256 hay tự ghép JWT: ' +
      'client library làm việc đó. Nhưng bạn phải biết code_verifier tồn tại và phải giữ nó.',
  },

  {
    id: 'cc-steal',
    title: 'Đóng vai kẻ tấn công',
    difficulty: 2,
    mode: 'console',
    flow: 'authcode',
    brief:
      'Bạn là kẻ tấn công và đã đọc được URL /authorize từ log proxy. Hãy tự lấy access token của alice. ' +
      'Sau đó chứng minh cùng cách đó thất bại khi server dùng S256.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'plain-win',
        text: 'Lấy được token khi server dùng code_challenge_method=plain',
        check: (c) => {
          const plain = find(c, 'authorize', (e) => e.ok && e.data['method'] === 'plain');
          return plain.length > 0 && find(c, 'token', (e) => e.ok).length > 0;
        },
      },
      {
        id: 's256-fail',
        text: 'Với S256, trình verifier tự bịa và bị server từ chối',
        check: (c) =>
          find(c, 'authorize', (e) => e.ok && e.data['method'] === 'S256').length > 0 &&
          find(c, 'token', (e) => !e.ok && e.data['verifierGiven'] === true).length > 0,
      },
    ],
    hints: [
      'authorize --pkce plain rồi đọc code_challenge trong URL. Với plain, challenge chính là verifier.',
      'token --code <code> --verifier <chuỗi bạn đọc được từ URL>',
      'Phần hai: authorize (S256) rồi token --verifier tự-bịa. Đọc kỹ lý do server từ chối.',
    ],
    debrief:
      'Với plain, cái gọi là bí mật nằm ngay trong URL nên không bảo vệ gì. Với S256 bạn cần tìm chuỗi ' +
      'có SHA-256 bằng đúng challenge - tức là đảo ngược hàm băm. Đó là toàn bộ khác biệt giữa hai giá trị.',
  },

  {
    id: 'cc-forge',
    title: 'Làm API chấp nhận token giả',
    difficulty: 3,
    mode: 'console',
    flow: 'authcode',
    brief:
      'Bạn có một access token hợp lệ. Hãy sửa nó để leo quyền và làm API chấp nhận. ' +
      'Thử ít nhất ba hướng khác nhau và ghi nhận mỗi hướng chết ở phép kiểm tra nào.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'have-token',
        text: 'Có một access token thật để làm gốc',
        check: (c) => find(c, 'token', (e) => e.ok).length > 0,
      },
      {
        id: 'forged',
        text: 'Đã tạo ít nhất 3 token giả khác nhau',
        check: (c) => find(c, 'jwt forge').length >= 3,
      },
      {
        id: 'three-checks',
        text: 'Bị chặn bởi ít nhất 3 phép kiểm tra khác nhau',
        check: (c) => {
          const failed = new Set<string>();
          for (const e of find(c, 'curl', (x) => x.status !== 200)) {
            for (const name of (e.data['failed'] as string[] | undefined) ?? []) failed.add(name);
          }
          for (const e of find(c, 'jwt verify', (x) => !x.ok)) {
            for (const name of (e.data['failed'] as string[] | undefined) ?? []) failed.add(name);
          }
          return failed.size >= 3;
        },
      },
    ],
    hints: [
      'jwt forge @access --set roles=admin rồi curl /me --token @forged',
      'Thử tiếp: --set-header alg=none, --set exp=9999999999, --set aud=https://api-internal.example.com',
      'jwt verify @forged in ra từng phép kiểm tra, dễ đọc hơn là chỉ nhìn mã lỗi từ curl.',
    ],
    debrief:
      'Không có cách nào thắng, và đó là kết quả đúng: chữ ký phủ lên cả header và payload, còn private key ' +
      'thì chỉ auth server có. Điều đáng học là chỗ MỖI hướng tấn công chết: sửa claim chết ở signature, ' +
      'alg=none chết ở alg. Server nào bỏ một trong hai phép kiểm tra đó là server bị chiếm.',
  },

  {
    id: 'cc-diagnose',
    title: 'Chẩn đoán lỗi 403',
    difficulty: 2,
    mode: 'console',
    flow: 'authcode',
    brief:
      'Người dùng báo API trả 403 dù vừa đăng nhập xong. Tái hiện lỗi đó, tìm nguyên nhân bằng cách ' +
      'đọc token, rồi sửa cho ra 200. Phải làm đúng quy trình: tái hiện, chẩn đoán, sửa.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'reproduce',
        text: 'Tái hiện được lỗi 403',
        check: (c) => find(c, 'curl', (e) => e.status === 403).length > 0,
      },
      {
        id: 'inspect',
        text: 'Đọc token để xem nó mang scope gì',
        check: (c) => find(c, 'jwt decode').length > 0 || find(c, 'jwt verify').length > 0,
      },
      {
        id: 'fixed',
        text: 'Sau đó gọi lại và được 200',
        check: (c) => {
          const l = log(c);
          const firstFail = l.findIndex((e) => e.cmd === 'curl' && e.status === 403);
          if (firstFail < 0) return false;
          return l.slice(firstFail).some((e) => e.cmd === 'curl' && e.status === 200);
        },
      },
    ],
    hints: [
      'Tái hiện: authorize --scope "openid profile" rồi token rồi curl /me.',
      '403 khác 401: token hợp lệ nhưng thiếu quyền. Đọc claim scope bằng jwt decode @access.',
      'Sửa bằng cách xin đúng scope: authorize --scope "openid profile read:reports", rồi token, rồi curl lại.',
    ],
    debrief:
      '403 không sửa được bằng đăng nhập lại - phải xin đúng scope từ đầu. Nếu code của bạn thấy 403 rồi ' +
      'đi refresh token thì nó sẽ lặp vô nghĩa, vì token mới cũng thiếu đúng scope đó.',
  },

  {
    id: 'cc-escalation',
    title: 'Tìm chỗ phân quyền bất đồng',
    difficulty: 3,
    mode: 'console',
    flow: 'authcode',
    brief:
      'Ba mô hình phân quyền có lúc trả lời khác nhau, và chênh lệch đó là lỗ hổng. ' +
      'Tìm một tình huống ba mô hình BẤT ĐỒNG, và một tình huống chúng ĐỒNG THUẬN. ' +
      'Tài liệu doc:42 thuộc về bob.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'disagree',
        text: 'Tìm được tình huống ba mô hình bất đồng',
        check: (c) => find(c, 'policy eval', (e) => e.data['disagree'] === true).length > 0,
      },
      {
        id: 'agree',
        text: 'Tìm được tình huống ba mô hình đồng thuận',
        check: (c) => find(c, 'policy eval', (e) => e.data['disagree'] === false).length > 0,
      },
      {
        id: 'explored',
        text: 'Thử ít nhất 3 tình huống khác nhau',
        check: (c) => {
          const seen = new Set(find(c, 'policy eval').map((e) => `${e.data['user']}|${e.data['action']}|${e.data['resource']}`));
          return seen.size >= 3;
        },
      },
    ],
    hints: [
      'policy eval alice delete doc:42 --model all',
      'Đổi action (read, delete), đổi user (alice, bob), đổi --hour để chạm vào luật giờ làm việc của ABAC.',
      'Bất đồng xảy ra khi role cho phép nhưng quan hệ sở hữu thì không. Vậy để cả ba đồng thuận, ' +
        'hãy tìm người mà cả role LẪN quan hệ sở hữu đều thuận - doc:42 là của bob.',
    ],
    debrief:
      'RBAC hỏi "anh là ai", ReBAC hỏi "cái này có phải của anh". Khi hai câu trả lời khác nhau mà hệ thống ' +
      'chỉ nghe câu đầu, đó chính là IDOR. ABAC nằm giữa: chặt hơn nhưng vẫn không biết ai sở hữu cái gì.',
  },

  {
    id: 'cc-revoke',
    title: 'Chứng minh phiên thu hồi được ngay',
    difficulty: 2,
    mode: 'console',
    flow: 'session',
    brief:
      'Chứng minh bằng lệnh: phiên phía server huỷ được tức thì, còn JWT thì không. ' +
      'Mật khẩu của alice là correct-horse-battery-staple.',
    knobs: [],
    start: {},
    toRun: () => ({}),
    objectives: [
      {
        id: 'logged-in',
        text: 'Đăng nhập bằng mật khẩu và nhận sid',
        check: (c) => find(c, 'login', (e) => e.ok).length > 0,
      },
      {
        id: 'profile-ok',
        text: 'Truy cập được khi phiên còn sống',
        check: (c) => find(c, 'profile', (e) => e.status === 200).length > 0,
      },
      {
        id: 'revoked-then-401',
        text: 'Sau khi huỷ phiên thì bị chặn ngay ở request kế tiếp',
        check: (c) => {
          const l = log(c);
          const rev = l.findIndex((e) => e.cmd === 'revoke' && e.ok);
          if (rev < 0) return false;
          return l.slice(rev).some((e) => e.cmd === 'profile' && e.status === 401);
        },
      },
      {
        id: 'jwt-contrast',
        text: 'Đối chiếu: lấy một access token JWT và đọc claim exp của nó',
        check: (c) => find(c, 'jwt decode').length > 0 || find(c, 'jwt verify').length > 0,
      },
    ],
    hints: [
      'login alice correct-horse-battery-staple rồi profile.',
      'revoke rồi profile lại. Chú ý nó chặn ngay, không phải đợi hết hạn.',
      'Phần đối chiếu: authorize rồi token rồi jwt decode @access. Claim exp là thứ duy nhất kết thúc được token đó.',
    ],
    debrief:
      'Phiên phía server: một dòng trong bảng, xoá là xong. JWT tự chứa: đã phát ra thì không gọi về được, ' +
      'chỉ còn cách đợi exp. Đó là lý do access token phải sống ngắn và mọi thứ cần thu hồi tức thì ' +
      'phải được kiểm tra trực tiếp lúc gọi, không đọc từ claim.',
  },
];
