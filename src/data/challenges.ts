import type { Packet } from '../core/types';
import type { FlowId } from './lessons';
import type { HudState } from '../ui/Hud';
import { CONSOLE_CHALLENGES } from './consoleChallenges';
import { EXPLOIT_CHALLENGES } from './exploitChallenges';

export interface ChallengeContext {
  packets: Packet[];
  outcome: 'success' | 'attacker-won' | 'failed';
  values: Record<string, string>;
  /** Log lệnh của console. Thử thách gõ tay kiểm tra mục tiêu từ đây. */
  log: unknown[];
}

export interface Objective {
  id: string;
  text: string;
  check: (c: ChallengeContext) => boolean;
}

export interface Knob {
  id: string;
  label: string;
  help: string;
  options: { value: string; label: string }[];
}

export interface Challenge {
  id: string;
  title: string;
  /** Tình huống. Viết như một phiếu báo lỗi, không như một bài giảng. */
  brief: string;
  difficulty: 1 | 2 | 3;
  /**
   * 'knobs' = sửa cấu hình bằng dropdown rồi bấm chạy. Dùng cho loại khởi động.
   * 'console' = gõ lệnh tay, mục tiêu tick ngay sau mỗi lệnh. Khó hơn hẳn vì
   * không có sẵn đáp án để bấm thử.
   */
  mode?: 'knobs' | 'console';
  /** Thử thách khai thác đặt trạng thái lỗ ban đầu qua đây. */
  setupPosture?: (harden: (name: string, value: string) => void) => void;
  flow: FlowId;
  knobs: Knob[];
  /** Giá trị khởi đầu - luôn là cấu hình SAI, đó là điểm của thử thách. */
  start: Record<string, string>;
  toRun: (values: Record<string, string>) => { flowOpts?: Record<string, unknown>; hud?: Partial<HudState> };
  objectives: Objective[];
  hints: string[];
  debrief: string;
}

// --- tiện ích tìm chặng, dùng trong các phép kiểm tra ---

const resp = (c: ChallengeContext, from: string, to: string) =>
  c.packets.filter((p) => p.from === from && p.to === to && p.http.kind === 'response');

const statusOf = (c: ChallengeContext, from: string, to: string): number | null => {
  const list = resp(c, from, to);
  return list.length ? (list[list.length - 1]!.http.status ?? null) : null;
};

const hasLabel = (c: ChallengeContext, needle: string) =>
  c.packets.some((p) => p.label.includes(needle));

const KNOB_CHALLENGES: Challenge[] = [
  {
    id: 'ch-pkce',
    title: 'Vá lỗ PKCE',
    difficulty: 1,
    brief:
      'Báo cáo từ đội bảo mật: có người lấy được authorization code từ log proxy và đổi thành ' +
      'access token của người khác. Cấu hình PKCE hiện tại đang sai. Sửa cho kẻ tấn công thất bại, ' +
      'nhưng client thật vẫn phải đăng nhập được.',
    flow: 'authcode',
    knobs: [
      {
        id: 'pkce',
        label: 'code_challenge_method',
        help: 'Cách client băm code_verifier trước khi gửi lên ở bước /authorize.',
        options: [
          { value: 'none', label: 'none — không dùng PKCE' },
          { value: 'plain', label: 'plain — gửi nguyên chuỗi gốc' },
          { value: 'S256', label: 'S256 — băm SHA-256' },
        ],
      },
    ],
    start: { pkce: 'plain' },
    toRun: (v) => ({ hud: { pkceMethod: v['pkce'] as HudState['pkceMethod'], interceptCode: true } }),
    objectives: [
      {
        id: 'attacker-blocked',
        text: 'Kẻ tấn công KHÔNG đổi được code bị trộm thành token',
        check: (c) => statusOf(c, 'authserver', 'attacker') === 400,
      },
      {
        id: 'client-works',
        text: 'Client thật vẫn lấy được token bình thường',
        check: (c) => resp(c, 'authserver', 'client').some((p) => p.http.status === 200),
      },
      {
        id: 'api-works',
        text: 'API vẫn trả 200 cho client thật',
        check: (c) => statusOf(c, 'api', 'client') === 200,
      },
    ],
    hints: [
      'Kẻ tấn công đọc được URL /authorize. Với method nào thì URL đó chứa đủ thứ nó cần?',
      'PKCE không bảo vệ cái code. Nó bảo vệ quyền tiêu cái code - và chỉ khi challenge không đảo ngược được.',
    ],
    debrief:
      'S256 là giá trị duy nhất nên dùng. plain chỉ còn tồn tại trong RFC 7636 để tương thích thiết bị quá cũ. ' +
      'Trong OpenIddict, nhớ rằng RequireProofKeyForCodeExchange() KHÔNG tự loại plain - phải bỏ nó khỏi CodeChallengeMethods.',
  },

  {
    id: 'ch-aud',
    title: 'Chặn audience confusion',
    difficulty: 2,
    brief:
      'API nội bộ /payroll đang trả dữ liệu bảng lương cho token vốn được phát cho API công khai. ' +
      'Chữ ký token hoàn toàn đúng nên không ai để ý. Chặn lại, mà không được làm API công khai hỏng theo.',
    flow: 'aud-confusion',
    knobs: [
      {
        id: 'audCheck',
        label: 'API nội bộ kiểm tra claim aud',
        help: 'Có so aud trong token với chính định danh của API này hay không.',
        options: [
          { value: 'off', label: 'Tắt — chỉ verify chữ ký' },
          { value: 'on', label: 'Bật — so aud với chính mình' },
        ],
      },
    ],
    start: { audCheck: 'off' },
    toRun: (v) => ({ flowOpts: { checkAudienceOnInternal: v['audCheck'] === 'on' } }),
    objectives: [
      {
        id: 'internal-blocked',
        text: 'API nội bộ từ chối token không dành cho nó (401)',
        check: (c) => statusOf(c, 'api2', 'client') === 401,
      },
      {
        id: 'public-ok',
        text: 'API công khai vẫn hoạt động (200)',
        check: (c) => statusOf(c, 'api', 'client') === 200,
      },
    ],
    hints: [
      'Chữ ký trả lời câu "ai phát token này". Nó không trả lời câu "phát cho ai".',
      'Claim aud tồn tại đúng để giải quyết chuyện này. Vấn đề là có ai đọc nó không.',
    ],
    debrief:
      'Mỗi resource server phải kiểm tra aud khớp đúng chính nó. Thiếu bước đó thì mọi token của cùng một ' +
      'issuer thành chìa khoá dùng chung, và service quyền thấp leo lên được service quyền cao bằng token của chính nó.',
  },

  {
    id: 'ch-scope',
    title: 'Cắt scope về mức tối thiểu',
    difficulty: 2,
    brief:
      'Soát lại quyền: app dashboard đang xin quá nhiều scope, trong đó có cả admin:all. ' +
      'Nó chỉ cần đọc báo cáo. Cắt xuống mức tối thiểu mà vẫn chạy được.',
    flow: 'authcode',
    knobs: [
      {
        id: 'scope',
        label: 'scope app xin',
        help: 'Scope là quyền user uỷ cho app. Xin rộng hơn mức cần là tự tạo thiệt hại khi app bị xâm nhập.',
        options: [
          { value: 'openid profile read:reports write:reports admin:all', label: 'openid profile read:reports write:reports admin:all' },
          { value: 'openid profile read:reports write:reports', label: 'openid profile read:reports write:reports' },
          { value: 'openid profile read:reports', label: 'openid profile read:reports' },
          { value: 'openid profile', label: 'openid profile' },
        ],
      },
    ],
    start: { scope: 'openid profile read:reports write:reports admin:all' },
    toRun: (v) => ({ hud: { scope: v['scope']!, requiredScope: 'read:reports', interceptCode: false } }),
    objectives: [
      {
        id: 'api-200',
        text: 'API vẫn trả 200 — app còn làm được việc của nó',
        check: (c) => statusOf(c, 'api', 'client') === 200,
      },
      {
        id: 'no-admin',
        text: 'Không xin scope admin nào',
        check: (c) => !(c.values['scope'] ?? '').includes('admin'),
      },
      {
        id: 'no-write',
        text: 'Không xin quyền ghi — app này chỉ đọc',
        check: (c) => !(c.values['scope'] ?? '').includes('write'),
      },
    ],
    hints: [
      'Cắt hết thì API trả 403. Cắt đúng thì vừa đủ 200.',
      'Đọc thông báo 403: nó nói rõ endpoint cần scope nào.',
    ],
    debrief:
      'Least privilege: app chỉ nên xin đúng scope nó dùng. Scope không tạo thêm quyền cho user, ' +
      'nhưng scope rộng làm cho một app bị xâm nhập gây thiệt hại rộng theo.',
  },

  {
    id: 'ch-zombie',
    title: 'Diệt phiên zombie',
    difficulty: 3,
    brief:
      'Người dùng báo: bấm đăng xuất ở App 1 rồi, nhưng mở App 2 lên vẫn thấy đang đăng nhập. ' +
      'Trên máy dùng chung ở quầy lễ tân, người tiếp theo vào được tài khoản của họ. Sửa đi.',
    flow: 'sso-logout',
    knobs: [
      {
        id: 'backChannel',
        label: 'Back-channel logout',
        help: 'Auth server có chủ động gọi tới từng app để báo phiên đã đóng hay không.',
        options: [
          { value: 'off', label: 'Tắt' },
          { value: 'on', label: 'Bật' },
        ],
      },
      {
        id: 'wikiUri',
        label: 'App 2 khai backchannel_logout_uri',
        help: 'Bật back-channel logout ở server là chưa đủ: từng client phải khai endpoint để nhận thông báo.',
        options: [
          { value: 'no', label: 'Chưa khai' },
          { value: 'yes', label: 'Đã khai' },
        ],
      },
    ],
    start: { backChannel: 'off', wikiUri: 'no' },
    toRun: (v) => ({
      flowOpts: {
        backChannel: v['backChannel'] === 'on',
        registerWikiLogout: v['wikiUri'] === 'yes',
      },
    }),
    objectives: [
      {
        id: 'wiki-notified',
        text: 'App 2 nhận được thông báo đăng xuất',
        check: (c) => hasLabel(c, 'backchannel_logout -> wiki'),
      },
      {
        id: 'wiki-relogin',
        text: 'Mở lại App 2 thì bị đẩy đi đăng nhập lại, không còn phiên zombie',
        check: (c) => statusOf(c, 'client2', 'browser') === 302,
      },
    ],
    hints: [
      'Có hai công tắc, và bật một cái thôi thì chưa đủ.',
      'Auth server không thể gọi tới một endpoint mà client chưa khai bao giờ.',
    ],
    debrief:
      'Đăng xuất chỉ có hiệu lực ở nơi được thông báo, và việc thông báo cần cả hai phía: server bật ' +
      'back-channel logout, client khai endpoint nhận. Phần vẫn chưa giải quyết được: access token đã ' +
      'phát ra vẫn hợp lệ tới khi exp trôi qua - đó là lý do access token phải sống ngắn.',
  },

  {
    id: 'ch-redirect',
    title: 'Điều tra: đăng nhập hỏng',
    difficulty: 1,
    brief:
      'Sau khi đổi domain, không ai đăng nhập được nữa. Auth server trả 400 ngay từ bước đầu. ' +
      'Tìm redirect_uri đúng. Chú ý: chỉ một giá trị được chấp nhận, và lý do đó rất quan trọng.',
    flow: 'authcode',
    knobs: [
      {
        id: 'redirect',
        label: 'redirect_uri app gửi lên',
        help: 'Nơi auth server sẽ đẩy người dùng về kèm authorization code.',
        options: [
          { value: 'https://spa.example.com/callback/', label: 'https://spa.example.com/callback/  (có dấu / cuối)' },
          { value: 'https://spa.example.com/Callback', label: 'https://spa.example.com/Callback  (chữ C hoa)' },
          { value: 'https://spa.example.com/callback', label: 'https://spa.example.com/callback' },
          { value: 'https://spa.example.com.evil.co/callback', label: 'https://spa.example.com.evil.co/callback' },
        ],
      },
    ],
    start: { redirect: 'https://spa.example.com/callback/' },
    toRun: (v) => ({ flowOpts: { redirectUri: v['redirect']! }, hud: { interceptCode: false } }),
    objectives: [
      {
        id: 'authorize-302',
        text: '/authorize trả 302 kèm code',
        check: (c) => resp(c, 'authserver', 'browser').some((p) => p.http.status === 302),
      },
      {
        id: 'api-200',
        text: 'Luồng chạy hết và API trả 200',
        check: (c) => statusOf(c, 'api', 'client') === 200,
      },
    ],
    hints: [
      'So khớp redirect_uri là so chuỗi tuyệt đối. Không chuẩn hoá, không bỏ qua chữ hoa chữ thường, không bỏ qua dấu / cuối.',
      'Để ý cái lựa chọn cuối: tên miền đó bắt đầu bằng chuỗi hợp lệ nhưng không phải nó. Nếu server so khớp theo tiền tố thì đó là chiếm tài khoản.',
    ],
    debrief:
      'Quy tắc khớp tuyệt đối trông cứng nhắc và gây nhiều lỗi lúc triển khai, nhưng nó cố ý như vậy: ' +
      'mọi cách nới lỏng (so tiền tố, cho wildcard, chuẩn hoá URL) đều biến redirect_uri thành open redirect, ' +
      'và open redirect trong OAuth nghĩa là code bị chuyển thẳng tới kẻ tấn công.',
  },
];

/**
 * Console đứng trước, vì đó là loại thực hành thật. Loại dropdown giữ lại làm
 * bước khởi động cho người chưa quen thuật ngữ.
 */
export const CHALLENGES: Challenge[] = [...EXPLOIT_CHALLENGES, ...CONSOLE_CHALLENGES, ...KNOB_CHALLENGES];
