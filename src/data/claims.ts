import { getLang } from '../i18n';

/**
 * Mỗi claim dùng làm gì, và bỏ nó thì vỡ ở đâu. Hiện khi hover trong token
 * inspector - một cái JWT decode ra không tự nó dạy được gì.
 *
 * Tên claim giữ nguyên tiếng Anh vì đó là khoá chạy thật trong token.
 */
export const CLAIM_DOCS: Record<string, { title: string; why: string }> = {
  iss: {
    title: 'Issuer - ai phát token',
    why: 'Phải so khớp tuyệt đối với một chuỗi cố định. Server nào bỏ qua bước này sẽ vui vẻ nhận một token hoàn toàn hợp lệ nhưng do kẻ tấn công tự dựng auth server phát ra.',
  },
  sub: {
    title: 'Subject - user là ai',
    why: 'Mã định danh cố định và vô nghĩa của user. Đừng bao giờ dùng username hay email làm khoá chính: chúng đổi được và cấp lại được, nên một tài khoản đổi tên có thể thừa hưởng dữ liệu của tài khoản khác.',
  },
  aud: {
    title: 'Audience - token dành cho ai',
    why: 'Lỗi audience confusion kinh điển: API B nhận token vốn phát cho API A. Khi đó một service quyền thấp chỉ cần lấy token của chính nó đem gọi service quyền cao là leo thang được. Luôn kiểm tra aud có đúng chính mình.',
  },
  exp: {
    title: 'Expiration - hết hạn lúc nào',
    why: 'Sau mốc này phải từ chối. Với JWT tự chứa, đây là cơ chế thu hồi duy nhất - đã phát ra rồi thì không gọi về được. Đó là lý do mô hình chuẩn là token sống ngắn cộng refresh rotation.',
  },
  nbf: {
    title: 'Not before - chưa hiệu lực trước lúc này',
    why: 'Chặn token bị dùng quá sớm. Hữu ích cho token phát trước và để hấp thụ lệch giờ giữa các server.',
  },
  iat: {
    title: 'Issued at - phát lúc nào',
    why: 'Cho phép từ chối token quá cũ theo chính sách riêng, ngay cả khi exp chưa trôi qua.',
  },
  jti: {
    title: 'JWT ID - số hiệu token',
    why: 'Là chỗ móc để làm danh sách chặn. Không có jti thì không thu hồi được một token cụ thể, chỉ có thể huỷ toàn bộ token của cả cái key đó.',
  },
  scope: {
    title: 'Scope - quyền user uỷ cho app',
    why: 'Không phải quyền của user. Scope thu hẹp quyền đã có, không bao giờ tạo thêm quyền. Nhầm scope thành hệ thống phân quyền là biến nó thành lớp bảo vệ giả.',
  },
  client_id: {
    title: 'Client ID - app nào lấy token này',
    why: 'Cần cho vết audit, và để thu hồi riêng một app bị xâm nhập mà không phải đăng xuất toàn bộ user.',
  },
  roles: {
    title: 'Roles - vai trò, và cái bẫy',
    why: 'Role nhét trong token bị đóng băng cho tới khi token hết hạn: thu hồi quyền admin của một người thì họ vẫn còn admin đến hết thời hạn token. Bất cứ thứ gì cần thu hồi tức thì thì phải kiểm tra trực tiếp, không đọc từ claim.',
  },
  auth_time: {
    title: 'Auth time - user chứng minh danh tính lúc nào',
    why: 'Cho phép bắt xác thực lại với thao tác nhạy cảm (đổi mật khẩu, chuyển tiền) dù phiên vẫn còn sống.',
  },
  name: {
    title: 'Tên hiển thị',
    why: 'Dữ liệu hồ sơ từ id_token. Dùng để vẽ giao diện, tuyệt đối không dùng để quyết định phân quyền.',
  },
  email: {
    title: 'Email',
    why: 'Dữ liệu hồ sơ. Coi như chưa xác minh trừ khi có claim email_verified nói khác. Lấy email chưa xác minh làm khoá tài khoản là mở đường chiếm tài khoản.',
  },
  preferred_username: {
    title: 'Username hiển thị',
    why: 'Chỉ để hiển thị. Đổi được, và không duy nhất khi có nhiều identity provider.',
  },
};

export const HEADER_DOCS: Record<string, { title: string; why: string }> = {
  alg: {
    title: 'Algorithm - thuật toán ký',
    why: 'Tuyệt đối đừng tin trường này để chọn cách verify - đó chính là họ lỗ hổng alg=none và HMAC/RSA confusion. Ghim danh sách thuật toán cho phép ở phía server rồi so sánh.',
  },
  typ: {
    title: 'Type - loại token',
    why: 'Kiểu media của token, thường là "JWT".',
  },
  kid: {
    title: 'Key ID - key nào đã ký',
    why: 'Cho biết dùng key nào trong JWKS để verify, nhờ đó đổi key được mà không downtime. Đừng dùng kid làm đường dẫn file hay URL - làm vậy là biến việc đổi key thành lỗ path traversal hoặc SSRF.',
  },
};

/** Bản dịch tiếng Anh, khoá theo cùng tên claim/header. */
const CLAIM_DOCS_EN: Record<string, { title: string; why: string }> = {
  iss: {
    title: 'Issuer — who minted this token',
    why: 'Must match an exact, fixed string. A server that skips this check will happily accept a fully valid token minted by an attacker running their own auth server.',
  },
  sub: {
    title: 'Subject — who the user is',
    why: 'A stable, meaningless identifier for the user. Never use username or email as a primary key: both can change and be reassigned, so a renamed account could inherit another account\'s data.',
  },
  aud: {
    title: 'Audience — who this token is for',
    why: 'The classic audience-confusion bug: API B accepts a token minted for API A. A low-privilege service can then take its own token and call a high-privilege one to escalate. Always check aud matches yourself.',
  },
  exp: {
    title: 'Expiration — when it dies',
    why: 'Must be refused past this point. For a self-contained JWT, this is the only revocation mechanism — once issued it cannot be called back. That is why the standard model is short-lived tokens plus refresh rotation.',
  },
  nbf: {
    title: 'Not before — not valid until this point',
    why: 'Blocks a token used too early. Useful for pre-issued tokens and for absorbing clock skew between servers.',
  },
  iat: {
    title: 'Issued at — when it was minted',
    why: 'Lets you reject tokens older than your own policy allows, even if exp hasn\'t passed yet.',
  },
  jti: {
    title: 'JWT ID — this token\'s serial number',
    why: 'The hook for a denylist. Without jti you cannot revoke one specific token, only invalidate every token from that key.',
  },
  scope: {
    title: 'Scope — authority the user delegated to the app',
    why: 'Not the user\'s own power. Scope narrows existing authority, it never grants new authority. Mistaking scope for an authorization system turns it into a fake protection layer.',
  },
  client_id: {
    title: 'Client ID — which app obtained this token',
    why: 'Needed for the audit trail, and to revoke a single compromised app without logging out every user.',
  },
  roles: {
    title: 'Roles — and the trap they set',
    why: 'A role baked into a token is frozen until the token expires: revoke someone\'s admin role and they keep it until the token\'s own lifetime ends. Anything needing instant revocation must be checked live, never read from a claim.',
  },
  auth_time: {
    title: 'Auth time — when the user last proved who they are',
    why: 'Lets you force re-authentication for sensitive actions (changing a password, moving money) even while the session is still alive.',
  },
  name: {
    title: 'Display name',
    why: 'Profile data from the id_token. Use it to render UI, never to make an authorization decision.',
  },
  email: {
    title: 'Email',
    why: 'Profile data. Treat as unverified unless an email_verified claim says otherwise. Using an unverified email as an account key opens the door to account takeover.',
  },
  preferred_username: {
    title: 'Display username',
    why: 'Display only. It can change, and isn\'t unique across multiple identity providers.',
  },
};

const HEADER_DOCS_EN: Record<string, { title: string; why: string }> = {
  alg: {
    title: 'Algorithm — the signing algorithm',
    why: 'Never trust this field to decide how to verify — that is exactly the alg=none and HMAC/RSA-confusion vulnerability family. Pin the allowed algorithm list server-side and compare against it.',
  },
  typ: {
    title: 'Type — the token\'s type',
    why: 'The token\'s media type, usually "JWT".',
  },
  kid: {
    title: 'Key ID — which key signed this',
    why: 'States which key in the JWKS to verify with, enabling key rotation with no downtime. Never use kid as a file path or URL — doing so turns key rotation into a path-traversal or SSRF hole.',
  },
};

/** Đọc đúng ngôn ngữ hiện tại cho một claim/header, lùi về vi nếu thiếu bản dịch. */
export function claimDoc(key: string, table: 'claim' | 'header'): { title: string; why: string } | undefined {
  const base = table === 'claim' ? CLAIM_DOCS[key] : HEADER_DOCS[key];
  if (!base) return undefined;
  if (getLang() !== 'en') return base;
  const en = (table === 'claim' ? CLAIM_DOCS_EN : HEADER_DOCS_EN)[key];
  return en ?? base;
}
