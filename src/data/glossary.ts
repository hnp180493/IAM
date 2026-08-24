import { getLang } from '../i18n';
/**
 * Từ điển thuật ngữ. Tên tham số giao thức luôn giữ nguyên tiếng Anh vì đó là
 * chuỗi chạy thật trên dây - đổi sang tiếng Việt thì sau này đọc RFC hay log
 * production sẽ không nhận ra.
 */
export interface GlossaryEntry {
  term: string;
  short: string;
  long: string;
}

export const GLOSSARY: Record<string, GlossaryEntry> = {
  pkce: {
    term: 'PKCE',
    short: 'Cơ chế chống trộm authorization code',
    long: 'Proof Key for Code Exchange. Client tự sinh một chuỗi bí mật (code_verifier) giữ trong máy, chỉ gửi lên server bản băm của nó (code_challenge). Khi đổi code lấy token mới trình chuỗi gốc ra. Kẻ trộm được code nhưng không có code_verifier thì đổi không được.',
  },
  code_verifier: {
    term: 'code_verifier',
    short: 'Chuỗi bí mật client tự sinh, không bao giờ đi qua browser',
    long: 'Chuỗi random 43-128 ký tự client sinh ra mỗi lần đăng nhập. Nó chỉ được gửi đúng một lần, ở bước POST /token, qua kết nối trực tiếp client - server. Browser không bao giờ thấy nó, nên kẻ nghe lén thanh địa chỉ cũng không có.',
  },
  code_challenge: {
    term: 'code_challenge',
    short: 'Bản băm của code_verifier, gửi công khai được',
    long: 'Bản băm SHA-256 của code_verifier. Nó nằm công khai trong URL /authorize và điều đó không sao cả: từ hash không suy ra được chuỗi gốc. Auth server ghi nhớ hash này, gắn vào authorization code vừa phát.',
  },
  s256: {
    term: 'S256',
    short: 'Băm bằng SHA-256 rồi mới gửi. Đây là cách đúng.',
    long: 'code_challenge = BASE64URL(SHA-256(code_verifier)). Kẻ trộm đọc được hash trong URL nhưng muốn tìm chuỗi gốc thì phải đảo ngược SHA-256, chuyện đó không làm được. Đây là giá trị duy nhất nên dùng trong thực tế.',
  },
  plain: {
    term: 'plain',
    short: 'Không băm gì cả. Vô dụng.',
    long: 'code_challenge = code_verifier, tức là gửi luôn chuỗi gốc. Chuỗi bí mật nằm cleartext trong URL /authorize, ai đọc được URL đó là có luôn chìa khóa. RFC 7636 chỉ giữ plain để tương thích với thiết bị quá cũ không băm nổi SHA-256.',
  },
  authorization_code: {
    term: 'authorization code',
    short: 'Vé một lần, đổi được thành token',
    long: 'Chuỗi ngắn hạn (thường 60 giây) auth server phát ra sau khi user đăng nhập xong. Nó phải đi qua thanh địa chỉ browser mới về được app, nên coi như công khai. Đổi được đúng một lần: lần thứ hai là dấu hiệu code bị lộ, và server thật sẽ thu hồi toàn bộ phiên.',
  },
  front_channel: {
    term: 'front channel',
    short: 'Đường đi qua browser. Coi như công khai.',
    long: 'Mọi thứ truyền qua redirect của trình duyệt: URL, query string, Referer header. Nó nằm trong history, trong log proxy, trong log server, và app độc hại cùng máy có thể đọc. Nguyên tắc: đừng bao giờ đặt bí mật vào front channel.',
  },
  back_channel: {
    term: 'back channel',
    short: 'Đường client gọi thẳng server. Browser không thấy.',
    long: 'Kết nối HTTP trực tiếp từ server của client tới auth server, không đi qua trình duyệt người dùng. Đây là chỗ duy nhất an toàn để truyền code_verifier hay client secret.',
  },
  jwt: {
    term: 'JWT',
    short: 'Token tự chứa thông tin, có ký số',
    long: 'JSON Web Token: ba khối base64url nối bằng dấu chấm - header.payload.signature. Ai cũng đọc được nội dung (base64 không phải mã hóa), nhưng không ai sửa được mà không làm chữ ký sai. Đổi lại: một khi đã phát ra thì không thu hồi được, chỉ đợi hết hạn.',
  },
  jwks: {
    term: 'JWKS',
    short: 'Danh sách public key auth server công bố',
    long: 'JSON Web Key Set, thường ở /.well-known/jwks.json. API tải về để tự verify chữ ký, không cần chia sẻ secret với auth server. Nhờ vậy API verify được nhưng không phát được token - đó là điểm mạnh của ký bất đối xứng (RS256) so với đối xứng (HS256).',
  },
  kid: {
    term: 'kid',
    short: 'ID của key đã ký token này',
    long: 'Key ID trong header JWT, cho biết dùng key nào trong JWKS để verify. Nhờ nó mà đổi key được mà không downtime: phát key mới, giữ key cũ trong JWKS đến khi token cũ hết hạn. Tuyệt đối đừng dùng kid làm đường dẫn file hay URL - biến việc đổi key thành lỗ path traversal hoặc SSRF.',
  },
  access_token: {
    term: 'access_token',
    short: 'Vé để gọi API',
    long: 'Token client đính vào header Authorization: Bearer khi gọi resource API. Nó nói "được phép làm gì", không nói "user là ai" cho mục đích hiển thị. Sống ngắn (5-15 phút) vì không thu hồi được.',
  },
  id_token: {
    term: 'id_token',
    short: 'Giấy chứng nhận user là ai. Không dùng để gọi API.',
    long: 'Token của OpenID Connect, dành cho chính client đọc để biết user là ai (tên, email, thời điểm đăng nhập). aud của nó là client_id, không phải API. Đính id_token vào Authorization header gọi API là sai - đó là hai loại vé khác nhau.',
  },
  refresh_token: {
    term: 'refresh_token',
    short: 'Vé đổi lấy access_token mới khi hết hạn',
    long: 'Sống dài, dùng để lấy access_token mới mà không bắt user đăng nhập lại. Vì sống dài nên nó là mục tiêu béo bở: bắt buộc phải rotation - mỗi lần dùng là phát cái mới và huỷ cái cũ. Nếu cái cũ bị dùng lại lần nữa, đó là dấu hiệu bị trộm, và phải huỷ cả chuỗi.',
  },
  scope: {
    term: 'scope',
    short: 'Quyền mà USER uỷ cho APP, không phải quyền của user',
    long: 'Scope thu hẹp quyền đã có, không bao giờ tạo thêm quyền. User là admin, app xin scope read:reports thì app chỉ đọc được báo cáo. Ngược lại user chỉ là reader, app xin scope admin:all thì app vẫn không thành admin. Nhầm scope thành hệ thống phân quyền là lỗi thiết kế rất phổ biến.',
  },
  aud: {
    term: 'aud',
    short: 'Token này dành cho ai',
    long: 'Audience - API nào được phép nhận token này. Lỗi audience confusion: API B nhận token vốn phát cho API A. Khi đó một service quyền thấp có thể lấy token của chính nó đem gọi service quyền cao. Luôn kiểm tra aud khớp đúng chính mình.',
  },
  exp: {
    term: 'exp',
    short: 'Thời điểm token chết',
    long: 'Unix timestamp, sau mốc này phải từ chối token. Với JWT tự chứa, exp là cơ chế thu hồi duy nhất bạn có - đã phát ra rồi thì không gọi lại được. Đó là lý do access token phải sống ngắn và đi kèm refresh rotation.',
  },
  bearer: {
    term: 'Bearer',
    short: 'Ai giữ, người đó dùng được. Như tiền mặt.',
    long: 'Bearer token không gắn với thiết bị hay danh tính người gửi: chỉ cần trình ra là được chấp nhận. Trộm được là dùng được. Muốn khắc phục thì phải gắn token vào máy (mTLS, DPoP) - nội dung của chương hardening.',
  },
  oidc: {
    term: 'OIDC',
    short: 'Lớp xác thực dựng trên OAuth 2.0',
    long: 'OpenID Connect. OAuth 2.0 gốc chỉ giải quyết uỷ quyền (app được làm gì), không trả lời user là ai. OIDC thêm id_token, endpoint /userinfo và tài liệu discovery để chuẩn hoá việc đó.',
  },
  sso: {
    term: 'SSO',
    short: 'Đăng nhập một lần, dùng nhiều app',
    long: 'Single Sign-On. Phiên đăng nhập nằm ở auth server, không ở từng app. App thứ hai chuyển hướng sang auth server, thấy phiên còn sống nên trả token về ngay không hỏi mật khẩu. Phần khó không phải đăng nhập mà là đăng xuất: huỷ phiên ở chỗ này thì các app kia phải biết.',
  },
  '401': {
    term: '401 Unauthorized',
    short: 'Không biết anh là ai',
    long: 'Lỗi xác thực: thiếu token, token sai chữ ký, hết hạn, sai issuer. Sửa bằng cách đăng nhập lại hoặc refresh. Tên gọi 401 Unauthorized là đặt sai từ đầu, đúng nghĩa phải là Unauthenticated.',
  },
  '403': {
    term: '403 Forbidden',
    short: 'Biết anh là ai, nhưng anh không được phép',
    long: 'Lỗi phân quyền: token hoàn toàn hợp lệ nhưng thiếu scope, thiếu role, hoặc không sở hữu tài nguyên đó. Đăng nhập lại không giải quyết được gì. Trả 401 khi đúng ra phải 403 sẽ khiến client refresh token vô nghĩa trong vòng lặp.',
  },
};

/** Bản dịch tiếng Anh, khoá theo cùng key. term giữ nguyên (chuỗi giao thức). */
const GLOSSARY_EN: Record<string, { short: string; long: string }> = {
  pkce: { short: 'Stops a stolen authorization code from being usable', long: 'Proof Key for Code Exchange. The client generates a secret (code_verifier) it keeps locally, and only sends the server a hash of it (code_challenge). When exchanging the code for a token it presents the original. A thief with the code but no code_verifier cannot redeem it.' },
  code_verifier: { short: 'A client-generated secret that never travels through the browser', long: 'A random 43-128 char string the client mints each login. It is sent exactly once, at POST /token, over a direct client-to-server connection. The browser never sees it, so an address-bar eavesdropper never gets it.' },
  code_challenge: { short: 'The hash of code_verifier — safe to send in the open', long: 'The SHA-256 hash of code_verifier. It sits openly in the /authorize URL and that is fine: you cannot get the original from the hash. The auth server remembers it and binds it to the code it issues.' },
  s256: { short: 'Hash with SHA-256 before sending. This is the right way.', long: 'code_challenge = BASE64URL(SHA-256(code_verifier)). A thief reads the hash in the URL but reversing SHA-256 to find the original is not feasible. This is the only value to use in practice.' },
  plain: { short: 'No hashing at all. Useless.', long: 'code_challenge = code_verifier, i.e. the raw secret is sent. It sits in cleartext in the /authorize URL, so anyone who reads the URL has the key. RFC 7636 keeps plain only for ancient devices that cannot compute SHA-256.' },
  authorization_code: { short: 'A one-time ticket, exchangeable for a token', long: 'A short-lived string (usually 60s) the auth server issues after login. It must travel through the browser address bar to reach the app, so treat it as public. Redeemable once: a second attempt signals a leak, and a real server revokes the whole grant.' },
  front_channel: { short: 'The path through the browser. Treat as public.', long: 'Everything that travels via browser redirects: URLs, query strings, Referer headers. It lives in history, proxy logs, server logs, and a malicious app on the same machine can read it. Rule: never put a secret in the front channel.' },
  back_channel: { short: 'The client calling the server directly. The browser never sees it.', long: 'A direct HTTP connection from the client’s server to the auth server, not through the user’s browser. This is the only safe place to transmit code_verifier or a client secret.' },
  jwt: { short: 'A self-contained, signed token', long: 'JSON Web Token: three base64url blocks joined by dots — header.payload.signature. Anyone can read the contents (base64 is not encryption), but nobody can change them without breaking the signature. The tradeoff: once issued it cannot be recalled, only expire.' },
  jwks: { short: 'The public keys the auth server publishes', long: 'JSON Web Key Set, usually at /.well-known/jwks.json. An API fetches it to verify signatures itself, no shared secret with the auth server. So the API can verify but never mint — the strength of asymmetric (RS256) over symmetric (HS256) signing.' },
  kid: { short: 'The id of the key that signed this token', long: 'Key ID in the JWT header: which key from the JWKS to verify with. It enables zero-downtime key rotation. Never use kid as a file path or URL — that turns rotation into path traversal or SSRF.' },
  access_token: { short: 'The ticket to call an API', long: 'The token a client attaches as Authorization: Bearer when calling a resource API. It says "what may be done", not "who the user is" for display. Short-lived (5-15 min) because it cannot be revoked.' },
  id_token: { short: 'Proof of who the user is. Not for calling APIs.', long: 'An OpenID Connect token for the client itself to read who the user is (name, email, login time). Its aud is the client_id, not an API. Attaching an id_token to an API’s Authorization header is wrong — two different kinds of ticket.' },
  refresh_token: { short: 'A ticket to get a new access_token when it expires', long: 'Long-lived, used to get a new access_token without forcing re-login. Because it is long-lived it is a prime target: it must rotate — each use mints a new one and voids the old. If the old one is used again, that signals theft, and the whole chain is revoked.' },
  scope: { short: 'What the USER delegated to the APP, not the user’s own powers', long: 'Scope narrows existing authority, it never grants new authority. The user is admin, the app requests scope read:reports, so the app can only read reports. Conversely if the user is only a reader, requesting scope admin:all does not make the app admin. Mistaking scope for a permission system is a very common design error.' },
  aud: { short: 'Who this token is for', long: 'Audience — which API may accept this token. The audience-confusion bug: API B accepts a token minted for API A. Then a low-privilege service can take its own token and call a high-privilege one. Always check aud matches yourself exactly.' },
  exp: { short: 'When the token dies', long: 'Unix timestamp after which the token must be refused. For a self-contained JWT, exp is your only revocation — once issued you cannot recall it. That is why access tokens must be short-lived and paired with refresh rotation.' },
  bearer: { short: 'Whoever holds it can use it. Like cash.', long: 'A bearer token is not bound to a device or the sender’s identity: presenting it is enough to be accepted. Steal it and you can use it. Fixing that means binding the token to a machine (mTLS, DPoP) — the hardening chapter.' },
  oidc: { short: 'An authentication layer on top of OAuth 2.0', long: 'OpenID Connect. Plain OAuth 2.0 only handles delegation (what an app may do), not who the user is. OIDC adds the id_token, a /userinfo endpoint, and discovery to standardise that.' },
  sso: { short: 'Log in once, use many apps', long: 'Single Sign-On. The login session lives at the auth server, not at each app. The second app redirects to the auth server, which sees the session is alive and returns a token without asking for a password. The hard part is not login but logout: revoking the session in one place means the other apps must find out.' },
  '401': { short: 'It doesn’t know who you are', long: 'An authentication error: missing token, bad signature, expired, wrong issuer. Fix by logging in again or refreshing. The name 401 Unauthorized was mislabelled from the start — it really means Unauthenticated.' },
  '403': { short: 'It knows who you are, but you may not', long: 'An authorization error: the token is perfectly valid but lacks a scope, a role, or ownership. Logging in again solves nothing. Returning 401 where it should be 403 makes a client refresh in a pointless loop.' },
};

export function glossaryTerm(key: string, field: 'short' | 'long'): string {
  const g = GLOSSARY[key];
  if (!g) return '';
  const en = GLOSSARY_EN[key];
  return getLang() === 'en' && en ? en[field] : g[field];
}

export function glossaryHtml(key: string): string {
  const g = GLOSSARY[key];
  if (!g) return '';
  return `<span class="gl" data-term="${key}">${g.term}<span class="gl-pop"><b>${g.term}</b> — ${glossaryTerm(key, 'short')}<em>${glossaryTerm(key, 'long')}</em></span></span>`;
}
