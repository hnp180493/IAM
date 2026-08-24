import type { PkceMethod } from '../crypto/pkce';

export interface LessonPreset {
  pkceMethod: PkceMethod;
  interceptCode: boolean;
  scope: string;
  requiredScope: string;
  timeScale: number;
}

export type FlowId = 'authcode' | 'session' | 'aud-confusion' | 'policy' | 'sso-login' | 'sso-logout' | 'openiddict' | 'openiddict-m2m' | 'openiddict-refresh';

export interface Lesson {
  id: string;
  /** Luồng nào chạy khi bấm "Chạy luồng". Mặc định là authcode. */
  flow?: FlowId;
  /** Tuỳ chọn riêng của luồng đó. */
  flowOpts?: Record<string, unknown>;
  chapter: number;
  title: string;
  tagline: string;
  /** Câu hỏi bài học này trả lời. Đây là thứ hiện trên card. */
  question: string;
  status: 'ready' | 'soon';
  goal: string;
  /** Khái niệm phải biết trước, tra trong GLOSSARY. */
  terms: string[];
  steps: string[];
  watchFor: string;
  preset?: LessonPreset;
  /** Mở sẵn tab Token ở hop nào khi chạy xong. */
  focusHop?: string;
}

export const CHAPTERS: { id: number; title: string; blurb: string }[] = [
  { id: 1, title: 'Nền tảng', blurb: 'Vì sao không thể tự làm cái đăng nhập rồi thôi' },
  { id: 2, title: 'OAuth 2.0 và OIDC', blurb: 'Luồng uỷ quyền, và chỗ nó bị phá' },
  { id: 3, title: 'JWT', blurb: 'Mổ token ra xem, rồi thử sửa nó' },
  { id: 4, title: 'Phân quyền', blurb: 'Biết anh là ai không có nghĩa anh được làm' },
  { id: 5, title: 'SSO', blurb: 'Một lần đăng nhập, và bài toán đăng xuất' },
  { id: 6, title: 'OpenIddict thật', blurb: 'Tự cấu hình authorization server bằng .NET' },
];

export const LESSONS: Lesson[] = [
  // ---- Chương 2: OAuth 2.0 / OIDC ----
  {
    id: 'pkce-happy',
    chapter: 2,
    title: 'Luồng đăng nhập chuẩn',
    tagline: 'Authorization Code + PKCE, từ đầu đến cuối',
    question: 'Bấm "Đăng nhập bằng Google" thì thật ra có bao nhiêu bước?',
    status: 'ready',
    goal: 'Nhìn thấy toàn bộ 11 chặng của một lần đăng nhập thành công, và hiểu vì sao phải nhiều bước thế thay vì app hỏi thẳng mật khẩu.',
    terms: ['pkce', 'authorization_code', 'front_channel', 'back_channel', 'access_token', 'id_token'],
    steps: [
      'Bấm "Chạy luồng" và xem sơ đồ vẽ dần từng chặng một.',
      'Để ý chặng 2: client sinh code_verifier nhưng chỉ gửi bản băm code_challenge.',
      'Để ý chặng 4: code quay về qua thanh địa chỉ browser - tức là công khai.',
      'Để ý chặng 8: code_verifier lần đầu tiên được gửi, và đi đường riêng không qua browser.',
      'Click vào bất kỳ mũi tên nào để đọc HTTP thật đã chạy trên dây.',
    ],
    watchFor:
      'Mật khẩu của user không bao giờ đi qua app. App chỉ nhận được token, và chỉ nhận được ở back channel. Đó là toàn bộ lý do luồng này dài dòng như vậy.',
    preset: { pkceMethod: 'S256', interceptCode: false, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 1 },
  },
  {
    id: 'pkce-none',
    chapter: 2,
    title: 'Không có PKCE: mất tài khoản',
    tagline: 'Kẻ trộm chỉ cần đọc được một URL',
    question: 'Code nằm trong thanh địa chỉ, vậy ai đọc được nó thì sao?',
    status: 'ready',
    goal: 'Thấy tận mắt kẻ tấn công lấy authorization code từ redirect rồi đổi thành access token hợp lệ của user khác.',
    terms: ['authorization_code', 'front_channel', 'bearer'],
    steps: [
      'Bấm "Chạy luồng". Chú ý cột Attacker màu đỏ xuất hiện.',
      'Xem chặng "Code lọt sang kẻ tấn công": trong thực tế đây là app độc hại cùng máy, log proxy, hoặc Referer leak.',
      'Xem chặng "POST /token (code bị trộm)" nhận về 200 OK.',
      'Click chặng đó, mở tab Token: đó là access token thật, ký thật, dùng được thật.',
    ],
    watchFor:
      'Auth server không làm gì sai. Nó không có cách nào phân biệt kẻ trộm với client thật, vì cả hai đều chỉ trình ra đúng một cái code. Thiếu PKCE thì code là tiền mặt.',
    preset: { pkceMethod: 'none', interceptCode: true, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 1 },
  },
  {
    id: 'pkce-s256',
    chapter: 2,
    title: 'S256 chặn kẻ trộm',
    tagline: 'Vẫn bị trộm code, nhưng vô dụng',
    question: 'Vì sao trộm được code mà vẫn không vào được?',
    status: 'ready',
    goal: 'Hiểu PKCE không bảo vệ cái code - nó bảo vệ quyền tiêu cái code.',
    terms: ['pkce', 's256', 'code_verifier', 'code_challenge'],
    steps: [
      'Bấm "Chạy luồng". Kẻ tấn công vẫn trộm được code y như bài trước.',
      'Nhưng chặng "POST /token (code bị trộm)" giờ nhận 400 invalid_grant.',
      'Click chặng 400 đó và đọc lý do server đưa ra.',
      'So sánh với bài "Không có PKCE": cùng một cái code bị trộm, khác nhau đúng một tham số.',
    ],
    watchFor:
      'Kẻ tấn công phải tìm được một chuỗi mà SHA-256 của nó bằng đúng code_challenge. Đó là bài toán đảo ngược hàm băm. Nó không đoán được, và đây là SHA-256 thật đang chạy trong máy bạn.',
    preset: { pkceMethod: 'S256', interceptCode: true, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 1 },
  },
  {
    id: 'pkce-plain',
    chapter: 2,
    title: 'PKCE bị hạ cấp xuống plain',
    tagline: 'Có PKCE mà vẫn mất, vì cấu hình sai một chữ',
    question: 'Đã bật PKCE rồi thì an toàn chưa?',
    status: 'ready',
    goal: 'Thấy vì sao code_challenge_method=plain là bật PKCE nhưng không được bảo vệ gì.',
    terms: ['plain', 's256', 'code_verifier', 'front_channel'],
    steps: [
      'Bấm "Chạy luồng".',
      'Click chặng 2 và đọc URL /authorize: với plain, code_challenge chính là code_verifier, nằm nguyên văn trong URL.',
      'Xem kẻ tấn công đọc URL đó rồi replay lại: 200 OK.',
      'Đổi dropdown PKCE về S256, chạy lại. Cùng kịch bản, giờ nó thua.',
    ],
    watchFor:
      'Đây là lỗi cấu hình chứ không phải lỗi giao thức. Trong OpenIddict, tương ứng với việc không gọi RequireProofKeyForCodeExchange hoặc để client tự chọn method. Luôn ép S256 ở phía server.',
    preset: { pkceMethod: 'plain', interceptCode: true, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 1 },
  },

  // ---- Chương 3: JWT ----
  {
    id: 'jwt-anatomy',
    chapter: 3,
    title: 'Mổ xẻ JWT',
    tagline: 'Ba khối, mười ba claim, tám lần kiểm tra',
    question: 'Cái chuỗi dài loằng ngoằng đó bên trong là gì?',
    status: 'ready',
    goal: 'Đọc được từng claim trong access token, và biết API kiểm tra những gì trước khi chấp nhận nó.',
    terms: ['jwt', 'jwks', 'kid', 'aud', 'exp', 'access_token', 'id_token'],
    steps: [
      'Bấm "Chạy luồng", đợi vẽ xong.',
      'Click mũi tên "GET /me (Bearer)" rồi chọn tab Token.',
      'Ba khối màu là header, payload, signature - base64url, không phải mã hóa. Ai cũng đọc được.',
      'Hover từng claim để biết nó dùng làm gì và bỏ nó thì vỡ ở đâu.',
      'Kéo xuống cuối xem đủ 8 lần kiểm tra API đã chạy.',
    ],
    watchFor:
      'Payload đọc được không có nghĩa là sửa được. Chữ ký phủ lên cả header và payload, sửa một byte là chữ ký sai. Nhưng đọc được nghĩa là: đừng bao giờ nhét dữ liệu bí mật vào JWT.',
    preset: { pkceMethod: 'S256', interceptCode: false, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 1 },
    focusHop: 'GET /me (Bearer)',
  },
  {
    id: 'jwt-exp',
    chapter: 3,
    title: 'Token hết hạn',
    tagline: 'Tua 60x để xem nó chết',
    question: 'Vì sao access token chỉ sống 5 phút?',
    status: 'ready',
    goal: 'Hiểu exp là cơ chế thu hồi duy nhất của JWT tự chứa, và vì sao thời hạn phải ngắn.',
    terms: ['exp', 'jwt', 'refresh_token'],
    steps: [
      'Bấm "Chạy luồng" - ô "hết hạn sau" trên thanh trên hiện 300s.',
      'Tốc độ đã đặt 60x nên đồng hồ mô phỏng chạy nhanh gấp 60 lần.',
      'Ngồi xem khoảng 5 giây thật: 300 giây token trôi hết.',
      'Click hop GET /me, tab Token, xem claim exp và thời gian tuyệt đối bên cạnh.',
    ],
    watchFor:
      'Sa thải một người xong, token của họ vẫn sống cho tới khi exp trôi qua. Không có cách nào gọi nó về. Bất cứ thứ gì cần thu hồi tức thì thì phải kiểm tra trực tiếp lúc gọi, không được đọc từ claim.',
    preset: { pkceMethod: 'S256', interceptCode: false, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 60 },
  },
  {
    id: 'jwt-tamper',
    chapter: 3,
    title: 'Sửa token để lên admin',
    tagline: 'Sửa được payload, nhưng không sửa được chữ ký',
    question: 'Payload đọc được thì sửa roles thành admin có được không?',
    status: 'ready',
    goal: 'Tự tay sửa claim rồi bắn lại vào API thật, xem nó bắt được ở phép kiểm tra nào. Đây là bài duy nhất bạn là người tấn công.',
    terms: ['jwt', 'jwks', 'kid', 'bearer'],
    steps: [
      'Bấm "Chạy luồng", đợi xong.',
      'Click hop "GET /me (Bearer)", mở tab Token, bấm nút "Sửa và bắn lại".',
      'Bấm nút "Nâng roles lên admin" rồi bấm "Bắn lại vào API".',
      'Thử tiếp "Đổi alg thành none" và "Gia hạn exp thêm 10 năm".',
      'Đọc kỹ phép kiểm tra nào chuyển đỏ ở mỗi cú đánh.',
    ],
    watchFor:
      'Chữ ký được ghép lại nguyên bản gốc, vì kẻ tấn công không có private key. Đó là lý do mọi cú sửa payload đều chết ở phép kiểm tra signature. Riêng alg=none chết ở phép kiểm tra alg - và nếu server nào tin vào header để chọn cách verify thì chính cú đó lọt.',
    preset: { pkceMethod: 'S256', interceptCode: false, scope: 'openid profile read:reports', requiredScope: 'read:reports', timeScale: 1 },
    focusHop: 'GET /me (Bearer)',
  },
  {
    id: 'jwt-aud',
    chapter: 3,
    title: 'Audience confusion',
    tagline: 'Token hợp lệ, nhưng không phải cho anh',
    question: 'Token thật của API A đem gọi API B thì sao?',
    status: 'ready',
    flow: 'aud-confusion',
    flowOpts: { checkAudienceOnInternal: false },
    goal: 'Thấy vì sao thiếu đúng một dòng kiểm tra aud là mở đường cho service quyền thấp gọi được service quyền cao.',
    terms: ['aud', 'jwt', 'jwks'],
    steps: [
      'Bấm "Chạy luồng". Bài này API nội bộ đang TẮT kiểm tra aud.',
      'Chặng đầu: token được phát với aud = api.example.com.',
      'Chặng giữa: gọi đúng API đó, 200 OK. Bình thường.',
      'Chặng cuối: cùng token đó gọi API nội bộ - và nó trả dữ liệu bảng lương.',
      'Click chặng cuối, tab Token: chữ ký vẫn xanh. Chữ ký không hề sai.',
    ],
    watchFor:
      'Chữ ký chỉ chứng minh "ai phát ra token này", không chứng minh "phát cho ai". Bỏ kiểm tra aud là biến mọi token của cùng một issuer thành chìa khoá dùng chung cho mọi API.',
  },

  // ---- Chương 4: Phân quyền ----
  {
    id: 'authz-401-403',
    chapter: 4,
    title: '401 khác 403 ở đâu',
    tagline: 'Token hoàn hảo vẫn bị chặn',
    question: 'Đăng nhập rồi mà vẫn báo lỗi quyền là sao?',
    status: 'ready',
    goal: 'Phân biệt xác thực (anh là ai) với phân quyền (anh được làm gì), và biết scope không phải hệ thống phân quyền.',
    terms: ['scope', '401', '403', 'access_token'],
    steps: [
      'Bài này đặt trước "API yêu cầu" thành admin:everything - một scope không có trong token.',
      'Bấm "Chạy luồng". Chặng cuối trả 403 Forbidden, không phải 401.',
      'Click chặng đó: tất cả 8 lần kiểm tra chữ ký vẫn xanh. Token không có vấn đề gì.',
      'Sửa ô "API yêu cầu" thành read:reports rồi chạy lại: 200 OK.',
    ],
    watchFor:
      'Trả 401 khi đúng ra phải 403 sẽ khiến client tưởng token hỏng và refresh liên tục trong vòng lặp vô nghĩa. 401 là "đăng nhập lại đi", 403 là "đăng nhập lại cũng thế thôi".',
    preset: { pkceMethod: 'S256', interceptCode: false, scope: 'openid profile read:reports', requiredScope: 'admin:everything', timeScale: 1 },
  },
  {
    id: 'authz-rbac',
    chapter: 4,
    title: 'RBAC, ABAC, ReBAC',
    tagline: 'Cùng một yêu cầu, ba mô hình, ba câu trả lời',
    question: 'Role trong token có đủ để phân quyền không?',
    status: 'ready',
    flow: 'policy',
    flowOpts: { atHour: 14 },
    goal: 'Thấy chỗ ba mô hình phân quyền lệch nhau, và vì sao chênh lệch đó chính là lỗ IDOR.',
    terms: ['scope', '403', 'access_token'],
    steps: [
      'Tình huống: alice (role writer) muốn xoá doc:42, nhưng tài liệu đó là của bob.',
      'Bấm "Chạy luồng" và đọc ba chặng đánh giá liên tiếp.',
      'RBAC cho phép - nó chỉ nhìn role, không biết tài liệu của ai.',
      'ABAC cũng cho phép - cùng phòng ban, trong giờ làm việc.',
      'ReBAC từ chối - alice không có quan hệ nào với doc:42.',
      'Click từng chặng để đọc vết suy luận đầy đủ trong phần body.',
    ],
    watchFor:
      'Role trả lời "anh là ai". Quan hệ trả lời "cái này có phải của anh". Hầu hết lỗ hổng phân quyền thực tế nằm ở câu thứ hai, và RBAC thuần không có chỗ nào để hỏi nó.',
  },

  // ---- Chương 1: Nền tảng ----
  {
    id: 'basics-session',
    chapter: 1,
    title: 'Cookie phiên và token khác nhau ra sao',
    tagline: 'Trạng thái ở server, hay ở trong tay client',
    question: 'Trước khi có OAuth thì người ta đăng nhập thế nào?',
    status: 'ready',
    flow: 'session',
    flowOpts: { revokeMidway: true },
    goal: 'Thấy điều mà JWT tự chứa không làm được: huỷ phiên có hiệu lực ngay ở request kế tiếp.',
    terms: ['jwt', 'bearer'],
    steps: [
      'Bấm "Chạy luồng". Chú ý mật khẩu đi thẳng vào app - khác hẳn OAuth.',
      'Chặng "PBKDF2 100.000 vòng": đây là PBKDF2-HMAC-SHA256 thật đang chạy trong máy bạn.',
      'Cookie chỉ chứa một sid vô nghĩa. Toàn bộ phiên nằm ở server.',
      'Chặng "Admin huỷ phiên": nhân viên bị cho nghỉ việc.',
      'Request ngay sau đó: 401. Không phải đợi hết hạn gì cả.',
    ],
    watchFor:
      'Đây chính là cái bạn đánh đổi khi chuyển sang JWT. Bỏ trạng thái ở server thì hết cần tra database mỗi request, nhưng cũng hết khả năng thu hồi. So với bài "Token hết hạn" ở chương JWT để thấy rõ.',
  },

  // ---- Chương 5: SSO ----
  {
    id: 'sso-two-apps',
    chapter: 5,
    title: 'Đăng nhập một lần, vào hai app',
    tagline: 'App thứ hai không hỏi mật khẩu',
    question: 'Vì sao vào app thứ hai không phải đăng nhập lại?',
    status: 'ready',
    flow: 'sso-login',
    goal: 'Thấy phiên đăng nhập không nằm ở app nào - nó nằm ở auth server, và mọi app chỉ đi hỏi lại chỗ đó.',
    terms: ['sso', 'oidc', 'front_channel'],
    steps: [
      'Bấm "Chạy luồng". Nửa đầu là App 1 đăng nhập, có form nhập mật khẩu.',
      'Để ý form đăng nhập thuộc domain id.example.com, không thuộc app.',
      'Nửa sau App 2 mở lên - domain khác hẳn, không chung cookie hay database.',
      'Chặng "302 + code (KHÔNG hỏi mật khẩu)": đó là toàn bộ phép màu SSO.',
    ],
    watchFor:
      'SSO không có gì huyền bí: nhiều app cùng đi hỏi một chỗ, và chỗ đó có cookie nhớ bạn. Cookie phiên SSO thuộc domain của auth server, nên app nào chuyển hướng sang đó cũng được hưởng.',
  },
  {
    id: 'sso-logout',
    chapter: 5,
    title: 'Đăng xuất mới là phần khó',
    tagline: 'Phiên zombie sau khi bấm logout',
    question: 'Bấm đăng xuất ở một app, các app kia có biết không?',
    status: 'ready',
    flow: 'sso-logout',
    flowOpts: { backChannel: true },
    goal: 'Thấy vì sao đăng xuất chỉ có hiệu lực ở nơi được thông báo, và phiên zombie xuất hiện thế nào.',
    terms: ['sso', 'refresh_token', 'exp'],
    steps: [
      'Bấm "Chạy luồng". Back-channel logout đang BẬT.',
      'App 1 có khai backchannel_logout_uri nên nhận được thông báo.',
      'App 2 không khai, nên auth server không có cách nào báo cho nó.',
      'Chặng cuối: mở lại App 2 và nó vẫn đang đăng nhập. Đó là phiên zombie.',
    ],
    watchFor:
      'Trên máy dùng chung, phiên zombie nghĩa là người tiếp theo mở App 2 lên là vào được tài khoản của alice. Và kể cả khi mọi app đều đóng phiên, access token đã phát ra vẫn hợp lệ tới khi exp trôi qua - đăng xuất không thu hồi được JWT.',
  },

  // ---- Chương 6: OpenIddict ----
  {
    id: 'openiddict-server',
    chapter: 6,
    title: 'Chạy trên OpenIddict thật',
    tagline: 'Không còn mock: ASP.NET Core 9 ở cổng 5181',
    question: 'Mock có nói đúng những gì server thật làm không?',
    status: 'ready',
    flow: 'openiddict',
    goal:
      'Chạy đúng luồng của chương 2 nhưng qua một authorization server thật, rồi đối chiếu từng bước với mock. Chỗ nào lệch là chỗ mock đã đơn giản hoá quá.',
    terms: ['pkce', 's256', 'jwks', 'access_token', 'oidc'],
    steps: [
      'Mở terminal, chạy: cd server-dotnet/IamLab.AuthServer && dotnet run --urls http://localhost:5181',
      'Bấm Chạy luồng. Chặng đầu là /lab/config, cho biết server đang siết những gì.',
      'Đọc chặng discovery: code_challenge_methods_supported do OpenIddict tự sinh từ cấu hình.',
      'Tick "Kẻ tấn công trộm code" để gửi code_verifier sai, xem OpenIddict tự từ chối.',
      'Đổi PKCE sang plain: OpenIddict chặn ngay ở /authorize với 400.',
      'Click chặng GET /api/me, tab Token: bộ verify của lab chạy trên token thật do OpenIddict ký.',
    ],
    watchFor:
      'Có một điểm mock đã nói sai, và chỉ chạy server thật mới lộ ra: RequireProofKeyForCodeExchange() chỉ ép PKCE phải CÓ, nó không ép method phải là S256 - OpenIddict vẫn quảng cáo và vẫn nhận plain. Phải bỏ plain khỏi CodeChallengeMethods mới thật sự chặn được. Xem chú thích trong Program.cs.',
  },
  {
    id: 'openiddict-m2m',
    chapter: 6,
    title: 'Client Credentials (máy-gọi-máy)',
    tagline: 'Đăng nhập khi không có người dùng nào',
    question: 'Một cron job hay microservice thì "đăng nhập" kiểu gì?',
    status: 'ready',
    flow: 'openiddict-m2m',
    goal:
      'Thấy luồng client_credentials thật: một service tự lấy token bằng client_id + secret, không có /authorize, không có người dùng, không có PKCE.',
    terms: ['access_token', 'scope', 'bearer'],
    steps: [
      'Cần server thật đang chạy ở :5181 (xem bài trước).',
      'Bấm Chạy luồng. Chỉ có 2 chặng: POST /token rồi gọi /api/service.',
      'Click chặng token, tab Token: sub của access token là "service-worker" - chính là client, không phải người dùng.',
      'Chú ý không hề có bước redirect hay code: client confidential giữ được secret nên tự xác thực thẳng.',
    ],
    watchFor:
      'Client credentials CHỈ dành cho máy-gọi-máy. Đừng bao giờ dùng nó cho luồng có người dùng - ở đó phải là authorization code + PKCE, vì client (SPA, app) không giữ được secret. Nhầm hai cái này là lỗi kiến trúc phổ biến.',
  },
  {
    id: 'openiddict-refresh',
    chapter: 6,
    title: 'Refresh rotation trên server thật',
    tagline: 'OpenIddict bắt refresh token bị dùng lại',
    question: 'Server thật có phát hiện refresh token bị trộm không?',
    status: 'ready',
    flow: 'openiddict-refresh',
    goal:
      'Thấy refresh token rotation + reuse detection thật, và một điểm mock-vs-real: OpenIddict mặc định để leeway cho bản cũ, phải đặt leeway=0 mới bắt reuse ngay.',
    terms: ['refresh_token', 'access_token', 'exp'],
    steps: [
      'Cần server thật đang chạy ở :5181.',
      'Bấm Chạy luồng. Client thật refresh một lần (bản cũ bị xoay).',
      'Chặng đỏ: kẻ tấn công dùng lại bản CŨ đã bị xoay -> OpenIddict thu hồi cả chuỗi.',
      'Chặng cuối: refresh mới của client thật cũng chết theo - cái giá của reuse detection.',
    ],
    watchFor:
      'Điểm chỉ server thật dạy được: OpenIddict xoay refresh mặc định NHƯNG để ~30s leeway cho bản cũ (chịu request đồng thời). Trong khoảng đó reuse không bị bắt. Lab đặt SetRefreshTokenReuseLeeway(TimeSpan.Zero) để nghiêm ngặt - production phải cân nhắc giữa an toàn và trải nghiệm mạng chập chờn.',
  },
];

export function lessonsByChapter(chapter: number): Lesson[] {
  return LESSONS.filter((l) => l.chapter === chapter);
}
