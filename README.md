# IAM Lab

Lab tương tác để học xác thực và phân quyền. Chạy từng luồng OAuth theo chặng,
click vào chặng nào cũng xem được HTTP thật đã chạy trên dây, rồi mổ token ra
từng claim — và tự tay sửa nó để xem chỗ nào bắt được.

**Song ngữ Việt / English** — nút EN/VI ở góc phải menu, lưu lựa chọn lại. Giao
diện, điều hướng, tiêu đề bài học và từ điển thuật ngữ đã dịch đầy đủ tiếng Anh;
phần văn bản sâu trong bài (các bước, tổng kết, output console) hiện vẫn tiếng
Việt và dịch dần qua khung i18n trong `src/i18n/`. Tên tham số giao thức
(`code_challenge`, `S256`, `aud`, `exp`) luôn giữ tiếng Anh vì là chuỗi chạy thật.

## Chạy

```bash
npm install
npm run dev
```

13 trong 14 bài chạy thuần trong trình duyệt, không cần gì thêm. Riêng bài
"Chạy trên OpenIddict thật" cần authorization server thật:

```bash
cd server-dotnet/IamLab.AuthServer
dotnet run --urls http://localhost:5181
```

## Thực hành

Ba kiểu, xếp theo mức độ bạn phải tự làm.

### 0. Red Team mode — tấn công dồn dập, phòng thủ real-time

Chế độ vô hạn. Cứ vài giây một cấu hình phòng thủ bị tắt, và tấn công leo thang
theo thời gian. Dùng `audit` để soi, `harden <cấu hình> on` để vá, trước khi thanh
toàn vẹn về 0. Vá càng nhanh càng nhiều điểm.

**15 loại tấn công**, mỗi cái phá đúng một cờ phòng thủ **có thật** — không có cái nào
là thông báo suông, và `audit` đọc lại trạng thái thật (15 phép kiểm tra) nên không
ghi điểm được nếu không thực sự vá.

### 1. Khai thác lỗ hổng (3 cái) — hack rồi vá, trong cùng một bài

Mỗi bài bắt đầu với hệ thống đang có một lỗ hổng thật. Bạn phải khai thác được
(API trả `200` với token giả), rồi vá, rồi xác nhận cùng token đó giờ bị chặn.

| Khai thác | Cơ chế |
|---|---|
| alg-confusion (HS256/RS256) | Ký lại token bằng HS256, secret là **public key thật** lấy từ JWKS. Crypto thật — HMAC thật. |
| Key nhúng trong token (jwk/jku) | Ký token bằng **khoá của chính bạn**, nhúng public key vào header; server ngây thơ verify bằng đúng key đó |
| Bỏ verify chữ ký | Sửa `roles=admin` giữ chữ ký cũ, server không kiểm nên nhận |
| Audience confusion | Token của API công khai gọi được `/payroll` của API nội bộ |
| Session fixation | Gài sid biết trước, nạn nhân đăng nhập, sid không đổi → chiếm phiên |
| Refresh token dùng mãi | Không rotation → refresh bị trộm dùng vô hạn; bật rotation thì reuse thu hồi cả family |

alg-confusion và key-injection là hai bài đáng nhất — cả hai đều tạo ra **chữ ký hợp
lệ thật sự** bằng crypto thật:

```
$ jwt forge @access --set roles=admin --hs256 <public key>   # HMAC bằng public key
$ jwt forge @access --set roles=admin --own-key              # ký bằng khoá attacker, nhúng vào header
$ curl /me --token @forged                                    # 200 OK, roles=admin
$ harden hs256 on   (hoặc: harden jku on)                     # vá → 401
```

### 2. Thử thách gõ tay (6 cái) — không có đáp án để bấm thử

Console riêng, gõ lệnh thật. Mục tiêu tick ngay sau mỗi lệnh.

```
$ authorize --pkce plain
$ token --code code-xxx --verifier <chuỗi bạn đọc được từ URL>
$ jwt forge @access --set roles=admin
$ curl /me --token @forged
$ policy eval alice delete doc:42 --model all
```

| Thử thách | Bạn phải làm gì |
|---|---|
| Tự tay đăng nhập | Gõ đủ 3 bước của code + PKCE cho tới khi API trả 200 |
| Đóng vai kẻ tấn công | Trộm token của alice qua `plain`, rồi chứng minh `S256` chặn được |
| Làm API chấp nhận token giả | Sửa token 3 hướng, ghi nhận mỗi hướng chết ở phép kiểm tra nào |
| Chẩn đoán lỗi 403 | Tái hiện → đọc token tìm nguyên nhân → sửa ra 200 |
| Tìm chỗ phân quyền bất đồng | Tìm tình huống 3 mô hình bất đồng, và một tình huống đồng thuận |
| Chứng minh phiên thu hồi được ngay | Dùng lệnh chứng minh session huỷ được mà JWT thì không |

Lệnh có tab completion, lịch sử mũi tên lên/xuống, và token lưu theo tên gọi bằng
`@access` / `@forged`.

### 3. Thử thách cấu hình (5 cái) — bước khởi động

Dropdown, dành cho lúc chưa quen thuật ngữ. "Diệt phiên zombie" có hai công tắc và
**bật một cái là chưa đủ**.

| Thử thách | Tình huống |
|---|---|
| Vá lỗ PKCE | Có người đổi được code bị trộm thành token. Chặn lại, client thật vẫn phải vào được. |
| Chặn audience confusion | API nội bộ đang trả bảng lương cho token của API công khai. |
| Cắt scope về mức tối thiểu | App chỉ cần đọc mà đang xin cả `admin:all`. |
| Diệt phiên zombie | Đăng xuất rồi mà App 2 vẫn thấy đang đăng nhập. |
| Điều tra: đăng nhập hỏng | Đổi domain xong không ai vào được. Tìm `redirect_uri` đúng. |

### 4. Sửa và bắn lại

Ở bài "Sửa token để lên admin", bạn tự sửa claim rồi bắn token giả vào API thật.

### 5. Sửa C# rồi audit

Bộ kiểm tra tự động tấn công server thật của bạn:

```bash
npm run audit
```

13 phép kiểm tra, mỗi cái nêu rõ vấn đề, vì sao nó nguy hiểm, và dòng code cần sửa.
Nó **không đọc file cấu hình** — nó tấn công thật rồi kết luận từ phản hồi thật, nên
sửa comment không lừa được nó. Muốn thấy nó bắt lỗi thì tự tạo lỗ hổng:

```bash
LAB_ALLOW_PLAIN_PKCE=1 dotnet run --urls http://localhost:5181
```

Bộ audit chuyển thành 9/10 và chỉ đúng chỗ.

## Crypto là thật

Đây là mô phỏng *network*, không phải mô phỏng *mật mã*. Mọi token được ký bằng
khoá RSA 2048-bit sinh ngay trong trình duyệt bạn, và mọi lần từ chối là một
phép kiểm tra thật sự thất bại:

- `code_challenge` là bản băm SHA-256 thật (RFC 7636)
- token là JWT RS256 thật, verify bằng JWKS thật
- mật khẩu băm bằng PBKDF2-HMAC-SHA256 thật, 100.000 vòng
- sửa một byte trong payload là chữ ký sai, vì nó sai thật

Nên khi lab nói kẻ tấn công không tiêu được authorization code đã trộm dưới
`S256`, đó không phải kết quả dàn dựng. Đó là SHA-256 từ chối bị đảo ngược.

## 14 bài học

| Chương | Bài | Cho thấy điều gì |
|---|---|---|
| 1. Nền tảng | Cookie phiên và token khác nhau ra sao | Huỷ phiên có hiệu lực ngay — điều JWT không làm được |
| 2. OAuth 2.0 | Luồng đăng nhập chuẩn | 11 chặng của một lần đăng nhập, và vì sao phải dài thế |
| | Không có PKCE: mất tài khoản | Kẻ tấn công trộm code rồi đổi thành token thật |
| | S256 chặn kẻ trộm | Vẫn bị trộm code, nhưng `400 invalid_grant` |
| | PKCE hạ cấp xuống `plain` | Bật PKCE mà vẫn mất, vì sai một tham số |
| 3. JWT | Mổ xẻ JWT | 13 claim, 8 phép kiểm tra, hover ra giải thích |
| | Token hết hạn | Tua 60x, xem token 300 giây chết trong 5 giây |
| | Sửa token để lên admin | Bạn là người tấn công: sửa claim rồi bắn lại vào API |
| | Audience confusion | Token hợp lệ của API A mở được API B |
| 4. Phân quyền | 401 khác 403 ở đâu | Token hoàn hảo vẫn bị chặn vì thiếu scope |
| | RBAC, ABAC, ReBAC | Một yêu cầu, ba mô hình, ba câu trả lời khác nhau |
| 5. SSO | Đăng nhập một lần, vào hai app | Phiên nằm ở auth server, không ở app |
| | Đăng xuất mới là phần khó | Phiên zombie sau khi bấm logout |
| 6. OpenIddict | Chạy trên OpenIddict thật | Đối chiếu mock với authorization server thật |
| 6. OpenIddict | Client Credentials (M2M) | Đăng nhập khi không có người dùng nào |
| 6. OpenIddict | Refresh rotation trên server thật | OpenIddict bắt refresh token bị dùng lại |

## Sửa và bắn lại

Ở bài "Sửa token để lên admin", nút **Sửa và bắn lại** trên token inspector mở
một hộp thoại cho sửa trực tiếp header và payload. Token được ghép lại với
**chữ ký gốc giữ nguyên** — đúng những gì kẻ tấn công làm được, vì họ không có
private key. Bốn cú tấn công có sẵn, và mỗi cú chết ở một phép kiểm tra khác nhau:

| Cú tấn công | Chết ở |
|---|---|
| Nâng `roles` lên admin | `signature` |
| Đổi `alg` thành `none` | `alg` rồi `signature` |
| Gia hạn `exp` thêm 10 năm | `signature` |
| Đổi `aud` sang API nội bộ | `signature` và `aud` |

## Điều chỉ server thật mới lộ ra

Bài chương 6 tồn tại để đối chiếu, và nó đã bắt được một chỗ mock nói sai.

`RequireProofKeyForCodeExchange()` **chỉ ép PKCE phải có mặt, không ép method
phải là `S256`**. OpenIddict vẫn quảng cáo `plain` trong discovery và vẫn nhận
`plain` ở `/connect/token` — đã kiểm chứng: `200 OK`. Muốn chặn thật thì phải bỏ
nó ra khỏi danh sách:

```csharp
options.AllowAuthorizationCodeFlow()
       .RequireProofKeyForCodeExchange();

// Dòng này mới là dòng thật sự chặn plain.
options.Configure(o => o.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
```

Đặt `LAB_ALLOW_PLAIN_PKCE=1` rồi khởi động lại server để mở lại `plain` và so sánh.

## Layout

```
src/
  crypto/   jose.ts     ký/verify RS256, JWKS, verdict là danh sách check
            pkce.ts     dẫn xuất và kiểm tra S256
  server/   MockAuthServer.ts  /authorize + /token + phiên SSO
            ResourceApi.ts     chỉ verify bằng public key
            SessionServer.ts   PBKDF2 + phiên thu hồi được
  engine/   PolicyEngine.ts    RBAC / ABAC / ReBAC, có vết suy luận
  flows/    authCodePkce · sessionCookie · audConfusion · policyModels
            sso · openiddictReal
  ui/       Menu · Tutorial · Stage · Inspector · Hud · TamperDialog
  core/     Clock.ts     thời gian mô phỏng, để quan sát token hết hạn
  data/     lessons.ts · glossary.ts (22 thuật ngữ) · claims.ts

server-dotnet/IamLab.AuthServer/
  Program.cs             OpenIddict 6 trên ASP.NET Core 9, SQLite
```

## Vì sao sơ đồ là 2D

k8sgames vẽ một cluster Kubernetes — thứ có *không gian*, nên cảnh 3D là xứng
đáng. Một luồng auth là thứ có *thời gian*: điều đáng xem là thứ tự các chặng và
mỗi chặng mang theo cái gì. Nên sân khấu ở đây là sequence diagram, và trục dọc
của nó chính là thời gian.

Thiết kế và những phần chưa làm nằm ở [docs/DESIGN.md](docs/DESIGN.md).
