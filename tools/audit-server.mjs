#!/usr/bin/env node
/**
 * Bộ kiểm tra bảo mật cho authorization server ở localhost:5181.
 *
 * Đây là phần thực hành bằng code: sửa Program.cs, chạy lại cái này, xem hệ quả.
 * Mỗi phép kiểm tra tấn công server thật rồi kết luận từ phản hồi thật - không
 * hề đọc file cấu hình, nên không lừa được nó bằng cách sửa comment.
 *
 *   node tools/audit-server.mjs
 *   npm run audit
 */

import { createHash, randomBytes } from 'node:crypto';

const BASE = process.env['AUDIT_BASE'] ?? 'http://localhost:5181';
const CLIENT = 'spa-dashboard';
const REDIRECT = 'http://localhost:5180/callback';

const b64u = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const verifier = () => b64u(randomBytes(32));
const s256 = (v) => b64u(createHash('sha256').update(v).digest());

const c = {
  reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  dim: '\x1b[2m', bold: '\x1b[1m', cyan: '\x1b[36m',
};

async function authorize({ challenge, method, redirect = REDIRECT, scope = 'openid profile read:reports' }) {
  const url =
    `${BASE}/connect/authorize?response_type=code&client_id=${CLIENT}` +
    `&redirect_uri=${encodeURIComponent(redirect)}&scope=${encodeURIComponent(scope)}&state=s` +
    (challenge ? `&code_challenge=${challenge}&code_challenge_method=${method}` : '');
  const res = await fetch(url, { redirect: 'manual' });
  const loc = res.headers.get('location');
  return { status: res.status, code: loc ? new URL(loc).searchParams.get('code') : null };
}

async function token({ code, codeVerifier }) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, client_id: CLIENT, redirect_uri: REDIRECT });
  if (codeVerifier) body.set('code_verifier', codeVerifier);
  const res = await fetch(`${BASE}/connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

/** Lấy một access token hợp lệ, dùng cho các phép kiểm tra phía resource server. */
async function goodToken() {
  const v = verifier();
  const a = await authorize({ challenge: s256(v), method: 'S256' });
  if (!a.code) return null;
  const t = await token({ code: a.code, codeVerifier: v });
  return t.json.access_token ?? null;
}

const CHECKS = [
  {
    id: 'pkce-required',
    title: 'Bắt buộc PKCE',
    why: 'Thiếu PKCE thì authorization code thành bearer: ai đọc được redirect là tiêu được.',
    fix: 'options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();',
    async run() {
      const a = await authorize({ challenge: null, method: null });
      if (a.status === 400) return { pass: true, detail: 'Request không có code_challenge bị từ chối (400).' };
      return { pass: false, detail: `Server nhận request không có PKCE (${a.status}${a.code ? ', còn phát cả code' : ''}).` };
    },
  },
  {
    id: 'pkce-s256-only',
    title: 'Chỉ cho phép S256',
    why: 'plain nghĩa là code_verifier nằm cleartext trong URL /authorize. Bật PKCE mà để plain là không được bảo vệ gì.',
    fix: 'options.Configure(o => o.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));',
    async run() {
      const v = verifier();
      const a = await authorize({ challenge: v, method: 'plain' });
      if (a.status === 400) return { pass: true, detail: 'method=plain bị từ chối ngay ở /authorize.' };
      const t = a.code ? await token({ code: a.code, codeVerifier: v }) : { status: 0 };
      if (t.status === 200) {
        return { pass: false, detail: 'method=plain được chấp nhận và phát token. RequireProofKeyForCodeExchange() một mình KHÔNG loại plain.' };
      }
      return { pass: false, detail: `plain qua được /authorize (${a.status}) dù /token trả ${t.status}. Nên chặn từ /authorize.` };
    },
  },
  {
    id: 'verifier-checked',
    title: 'Kiểm tra code_verifier',
    why: 'Đây là phép kiểm tra làm cho một authorization code bị trộm trở thành vô dụng.',
    fix: 'Đã có sẵn khi bật PKCE. Nếu fail thì luồng /token đang không gọi AuthenticateAsync.',
    async run() {
      const v = verifier();
      const a = await authorize({ challenge: s256(v), method: 'S256' });
      if (!a.code) return { pass: false, detail: 'Không lấy được code để thử.' };
      const t = await token({ code: a.code, codeVerifier: verifier() });
      return t.status === 400
        ? { pass: true, detail: `code_verifier sai bị từ chối: ${t.json.error_description ?? t.json.error}` }
        : { pass: false, detail: `code_verifier sai vẫn phát được token (${t.status}).` };
    },
  },
  {
    id: 'code-single-use',
    title: 'Code chỉ dùng một lần',
    why: 'Code bị dùng lần thứ hai là dấu hiệu nó đã lộ. Server phải từ chối, và nên thu hồi cả phiên.',
    fix: 'OpenIddict làm sẵn, nhưng cần EF provider hỗ trợ ExecuteUpdate (InMemory thì không).',
    async run() {
      const v = verifier();
      const a = await authorize({ challenge: s256(v), method: 'S256' });
      if (!a.code) return { pass: false, detail: 'Không lấy được code để thử.' };
      const first = await token({ code: a.code, codeVerifier: v });
      const second = await token({ code: a.code, codeVerifier: v });
      if (first.status !== 200) return { pass: false, detail: `Lần đổi đầu đã thất bại (${first.status}).` };
      return second.status === 400
        ? { pass: true, detail: `Lần thứ hai bị từ chối: ${second.json.error_description ?? second.json.error}` }
        : { pass: false, detail: `Cùng một code đổi được hai lần (lần 2: ${second.status}).` };
    },
  },
  {
    id: 'redirect-exact',
    title: 'redirect_uri khớp tuyệt đối',
    why: 'So khớp theo tiền tố cho phép attacker.com dùng tên miền bắt đầu bằng chuỗi hợp lệ để hứng code.',
    fix: 'Đừng nới lỏng so khớp. Khai từng redirect_uri đầy đủ trong RedirectUris.',
    async run() {
      const v = verifier();
      const evil = 'http://localhost:5180.evil.co/callback';
      const a = await authorize({ challenge: s256(v), method: 'S256', redirect: evil });
      return a.status === 400
        ? { pass: true, detail: 'redirect_uri chưa đăng ký bị từ chối (400).' }
        : { pass: false, detail: `Server nhận redirect_uri lạ (${a.status}) - code sẽ bị đẩy sang ${evil}.` };
    },
  },
  {
    id: 'token-readable-jwt',
    title: 'Access token là JWT đọc được',
    why: 'Không phải yêu cầu bảo mật - là yêu cầu của lab, để mổ token ra xem. Production thì nên bật lại JWE.',
    fix: 'options.DisableAccessTokenEncryption();',
    async run() {
      const t = await goodToken();
      if (!t) return { pass: false, detail: 'Không lấy được token.' };
      const parts = t.split('.');
      if (parts.length !== 3) return { pass: false, detail: `Token có ${parts.length} phần - đang là JWE đã mã hoá.` };
      try {
        const h = JSON.parse(Buffer.from(parts[0], 'base64url'));
        return { pass: h.alg === 'RS256', detail: `alg=${h.alg}, typ=${h.typ}` };
      } catch {
        return { pass: false, detail: 'Không giải mã được header.' };
      }
    },
  },
  {
    id: 'aud-present',
    title: 'Access token có claim aud',
    why: 'Thiếu aud thì resource server không có gì để so, và audience confusion thành cửa mở.',
    fix: 'identity.SetResources("https://api.example.com");',
    async run() {
      const t = await goodToken();
      if (!t) return { pass: false, detail: 'Không lấy được token.' };
      const claims = JSON.parse(Buffer.from(t.split('.')[1], 'base64url'));
      return claims.aud
        ? { pass: true, detail: `aud = ${JSON.stringify(claims.aud)}` }
        : { pass: false, detail: 'Token không có claim aud.' };
    },
  },
  {
    id: 'token-lifetime',
    title: 'Access token sống ngắn (<= 15 phút)',
    why: 'JWT tự chứa không thu hồi được. Thời hạn ngắn là cơ chế giới hạn thiệt hại duy nhất.',
    fix: 'options.SetAccessTokenLifetime(TimeSpan.FromMinutes(5));',
    async run() {
      const v = verifier();
      const a = await authorize({ challenge: s256(v), method: 'S256' });
      const t = await token({ code: a.code, codeVerifier: v });
      const ttl = t.json.expires_in;
      if (typeof ttl !== 'number') return { pass: false, detail: 'Không thấy expires_in.' };
      return ttl <= 900
        ? { pass: true, detail: `expires_in = ${ttl}s` }
        : { pass: false, detail: `expires_in = ${ttl}s - quá dài với một token không thu hồi được.` };
    },
  },
  {
    id: 'api-requires-token',
    title: 'API từ chối request không có token',
    why: 'Endpoint quên RequireAuthorization là lỗ hổng thẳng, không cần kỹ thuật gì để khai thác.',
    fix: 'app.MapGet("/api/me", ...).RequireAuthorization();',
    async run() {
      const res = await fetch(`${BASE}/api/me`);
      return res.status === 401
        ? { pass: true, detail: 'Không có token thì 401.' }
        : { pass: false, detail: `Không có token vẫn trả ${res.status}.` };
    },
  },
  {
    id: 'api-rejects-tampered',
    title: 'API từ chối token bị sửa',
    why: 'Nếu chấp nhận, nghĩa là chữ ký không được verify - và ai cũng tự phong admin được.',
    fix: 'AddValidation(options => { options.UseLocalServer(); options.UseAspNetCore(); });',
    async run() {
      const t = await goodToken();
      if (!t) return { pass: false, detail: 'Không lấy được token.' };
      const [h, p, s] = t.split('.');
      const claims = JSON.parse(Buffer.from(p, 'base64url'));
      claims.role = ['admin'];
      claims.scope = `${claims.scope ?? ''} admin:all`;
      const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${s}`;
      const res = await fetch(`${BASE}/api/me`, { headers: { Authorization: `Bearer ${forged}` } });
      return res.status === 401
        ? { pass: true, detail: 'Token bị sửa payload (giữ chữ ký cũ) bị từ chối 401.' }
        : { pass: false, detail: `Token bị sửa vẫn được nhận (${res.status}). Chữ ký không được kiểm tra.` };
    },
  },
  {
    id: 'scope-enforced',
    title: 'API quyền cao ép đúng scope',
    why: 'Endpoint admin nhận token thiếu scope là leo thang quyền: reader gọi được API admin.',
    fix: 'Kiểm tra scope trong handler; trả 403 nếu thiếu (RequireScope trong Program.cs).',
    async run() {
      const t = await goodToken(); // scope read:reports, KHÔNG có admin:reports
      if (!t) return { pass: false, detail: 'Không lấy được token.' };
      const res = await fetch(`${BASE}/api/admin`, { headers: { Authorization: `Bearer ${t}` } });
      return res.status === 403
        ? { pass: true, detail: 'Token thiếu admin:reports bị /api/admin trả 403.' }
        : { pass: false, detail: `/api/admin trả ${res.status} cho token thiếu scope - phải là 403.` };
    },
  },
  {
    id: 'm2m-secret-required',
    title: 'Client credentials cần đúng secret',
    why: 'Confidential client mà nhận secret sai nghĩa là ai cũng mạo danh service được.',
    fix: 'ClientType = Confidential + ClientSecret; OpenIddict tự kiểm.',
    async run() {
      const bad = await fetch(`${BASE}/connect/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'service-worker', client_secret: 'sai', scope: 'reports.api' }),
      });
      const good = await fetch(`${BASE}/connect/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'service-worker', client_secret: 's3rv1ce-s3cr3t', scope: 'reports.api' }),
      });
      return bad.status >= 400 && good.status === 200
        ? { pass: true, detail: `Secret sai bị từ chối (${bad.status}), secret đúng được cấp token.` }
        : { pass: false, detail: `Secret sai trả ${bad.status}, secret đúng trả ${good.status}.` };
    },
  },
  {
    id: 'refresh-reuse-detected',
    title: 'Refresh token reuse bị phát hiện',
    why: 'Không phát hiện reuse thì refresh bị trộm dùng song song với client thật vô thời hạn.',
    fix: 'options.SetRefreshTokenReuseLeeway(TimeSpan.Zero); (mặc định có leeway ~30s).',
    async run() {
      const v = verifier();
      const a = await authorize({ challenge: s256(v), method: 'S256', scope: 'openid profile read:reports offline_access' });
      if (!a.code) return { pass: false, detail: 'Không lấy được code.' };
      const t0 = await token({ code: a.code, codeVerifier: v });
      const rt0 = t0.json.refresh_token;
      if (!rt0) return { pass: false, detail: 'Không có refresh token (thiếu offline_access?).' };
      const refresh = (rt) => fetch(`${BASE}/connect/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', client_id: CLIENT, refresh_token: rt }),
      });
      await refresh(rt0);              // xoay rt0
      const reuse = await refresh(rt0); // dùng lại rt0 đã xoay
      return reuse.status >= 400
        ? { pass: true, detail: 'Dùng lại refresh đã xoay bị từ chối (thu hồi cả chuỗi).' }
        : { pass: false, detail: `Refresh cũ dùng lại vẫn được (${reuse.status}) - còn leeway, reuse không bị bắt.` };
    },
  },
];

async function main() {
  console.log(`\n${c.bold}Audit authorization server${c.reset} ${c.dim}${BASE}${c.reset}\n`);

  try {
    await fetch(`${BASE}/lab/config`);
  } catch {
    console.log(`${c.red}Không kết nối được ${BASE}${c.reset}\n`);
    console.log('Khởi động server trước:\n');
    console.log(`  ${c.cyan}cd server-dotnet/IamLab.AuthServer${c.reset}`);
    console.log(`  ${c.cyan}dotnet run --urls http://localhost:5181${c.reset}\n`);
    process.exit(2);
  }

  let passed = 0;
  const failures = [];

  for (const check of CHECKS) {
    let result;
    try {
      result = await check.run();
    } catch (e) {
      result = { pass: false, detail: `Phép kiểm tra lỗi: ${String(e)}` };
    }
    if (result.pass) {
      passed += 1;
      console.log(`${c.green}  PASS${c.reset}  ${check.title}`);
      console.log(`        ${c.dim}${result.detail}${c.reset}`);
    } else {
      failures.push({ check, result });
      console.log(`${c.red}  FAIL${c.reset}  ${check.title}`);
      console.log(`        ${c.yellow}${result.detail}${c.reset}`);
    }
  }

  console.log(`\n${c.bold}${passed}/${CHECKS.length} phép kiểm tra đạt${c.reset}\n`);

  if (failures.length) {
    console.log(`${c.bold}Cần sửa:${c.reset}\n`);
    for (const { check, result } of failures) {
      console.log(`${c.yellow}${check.title}${c.reset}`);
      console.log(`  vấn đề: ${result.detail}`);
      console.log(`  vì sao: ${check.why}`);
      console.log(`  sửa   : ${c.cyan}${check.fix}${c.reset}\n`);
    }
    console.log(`${c.dim}Sửa Program.cs, khởi động lại server, rồi chạy lại lệnh này.${c.reset}\n`);
    process.exit(1);
  }

  console.log(`${c.green}Không tìm thấy vấn đề nào.${c.reset}`);
  console.log(
    `${c.dim}Thử tự tạo lỗ hổng để xem bộ audit bắt được không:\n` +
      `  LAB_ALLOW_PLAIN_PKCE=1 dotnet run --urls http://localhost:5181${c.reset}\n`,
  );
}

await main();
