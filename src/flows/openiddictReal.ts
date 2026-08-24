import { challengeFrom, createVerifier, type PkceMethod } from '../crypto/pkce';
import { verifyJwt, type Jwk } from '../crypto/jose';
import { randomToken } from '../util/base64url';
import { HopRecorder, httpText, type FlowResult } from './kit';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';

const BASE = 'http://localhost:5181';
const CLIENT_ID = 'spa-dashboard';
const REDIRECT_URI = 'http://localhost:5180/callback';

/**
 * The one flow in the lab that talks to a real authorization server:
 * ASP.NET Core + OpenIddict, running on port 5181.
 *
 * Nothing here is simulated. Every verdict comes from OpenIddict, and the HTTP
 * shown on the diagram is real HTTP that actually ran through the browser's
 * network stack.
 */
export async function runOpenIddictReal(
  clock: Clock,
  opts: { pkceMethod: PkceMethod; sendWrongVerifier: boolean; requiredScope: string },
): Promise<FlowResult> {
  const rec = new HopRecorder(clock);

  // --- Is the server even running? This is this lesson's most common failure.
  let config: Record<string, unknown>;
  try {
    const res = await fetch(`${BASE}/lab/config`);
    config = (await res.json()) as Record<string, unknown>;
  } catch {
    rec.push({
      from: 'client',
      to: 'authserver',
      label: tr('Không kết nối được :5181', 'Could not connect to :5181'),
      tone: 'blocked',
      http: { kind: 'request', method: 'GET', url: `${BASE}/lab/config`, headers: {} },
      note: tr(
        'Bài này cần authorization server thật đang chạy. Mở một terminal và chạy:\n\n' +
          'cd server-dotnet/IamLab.AuthServer\n' +
          'dotnet run --urls http://localhost:5181\n\n' +
          'Rồi bấm "Chạy luồng" lại. Mọi bài học khác không cần backend.',
        'This lesson needs a real authorization server running. Open a terminal and run:\n\n' +
          'cd server-dotnet/IamLab.AuthServer\n' +
          'dotnet run --urls http://localhost:5181\n\n' +
          'Then click "Run flow" again. Every other lesson works without the backend.',
      ),
    });
    return {
      packets: rec.packets,
      outcome: 'failed',
      summary: tr(
        'Chưa thấy server ở http://localhost:5181. Xem hướng dẫn khởi động trong chặng vừa rồi.',
        "The server at http://localhost:5181 isn't reachable yet. See the startup instructions in the hop above.",
      ),
    };
  }

  rec.push({
    from: 'client',
    to: 'authserver',
    label: 'GET /lab/config',
    tone: 'normal',
    http: { kind: 'response', status: 200, statusText: 'OK', headers: { 'Content-Type': 'application/json' }, body: httpText(config) },
    note: tr(
      'Server thật đang chạy. Chú ý plain_pkce_allowed: đặt biến môi trường ' +
        'LAB_ALLOW_PLAIN_PKCE=1 rồi khởi động lại là mở lại được method plain, để so sánh.',
      'The real server is running. Notice plain_pkce_allowed: set the environment variable ' +
        'LAB_ALLOW_PLAIN_PKCE=1 and restart to re-enable the plain method, for comparison.',
    ),
  });

  const discovery = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
  rec.push({
    from: 'client',
    to: 'authserver',
    label: 'GET /.well-known/openid-configuration',
    tone: 'normal',
    http: {
      kind: 'response',
      status: 200,
      statusText: 'OK',
      headers: { 'Content-Type': 'application/json' },
      body: httpText({
        issuer: discovery.issuer,
        authorization_endpoint: discovery.authorization_endpoint,
        token_endpoint: discovery.token_endpoint,
        jwks_uri: discovery.jwks_uri,
        grant_types_supported: discovery.grant_types_supported,
        code_challenge_methods_supported: discovery.code_challenge_methods_supported,
      }),
    },
    note: tr(
      `OpenIddict tự sinh tài liệu này từ cấu hình. code_challenge_methods_supported = ` +
        `[${(discovery.code_challenge_methods_supported ?? []).join(', ')}]. ` +
        `Nếu thấy "plain" ở đây thì server đang cho phép hạ cấp PKCE - và chỉ gọi ` +
        `RequireProofKeyForCodeExchange() thôi là không đủ để bỏ nó đi.`,
      `OpenIddict generates this document automatically from its configuration. code_challenge_methods_supported = ` +
        `[${(discovery.code_challenge_methods_supported ?? []).join(', ')}]. ` +
        `If "plain" shows up here, the server is allowing a PKCE downgrade — and calling ` +
        `RequireProofKeyForCodeExchange() alone isn't enough to remove it.`,
    ),
  });

  // --- /authorize. Goes through the /lab/authorize endpoint because the browser
  //     won't let JS read the Location header of a cross-origin redirect.
  const verifier = createVerifier();
  const challenge = await challengeFrom(verifier, opts.pkceMethod);
  const state = randomToken(8);
  const authQuery =
    `response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent('openid profile read:reports')}&state=${state}` +
    (challenge ? `&code_challenge=${challenge}&code_challenge_method=${opts.pkceMethod}` : '');

  const authRes = await (await fetch(`${BASE}/lab/authorize?${authQuery}`)).json();

  rec.push({
    from: 'browser',
    to: 'authserver',
    label: `GET /connect/authorize -> ${authRes.status}`,
    tone: authRes.status === 302 ? 'normal' : 'blocked',
    http: {
      kind: 'response',
      status: authRes.status,
      statusText: authRes.status === 302 ? 'Found' : 'Bad Request',
      headers: authRes.location ? { Location: authRes.location } : {},
      body: authRes.body ?? undefined,
    },
    note:
      authRes.status === 302
        ? tr(
            `OpenIddict đã kiểm tra client_id, redirect_uri và code_challenge, rồi phát code. Method dùng: ${opts.pkceMethod}.`,
            `OpenIddict checked client_id, redirect_uri and code_challenge, then issued a code. Method used: ${opts.pkceMethod}.`,
          )
        : tr(
            `OpenIddict từ chối ngay ở front channel. Với method "${opts.pkceMethod}", server này không nhận - nó chỉ còn S256 trong danh sách cho phép.`,
            `OpenIddict rejected this right at the front channel. With method "${opts.pkceMethod}", this server won't accept it — it only has S256 left in its allow list.`,
          ),
  });

  if (authRes.status !== 302 || !authRes.location) {
    return {
      packets: rec.packets,
      outcome: 'failed',
      summary: tr(
        `OpenIddict từ chối request /authorize (${authRes.status}). Đây là server thật từ chối, không phải mock.`,
        `OpenIddict rejected the /authorize request (${authRes.status}). This is the real server rejecting it, not the mock.`,
      ),
    };
  }

  const code = new URL(authRes.location).searchParams.get('code')!;

  // --- /token. This is where PKCE is actually checked by OpenIddict.
  const sentVerifier = opts.sendWrongVerifier ? createVerifier() : verifier;
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
  });
  if (challenge) form.set('code_verifier', sentVerifier);

  rec.push({
    from: opts.sendWrongVerifier ? 'attacker' : 'client',
    to: 'authserver',
    label: opts.sendWrongVerifier ? tr('POST /connect/token (verifier sai)', 'POST /connect/token (wrong verifier)') : 'POST /connect/token',
    tone: opts.sendWrongVerifier ? 'danger' : 'normal',
    http: {
      kind: 'request',
      method: 'POST',
      url: `${BASE}/connect/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    },
    note: opts.sendWrongVerifier
      ? tr('Giả lập kẻ tấn công: có code thật nhưng trình một code_verifier tự bịa.', 'Simulating an attacker: has the real code but presents a made-up code_verifier.')
      : tr(
          'code_verifier thật, gửi qua back channel. OpenIddict sẽ băm nó và so với challenge đã lưu.',
          'The real code_verifier, sent over the back channel. OpenIddict will hash it and compare against the stored challenge.',
        ),
    tokens: [{ label: 'code_verifier', value: sentVerifier }],
  });

  const tokenRes = await fetch(`${BASE}/connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  const tokenBody = await tokenRes.json();

  rec.push({
    from: 'authserver',
    to: opts.sendWrongVerifier ? 'attacker' : 'client',
    label: `${tokenRes.status} ${tokenRes.statusText}`,
    tone: tokenRes.ok ? 'success' : 'blocked',
    http: {
      kind: 'response',
      status: tokenRes.status,
      statusText: tokenRes.statusText,
      headers: { 'Content-Type': 'application/json' },
      body: httpText(tokenBody),
    },
    note: tokenRes.ok
      ? tr('OpenIddict xác nhận code_verifier khớp và phát token.', 'OpenIddict confirmed the code_verifier matches and issued a token.')
      : tr(
          `OpenIddict từ chối: ${tokenBody.error_description ?? tokenBody.error}. Thông báo này do OpenIddict viết, không phải lab.`,
          `OpenIddict rejected it: ${tokenBody.error_description ?? tokenBody.error}. This message was written by OpenIddict, not the lab.`,
        ),
    tokens: tokenRes.ok ? [{ label: 'access_token', value: tokenBody.access_token }] : [],
  });

  if (!tokenRes.ok) {
    return {
      packets: rec.packets,
      outcome: 'success',
      summary: opts.sendWrongVerifier
        ? tr(
            `OpenIddict thật chặn code_verifier sai, đúng như mock đã nói: "${tokenBody.error_description}". Đây là lần đối chiếu quan trọng nhất của lab.`,
            `The real OpenIddict blocked the wrong code_verifier, exactly as the mock said it would: "${tokenBody.error_description}". This is the lab's most important cross-check.`,
          )
        : tr(`Không lấy được token: ${tokenBody.error_description ?? tokenBody.error}`, `Failed to get a token: ${tokenBody.error_description ?? tokenBody.error}`),
    };
  }

  // --- JWKS + verify. Uses the lab's own verify pipeline on a real token, so it
  //     still runs the same full list of checks as previous lessons.
  const jwks = (await (await fetch(`${BASE}/.well-known/jwks`)).json()) as { keys: Jwk[] };
  rec.push({
    from: 'api',
    to: 'authserver',
    label: 'GET /.well-known/jwks',
    tone: 'normal',
    http: {
      kind: 'response',
      status: 200,
      statusText: 'OK',
      headers: {},
      body: httpText(jwks.keys.map((k) => ({ kty: k.kty, alg: k.alg, use: k.use, kid: k.kid }))),
    },
    note: tr('Public key thật do OpenIddict công bố, sinh từ development signing certificate.', "A real public key published by OpenIddict, generated from the development signing certificate."),
  });

  const verification = await verifyJwt(tokenBody.access_token, {
    jwks: jwks.keys,
    issuer: String(discovery.issuer),
    audience: 'https://api.example.com',
    now: Math.floor(Date.now() / 1000),
  });

  const apiReq = rec.push({
    from: 'client',
    to: 'api',
    label: 'GET /api/me (Bearer)',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'GET',
      url: `${BASE}/api/me`,
      headers: { Authorization: `Bearer ${String(tokenBody.access_token).slice(0, 22)}...` },
    },
    note: tr(
      'Token này do OpenIddict ký. Mở tab Token để xem bộ verify của lab chạy trên nó - ' +
        'cùng 8 phép kiểm tra như các bài mock, nhưng đối tượng là token thật.',
      "This token was signed by OpenIddict. Open the Token tab to watch the lab's own verify pipeline run on it — " +
        'the same 8 checks as the mock lessons, but running against a real token.',
    ),
    tokens: [{ label: 'access_token (OpenIddict)', value: tokenBody.access_token }],
  });
  apiReq.verification = verification;

  const apiRes = await fetch(`${BASE}/api/me`, {
    headers: { Authorization: `Bearer ${tokenBody.access_token}` },
  });
  const apiBody = await apiRes.json().catch(() => ({}));

  rec.push({
    from: 'api',
    to: 'client',
    label: `${apiRes.status} ${apiRes.statusText}`,
    tone: apiRes.ok ? 'success' : 'blocked',
    http: {
      kind: 'response',
      status: apiRes.status,
      statusText: apiRes.statusText,
      headers: { 'Content-Type': 'application/json' },
      body: httpText(apiBody),
    },
    note: apiRes.ok
      ? tr('ASP.NET Core thật đã tự verify token bằng OpenIddict validation và trả dữ liệu.', 'The real ASP.NET Core server verified the token itself using OpenIddict validation and returned data.')
      : tr(`API từ chối: ${apiBody.error_description ?? apiBody.error}`, `The API rejected it: ${apiBody.error_description ?? apiBody.error}`),
  });

  return {
    packets: rec.packets,
    outcome: apiRes.ok ? 'success' : 'failed',
    summary: apiRes.ok
      ? tr(
          `Toàn bộ luồng chạy trên OpenIddict thật, và bộ verify của lab xác nhận token đạt ${verification.checks.filter((c) => c.ok).length}/${verification.checks.length} phép kiểm tra. So sánh với bài mock ở chương 2: cùng một giao thức, cùng một kết quả.`,
          `The entire flow ran on real OpenIddict, and the lab's own verifier confirms the token passed ${verification.checks.filter((c) => c.ok).length}/${verification.checks.length} checks. Compare with the mock lesson in chapter 2: same protocol, same result.`,
        )
      : tr(`Lấy được token nhưng API từ chối: ${apiBody.error_description ?? apiBody.error}`, `Got a token but the API rejected it: ${apiBody.error_description ?? apiBody.error}`),
  };
}
