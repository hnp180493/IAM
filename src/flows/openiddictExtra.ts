import { challengeFrom, createVerifier } from '../crypto/pkce';
import { randomToken } from '../util/base64url';
import { HopRecorder, httpText, type FlowResult } from './kit';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';

const BASE = 'http://localhost:5181';
const CLIENT_ID = 'spa-dashboard';
const REDIRECT_URI = 'http://localhost:5180/callback';

const decodeClaims = (jwt: string): Record<string, unknown> => {
  try {
    const p = jwt.split('.')[1];
    return p ? (JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>) : {};
  } catch {
    return {};
  }
};

/** Checks the server; pushes an error hop and returns false if it can't connect. */
async function ensureServer(rec: HopRecorder): Promise<boolean> {
  try {
    await (await fetch(`${BASE}/lab/config`)).json();
    return true;
  } catch {
    rec.push({
      from: 'client',
      to: 'authserver',
      label: tr('Không kết nối được :5181', 'Could not connect to :5181'),
      tone: 'blocked',
      http: { kind: 'request', method: 'GET', url: `${BASE}/lab/config`, headers: {} },
      note: tr(
        'Bài này cần server thật:\n\ncd server-dotnet/IamLab.AuthServer\ndotnet run --urls http://localhost:5181',
        'This lesson needs the real server:\n\ncd server-dotnet/IamLab.AuthServer\ndotnet run --urls http://localhost:5181',
      ),
    });
    return false;
  }
}

/**
 * Client Credentials (M2M) on real OpenIddict. No user: a service authenticates
 * itself with client_id + secret, gets a token for itself, calls an M2M API.
 */
export async function runOpenIddictM2M(clock: Clock): Promise<FlowResult> {
  const rec = new HopRecorder(clock);
  if (!(await ensureServer(rec))) return { packets: rec.packets, outcome: 'failed', summary: tr('Chưa thấy server ở :5181.', 'Server at :5181 not reachable yet.') };

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: 'service-worker',
    client_secret: 's3rv1ce-s3cr3t',
    scope: 'reports.api',
  });
  rec.push({
    from: 'client',
    to: 'authserver',
    label: 'POST /token (client_credentials)',
    tone: 'normal',
    http: { kind: 'request', method: 'POST', url: `${BASE}/connect/token`, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() },
    note: tr(
      'Service tự xác thực bằng client_id + client_secret. Không có /authorize, không người dùng, không PKCE - client confidential nên giữ được secret.',
      'The service authenticates itself with client_id + client_secret. No /authorize, no user, no PKCE — it is a confidential client, so it can hold a secret.',
    ),
  });

  const tokRes = await fetch(`${BASE}/connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const tok = (await tokRes.json()) as Record<string, string>;
  const at = tok['access_token'];
  rec.push({
    from: 'authserver',
    to: 'client',
    label: `${tokRes.status} ${tokRes.statusText}`,
    tone: tokRes.ok ? 'success' : 'blocked',
    http: { kind: 'response', status: tokRes.status, statusText: tokRes.statusText, headers: { 'Content-Type': 'application/json' }, body: httpText(tok) },
    note: tokRes.ok
      ? tr(
          `Access token phát cho chính service. Mở tab Token: sub = "${decodeClaims(at ?? '')['sub']}" là client_id, không phải người dùng.`,
          `An access token issued to the service itself. Open the Token tab: sub = "${decodeClaims(at ?? '')['sub']}" is the client_id, not a user.`,
        )
      : tr(`Bị từ chối: ${tok['error_description'] ?? tok['error']}`, `Rejected: ${tok['error_description'] ?? tok['error']}`),
    tokens: at ? [{ label: 'access_token (M2M)', value: at }] : [],
  });
  if (!at) return { packets: rec.packets, outcome: 'failed', summary: tr('Không lấy được token M2M.', 'Failed to get an M2M token.') };

  rec.push({
    from: 'client',
    to: 'api',
    label: 'GET /api/service',
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: `${BASE}/api/service`, headers: { Authorization: 'Bearer eyJ...' } },
    note: tr('Gọi endpoint M2M, cần scope reports.api.', 'Calling the M2M endpoint, which requires the reports.api scope.'),
    tokens: [{ label: 'access_token', value: at }],
  });
  const apiRes = await fetch(`${BASE}/api/service`, { headers: { Authorization: `Bearer ${at}` } });
  const apiBody = await apiRes.json().catch(() => ({}));
  rec.push({
    from: 'api',
    to: 'client',
    label: `${apiRes.status} ${apiRes.statusText}`,
    tone: apiRes.ok ? 'success' : 'blocked',
    http: { kind: 'response', status: apiRes.status, statusText: apiRes.statusText, headers: {}, body: httpText(apiBody) },
    note: apiRes.ok ? tr('API nhận token M2M và trả dữ liệu.', 'The API accepted the M2M token and returned data.') : tr('API từ chối.', 'The API rejected it.'),
  });

  return {
    packets: rec.packets,
    outcome: apiRes.ok ? 'success' : 'failed',
    summary: apiRes.ok
      ? tr(
          'Client credentials: service tự lấy token bằng secret. Không dùng cho luồng có người dùng - ở đó phải là authorization code + PKCE.',
          'Client credentials: the service gets its own token using a secret. Never use this for user-facing flows — those need authorization code + PKCE.',
        )
      : tr('Không gọi được API M2M.', 'Failed to call the M2M API.'),
  };
}

/**
 * Refresh rotation + reuse detection on real OpenIddict (leeway=0). The
 * mock-vs-real cross-check: reuse is caught immediately and the whole chain is revoked.
 */
export async function runOpenIddictRefresh(clock: Clock): Promise<FlowResult> {
  const rec = new HopRecorder(clock);
  if (!(await ensureServer(rec))) return { packets: rec.packets, outcome: 'failed', summary: tr('Chưa thấy server ở :5181.', 'Server at :5181 not reachable yet.') };

  const verifier = createVerifier();
  const challenge = await challengeFrom(verifier, 'S256');
  const state = randomToken(8);
  const authQuery =
    `response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent('openid profile read:reports offline_access')}&state=${state}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;
  const auth = await (await fetch(`${BASE}/lab/authorize?${authQuery}`)).json();
  const code = auth.location ? new URL(auth.location).searchParams.get('code') : null;
  rec.push({
    from: 'client',
    to: 'authserver',
    label: tr('Đăng nhập (offline_access) — gộp', 'Login (offline_access) — collapsed'),
    tone: 'normal',
    http: { kind: 'response', status: 200, statusText: 'OK', headers: {}, body: httpText({ note: tr('scope có offline_access nên server phát refresh token', 'the scope includes offline_access, so the server issues a refresh token') }) },
    note: tr(
      'Phải xin scope offline_access thì OpenIddict mới phát refresh token. Thiếu nó là không có gì để refresh.',
      'You must request the offline_access scope for OpenIddict to issue a refresh token. Without it, there is nothing to refresh.',
    ),
  });
  if (!code) return { packets: rec.packets, outcome: 'failed', summary: tr('Không lấy được code.', 'Failed to get a code.') };

  const doToken = (b: Record<string, string>) =>
    fetch(`${BASE}/connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b) });

  const t0 = (await (await doToken({ grant_type: 'authorization_code', code, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, code_verifier: verifier })).json()) as Record<string, string>;
  const rt0 = t0['refresh_token'] ?? '';
  rec.push({
    from: 'authserver',
    to: 'client',
    label: '200 + refresh_token',
    tone: 'success',
    http: { kind: 'response', status: 200, statusText: 'OK', headers: {}, body: httpText({ refresh_token: rt0.slice(0, 20) + '...' }) },
    note: tr('Có refresh token đầu tiên. Coi đây là bản mà kẻ tấn công sẽ trộm.', 'The first refresh token. Treat this as the copy an attacker will steal.'),
    tokens: [{ label: 'refresh_token', value: rt0 }],
  });

  const r1Res = await doToken({ grant_type: 'refresh_token', client_id: CLIENT_ID, refresh_token: rt0 });
  const r1 = (await r1Res.json()) as Record<string, string>;
  const rt1 = r1['refresh_token'] ?? '';
  rec.push({
    from: 'client',
    to: 'authserver',
    label: tr('POST /token (refresh lần 1)', 'POST /token (refresh #1)'),
    tone: 'success',
    http: { kind: 'response', status: r1Res.status, statusText: r1Res.statusText, headers: {}, body: httpText({ refresh_token: rt1.slice(0, 20) + '...' }) },
    note: tr(
      'Client thật dùng refresh, nhận access token mới VÀ refresh token mới. Bản cũ vừa bị xoay.',
      'The real client uses the refresh token, receives a new access token AND a new refresh token. The old copy was just rotated out.',
    ),
    tokens: rt1 ? [{ label: tr('refresh MỚI', 'NEW refresh'), value: rt1 }] : [],
  });

  const evilRes = await doToken({ grant_type: 'refresh_token', client_id: CLIENT_ID, refresh_token: rt0 });
  const evil = (await evilRes.json()) as Record<string, string>;
  rec.push({
    from: 'attacker',
    to: 'authserver',
    label: tr('POST /token (refresh CŨ bị trộm)', 'POST /token (stolen OLD refresh)'),
    tone: 'danger',
    http: { kind: 'response', status: evilRes.status, statusText: evilRes.statusText, headers: {}, body: httpText(evil) },
    note: evilRes.ok
      ? tr('Kẻ tấn công dùng lại được bản cũ - reuse detection KHÔNG hoạt động (còn leeway).', "The attacker reused the old copy successfully — reuse detection is NOT working (there's still a leeway window).")
      : tr(
          `OpenIddict bắt được reuse: ${evil['error_description'] ?? evil['error']}. Toàn bộ chuỗi bị thu hồi.`,
          `OpenIddict caught the reuse: ${evil['error_description'] ?? evil['error']}. The entire chain was revoked.`,
        ),
  });

  const afterRes = await doToken({ grant_type: 'refresh_token', client_id: CLIENT_ID, refresh_token: rt1 });
  const after = (await afterRes.json()) as Record<string, string>;
  rec.push({
    from: 'client',
    to: 'authserver',
    label: tr('Client thật refresh lại', 'The real client refreshes again'),
    tone: afterRes.ok ? 'success' : 'blocked',
    http: { kind: 'response', status: afterRes.status, statusText: afterRes.statusText, headers: {}, body: httpText(after) },
    note: afterRes.ok
      ? tr('Client thật vẫn dùng được.', 'The real client still works.')
      : tr(
          'Refresh của client thật cũng bị thu hồi. Cái giá của reuse detection: phát hiện trộm thì cả nhà đăng nhập lại - nhưng kẻ trộm bị chặn.',
          "The real client's refresh was revoked too. The price of reuse detection: once theft is detected, everyone has to log in again — but the thief is blocked.",
        ),
  });

  const detected = !evilRes.ok;
  return {
    packets: rec.packets,
    outcome: detected ? 'success' : 'failed',
    summary: detected
      ? tr(
          'OpenIddict (leeway=0) phát hiện refresh bị dùng lại và thu hồi cả chuỗi. So với mock ở chương 5: cùng cơ chế, cùng kết quả - đây là server thật.',
          'OpenIddict (leeway=0) detected the reused refresh token and revoked the whole chain. Compare with the mock in chapter 5: same mechanism, same result — this is the real server.',
        )
      : tr('Reuse không bị bắt - kiểm tra SetRefreshTokenReuseLeeway trong Program.cs.', 'Reuse was not caught — check SetRefreshTokenReuseLeeway in Program.cs.'),
  };
}
