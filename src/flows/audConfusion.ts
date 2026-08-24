import { challengeFrom, createVerifier } from '../crypto/pkce';
import { randomToken } from '../util/base64url';
import { decodeJwt } from '../crypto/jose';
import { HopRecorder, httpText, type FlowResult } from './kit';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';
import type { MockAuthServer } from '../server/MockAuthServer';
import type { ResourceApi } from '../server/ResourceApi';

const CLIENT_ID = 'spa-dashboard';
const REDIRECT_URI = 'https://spa.example.com/callback';

/**
 * Audience confusion: một token hoàn toàn hợp lệ, chữ ký đúng, chưa hết hạn,
 * nhưng được phát cho API khác.
 *
 * API nội bộ ở đây quyền cao hơn API công khai. Nếu nó quên kiểm tra aud thì
 * bất cứ service nào có token của API công khai đều gọi được nó.
 */
export async function runAudConfusion(
  clock: Clock,
  authServer: MockAuthServer,
  publicApi: ResourceApi,
  internalApi: ResourceApi,
  opts: { checkAudienceOnInternal: boolean; requiredScope: string },
): Promise<FlowResult> {
  const rec = new HopRecorder(clock);

  // Lấy token thật qua đúng luồng, nhưng gộp lại vì đó không phải nội dung bài này.
  const verifier = createVerifier();
  const challenge = await challengeFrom(verifier, 'S256');
  const auth = authServer.authorize({
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scope: 'openid profile read:reports',
    state: randomToken(8),
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    username: 'alice',
  });
  const code = new URL(auth.headers['Location']!).searchParams.get('code')!;
  const tok = await authServer.token({
    grantType: 'authorization_code',
    code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier,
  });
  const accessToken = (tok.body as Record<string, string>)['access_token']!;
  const aud = decodeJwt(accessToken)?.claims.aud;

  rec.push({
    from: 'client',
    to: 'authserver',
    label: tr('Đăng nhập (gộp lại)', 'Log in (collapsed)'),
    tone: 'normal',
    http: {
      kind: 'response',
      status: 200,
      statusText: 'OK',
      headers: {},
      body: httpText({ aud, scope: 'openid profile read:reports' }),
    },
    note: tr(
      `Luồng code + PKCE đầy đủ đã chạy, gộp thành một chặng vì đó không phải nội dung bài này. Điều duy nhất cần nhớ: token này có aud = "${aud}".`,
      `The full code + PKCE flow already ran, collapsed into one hop since that's not this lesson's focus. The one thing to remember: this token has aud = "${aud}".`,
    ),
    tokens: [{ label: 'access_token', value: accessToken }],
  });

  // Đúng nơi nó được phát cho.
  const okReq = rec.push({
    from: 'client',
    to: 'api',
    label: 'GET api.example.com/me',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'GET',
      url: 'https://api.example.com/me',
      headers: { Authorization: 'Bearer eyJ...' },
    },
    note: tr('Gọi đúng cái API mà token được phát cho. Đây là đường dùng bình thường.', 'Calling exactly the API this token was issued for. This is the normal path.'),
    tokens: [{ label: 'access_token', value: accessToken }],
  });
  const okRes = await publicApi.request('/me', accessToken, opts.requiredScope);
  okReq.verification = okRes.verification;
  rec.push({
    from: 'api',
    to: 'client',
    label: `${okRes.status} ${okRes.statusText}`,
    tone: okRes.status === 200 ? 'success' : 'blocked',
    http: { kind: 'response', status: okRes.status, statusText: okRes.statusText, headers: okRes.headers, body: httpText(okRes.body) },
    note: okRes.reason,
  });

  // Bây giờ đem đúng token đó sang API quyền cao hơn.
  internalApi.setAudienceCheck(opts.checkAudienceOnInternal);
  const evilReq = rec.push({
    from: 'client',
    to: 'api2',
    label: 'GET api-internal/payroll',
    tone: 'danger',
    http: {
      kind: 'request',
      method: 'GET',
      url: 'https://api-internal.example.com/payroll',
      headers: { Authorization: 'Bearer eyJ...' },
    },
    note: opts.checkAudienceOnInternal
      ? tr('Cùng một token, đem sang API nội bộ. API này có kiểm tra aud.', 'The same token, brought to the internal API. This API does check aud.')
      : tr(
          'Cùng một token, đem sang API nội bộ. API này QUÊN kiểm tra aud - chỉ verify chữ ký rồi cho qua.',
          'The same token, brought to the internal API. This API FORGOT to check aud — it only verifies the signature and lets it through.',
        ),
    tokens: [{ label: tr('access_token (dùng sai chỗ)', 'access_token (used in the wrong place)'), value: accessToken }],
  });
  const evilRes = await internalApi.request('/payroll', accessToken, opts.requiredScope);
  evilReq.verification = evilRes.verification;
  rec.push({
    from: 'api2',
    to: 'client',
    label: `${evilRes.status} ${evilRes.statusText}`,
    tone: evilRes.status === 200 ? 'danger' : 'success',
    http: { kind: 'response', status: evilRes.status, statusText: evilRes.statusText, headers: evilRes.headers, body: httpText(evilRes.body) },
    note: evilRes.reason,
  });

  const leaked = evilRes.status === 200;
  return {
    packets: rec.packets,
    outcome: leaked ? 'attacker-won' : 'success',
    summary: leaked
      ? tr(
          'API nội bộ vừa trả dữ liệu bảng lương cho một token không dành cho nó. Chữ ký đúng nên nó tưởng là an toàn - nhưng chữ ký chỉ chứng minh "ai phát ra", không chứng minh "phát cho ai". Bật lại kiểm tra aud rồi chạy lại.',
          'The internal API just returned payroll data for a token that was never meant for it. The signature is valid so it assumed that was enough — but a signature only proves "who issued this", not "who it was issued for". Turn the aud check back on and run again.',
        )
      : tr(
          'API nội bộ từ chối vì aud không khớp. Một dòng kiểm tra chặn được cả một đường leo thang quyền: service quyền thấp không dùng token của mình để gọi service quyền cao được.',
          'The internal API rejected it because aud doesn\'t match. One check blocks an entire privilege-escalation path: a low-privilege service can\'t use its own token to call a high-privilege one.',
        ),
  };
}
