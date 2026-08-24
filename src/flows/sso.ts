import { challengeFrom, createVerifier } from '../crypto/pkce';
import { randomToken } from '../util/base64url';
import { HopRecorder, httpText, type FlowResult } from './kit';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';
import type { MockAuthServer } from '../server/MockAuthServer';
import type { Lane } from '../core/types';

interface AppSpec {
  clientId: string;
  redirectUri: string;
  lane: Lane;
  name: string;
}

const APP1: AppSpec = { clientId: 'spa-dashboard', redirectUri: 'https://spa.example.com/callback', lane: 'client', name: 'App 1' };
const APP2: AppSpec = { clientId: 'wiki', redirectUri: 'https://wiki.example.com/callback', lane: 'client2', name: 'App 2' };

/** One code + PKCE login, collapsed down to 4 hops. */
async function loginApp(
  rec: HopRecorder,
  authServer: MockAuthServer,
  app: AppSpec,
  username: string,
  isFirst: boolean,
): Promise<string | null> {
  const verifier = createVerifier();
  const challenge = await challengeFrom(verifier, 'S256');
  const state = randomToken(8);

  rec.push({
    from: app.lane,
    to: 'browser',
    label: `${app.name}: 302 -> /authorize`,
    tone: 'normal',
    http: {
      kind: 'response',
      status: 302,
      statusText: 'Found',
      headers: {
        Location: `https://id.example.com/authorize?client_id=${app.clientId}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`,
      },
    },
    note: tr(`${app.name} không tự xử lý đăng nhập. Nó đẩy người dùng sang auth server.`, `${app.name} doesn't handle login itself. It sends the user over to the auth server.`),
  });

  const hadSession = authServer.ssoSession() !== null;

  rec.push({
    from: 'browser',
    to: 'authserver',
    label: hadSession ? tr('GET /authorize (kèm cookie SSO)', 'GET /authorize (with SSO cookie)') : 'GET /authorize',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'GET',
      url: `https://id.example.com/authorize?client_id=${app.clientId}&...`,
      headers: hadSession ? { Cookie: `sso=${authServer.ssoSession()!.sid}` } : { Host: 'id.example.com' },
    },
    note: hadSession
      ? tr(
          'Trình duyệt tự gửi cookie phiên SSO của domain id.example.com. Auth server nhận ra người này đã đăng nhập.',
          "The browser automatically sends the id.example.com domain's SSO session cookie. The auth server recognizes this person is already logged in.",
        )
      : tr(
          'Chưa có cookie phiên nào cho domain id.example.com, nên auth server sẽ phải hỏi mật khẩu.',
          "There's no session cookie yet for the id.example.com domain, so the auth server will have to ask for a password.",
        ),
  });

  if (!hadSession) {
    rec.push({
      from: 'authserver',
      to: 'browser',
      label: tr('Hiện form đăng nhập', 'Show login form'),
      tone: 'normal',
      http: { kind: 'response', status: 200, statusText: 'OK', headers: { 'Content-Type': 'text/html' }, body: '<form method="post" action="/login">...' },
      note: tr(
        'Form này thuộc auth server, không thuộc app. Mật khẩu được gõ vào domain id.example.com ' +
          'và không app nào thấy nó. Đây là lý do quan trọng nhất để dùng OAuth thay vì tự làm đăng nhập.',
        'This form belongs to the auth server, not the app. The password is typed into the id.example.com domain ' +
          "and no app ever sees it. This is the single most important reason to use OAuth instead of rolling your own login.",
      ),
    });
    const session = authServer.ssoLogin(username);
    rec.push({
      from: 'browser',
      to: 'authserver',
      label: 'POST /login',
      tone: 'normal',
      http: {
        kind: 'request',
        method: 'POST',
        url: 'https://id.example.com/login',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${username}&password=********`,
      },
      note: tr(
        `Đăng nhập xong. Auth server tạo phiên SSO ${session.sid} và đặt cookie cho chính domain của nó.`,
        `Login complete. The auth server creates SSO session ${session.sid} and sets a cookie for its own domain.`,
      ),
    });
  }

  const auth = authServer.authorize({
    clientId: app.clientId,
    redirectUri: app.redirectUri,
    scope: 'openid profile read:reports',
    state,
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    username,
  });

  if (auth.status !== 302) {
    rec.push({
      from: 'authserver',
      to: 'browser',
      label: `${auth.status} ${auth.statusText}`,
      tone: 'blocked',
      http: { kind: 'response', status: auth.status, statusText: auth.statusText, headers: auth.headers, body: httpText(auth.body) },
      note: auth.reason,
    });
    return null;
  }

  rec.push({
    from: 'authserver',
    to: app.lane,
    label: hadSession ? tr('302 + code (KHÔNG hỏi mật khẩu)', '302 + code (NO password prompt)') : '302 + code',
    tone: hadSession ? 'success' : 'normal',
    http: { kind: 'response', status: 302, statusText: 'Found', headers: auth.headers },
    note: hadSession
      ? tr(
          `Phiên SSO còn sống nên auth server phát code ngay. ${app.name} không hề hỏi mật khẩu, và người dùng chỉ thấy màn hình nhoáng qua.`,
          `The SSO session is still alive, so the auth server issues a code right away. ${app.name} never asked for a password, and the user only sees a flash of a screen.`,
        )
      : auth.reason,
  });

  const code = new URL(auth.headers['Location']!).searchParams.get('code')!;
  const tok = await authServer.token({
    grantType: 'authorization_code',
    code,
    clientId: app.clientId,
    redirectUri: app.redirectUri,
    codeVerifier: verifier,
  });

  if (tok.status !== 200) return null;
  authServer.noteGrant(app.clientId);

  const body = tok.body as Record<string, string>;
  rec.push({
    from: 'authserver',
    to: app.lane,
    label: `${app.name}: 200 + token`,
    tone: 'success',
    http: { kind: 'response', status: 200, statusText: 'OK', headers: tok.headers, body: httpText(tok.body) },
    note: tr(
      `${app.name} giờ có token riêng của nó. ${isFirst ? 'Đây là app đầu tiên nên phải trả giá một lần đăng nhập.' : 'App này không phải trả giá gì cả.'}`,
      `${app.name} now has its own token. ${isFirst ? 'This is the first app, so it had to pay the price of one login.' : "This app didn't have to pay any price at all."}`,
    ),
    tokens: [{ label: 'access_token', value: body['access_token']! }],
  });

  return body['access_token']!;
}

/** One login, two apps. */
export async function runSsoTwoApps(clock: Clock, authServer: MockAuthServer): Promise<FlowResult> {
  const rec = new HopRecorder(clock);

  rec.push({
    from: 'browser',
    to: 'client',
    label: tr('Mở App 1', 'Open App 1'),
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://spa.example.com/', headers: {} },
    note: tr('Chưa đăng nhập ở đâu cả.', "Not logged in anywhere yet."),
  });
  await loginApp(rec, authServer, APP1, 'alice', true);

  rec.push({
    from: 'browser',
    to: 'client2',
    label: tr('Mở App 2', 'Open App 2'),
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://wiki.example.com/', headers: {} },
    note: tr(
      'App hoàn toàn khác, domain khác, không chia sẻ cookie hay database nào với App 1.',
      'A completely different app, a different domain, sharing no cookies or database with App 1.',
    ),
  });
  await loginApp(rec, authServer, APP2, 'alice', false);

  return {
    packets: rec.packets,
    outcome: 'success',
    summary: tr(
      'App 2 lấy được token mà không hỏi mật khẩu, vì phiên đăng nhập không nằm ở app nào - nó nằm ở auth server. ' +
        'SSO chỉ là: nhiều app cùng đi hỏi một chỗ, và chỗ đó nhớ bạn.',
      "App 2 got a token without asking for a password, because the login session doesn't live in any app — it lives in the auth server. " +
        'SSO is simply this: many apps ask the same place, and that place remembers you.',
    ),
  };
}

/** Logout: the genuinely hard part of SSO. */
export async function runSsoLogout(
  clock: Clock,
  authServer: MockAuthServer,
  opts: { backChannel: boolean; registerWikiLogout?: boolean },
): Promise<FlowResult> {
  const rec = new HopRecorder(clock);

  authServer.setBackchannelLogoutUri(
    'wiki',
    opts.registerWikiLogout ? 'https://wiki.example.com/backchannel-logout' : undefined,
  );

  // Both apps are already logged in, collapsed since that was the previous lesson's content.
  authServer.ssoLogin('alice');
  authServer.noteGrant('spa-dashboard');
  authServer.noteGrant('wiki');
  rec.push({
    from: 'authserver',
    to: 'browser',
    label: tr('Đã đăng nhập cả 2 app (gộp)', 'Already logged into both apps (collapsed)'),
    tone: 'normal',
    http: { kind: 'response', status: 200, statusText: 'OK', headers: {}, body: httpText({ sso_session: 'active', apps: ['spa-dashboard', 'wiki'] }) },
    note: tr(
      'Trạng thái ban đầu: phiên SSO đang sống, cả App 1 và App 2 đều đã nhận token và đều đang giữ phiên nội bộ riêng.',
      'Starting state: the SSO session is alive, and both App 1 and App 2 have received tokens and each hold their own internal session.',
    ),
  });

  rec.push({
    from: 'browser',
    to: 'client',
    label: tr('Bấm "Đăng xuất" ở App 1', 'Click "Log out" on App 1'),
    tone: 'normal',
    http: { kind: 'request', method: 'POST', url: 'https://spa.example.com/logout', headers: {} },
    note: tr(
      'App 1 xoá phiên nội bộ của nó, rồi đẩy người dùng sang endpoint đăng xuất của auth server.',
      "App 1 clears its own internal session, then sends the user over to the auth server's logout endpoint.",
    ),
  });

  const result = authServer.ssoLogout(opts.backChannel);

  rec.push({
    from: 'client',
    to: 'authserver',
    label: 'GET /connect/endsession',
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://id.example.com/connect/endsession?id_token_hint=eyJ...', headers: {} },
    note: tr(
      'Auth server huỷ phiên SSO. Tới đây thì lần đăng nhập tiếp theo sẽ phải nhập mật khẩu lại.',
      'The auth server destroys the SSO session. From here, the next login will have to enter a password again.',
    ),
  });

  if (opts.backChannel) {
    for (const clientId of result.notified) {
      rec.push({
        from: 'authserver',
        to: clientId === 'wiki' ? 'client2' : 'client',
        label: `POST backchannel_logout -> ${clientId}`,
        tone: 'success',
        http: {
          kind: 'request',
          method: 'POST',
          url: authServer.client(clientId)!.backchannelLogoutUri!,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'logout_token=eyJhbGciOiJSUzI1NiIsInR5cCI6ImxvZ291dCtqd3QifQ...',
        },
        note: tr(
          'Auth server chủ động gọi tới app, không đi qua trình duyệt. Nhờ vậy nó hoạt động cả khi ' +
            'người dùng đã đóng tab. App nhận logout_token, verify chữ ký, rồi xoá phiên nội bộ.',
          'The auth server calls the app directly, not through the browser. This is why it still works even after ' +
            'the user has closed the tab. The app receives the logout_token, verifies the signature, then clears its internal session.',
        ),
      });
    }
  }

  for (const clientId of result.stale) {
    rec.push({
      from: 'authserver',
      to: clientId === 'wiki' ? 'client2' : 'client',
      label: `${clientId}: ${tr('KHÔNG được thông báo', 'NOT notified')}`,
      tone: 'danger',
      http: {
        kind: 'response',
        status: 0,
        statusText: tr('không có request nào', 'no request sent'),
        headers: {},
        body: httpText({
          client_id: clientId,
          backchannel_logout_uri: null,
          result: tr('phiên nội bộ vẫn sống', 'internal session still alive'),
        }),
      },
      note: opts.backChannel
        ? tr(
            `Client "${clientId}" không khai backchannel_logout_uri, nên auth server không có cách nào báo cho nó. Phiên nội bộ của nó vẫn sống.`,
            `Client "${clientId}" never registered a backchannel_logout_uri, so the auth server has no way to tell it. Its internal session is still alive.`,
          )
        : tr(
            'Back-channel logout đang tắt. Auth server huỷ phiên của chính nó và không báo cho ai.',
            "Back-channel logout is off. The auth server destroys its own session and notifies nobody.",
          ),
    });
  }

  const zombie = result.stale.includes('wiki');
  rec.push({
    from: 'browser',
    to: 'client2',
    label: tr('Mở lại App 2', 'Open App 2 again'),
    tone: zombie ? 'danger' : 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://wiki.example.com/dashboard', headers: { Cookie: 'app2_session=...' } },
    note: tr('Người dùng tưởng mình đã đăng xuất khỏi mọi thứ. Thử mở lại App 2.', 'The user thinks they logged out of everything. Try opening App 2 again.'),
  });
  rec.push({
    from: 'client2',
    to: 'browser',
    label: zombie ? tr('200 OK — vẫn đang đăng nhập', '200 OK — still logged in') : tr('302 -> đăng nhập lại', '302 -> log in again'),
    tone: zombie ? 'danger' : 'success',
    http: zombie
      ? { kind: 'response', status: 200, statusText: 'OK', headers: {}, body: httpText({ user: 'alice', note: tr('phiên nội bộ của App 2 chưa bị xoá', "App 2's internal session was never cleared") }) }
      : { kind: 'response', status: 302, statusText: 'Found', headers: { Location: 'https://id.example.com/authorize?...' } },
    note: zombie
      ? tr(
          'Phiên zombie. Người dùng đã bấm đăng xuất nhưng App 2 vẫn coi họ là đã đăng nhập. Trên máy dùng chung, người tiếp theo mở App 2 lên là vào được tài khoản của alice.',
          "A zombie session. The user clicked logout, but App 2 still treats them as logged in. On a shared machine, the next person to open App 2 walks straight into alice's account.",
        )
      : tr(
          'App 2 đã xoá phiên nội bộ khi nhận logout_token, nên nó đẩy người dùng đi đăng nhập lại. Đúng như mong đợi.',
          'App 2 cleared its internal session upon receiving the logout_token, so it sends the user to log in again. Exactly as expected.',
        ),
  });

  return {
    packets: rec.packets,
    outcome: zombie ? 'attacker-won' : 'success',
    summary: zombie
      ? tr(
          'Đăng xuất chỉ có hiệu lực ở nơi được thông báo. Thiếu back-channel logout thì "đăng xuất" chỉ là đăng xuất khỏi một app. Còn access token đã phát thì vẫn hợp lệ tới khi exp trôi qua - đăng xuất không thu hồi được nó.',
          'Logout only takes effect where it was notified. Without back-channel logout, "logging out" only means logging out of one app. Any access token already issued stays valid until exp passes — logout cannot revoke it.',
        )
      : tr(
          'Cả hai app đều đã đóng phiên vì cả hai đều nhận được logout_token. Lưu ý phần vẫn chưa giải quyết: access token đã phát ra vẫn hợp lệ tới khi hết hạn, vì không ai gọi được JWT về.',
          "Both apps closed their sessions because both received the logout_token. Note what's still unsolved: an access token already issued remains valid until it expires, because nobody can call a JWT back.",
        ),
  };
}
