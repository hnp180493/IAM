import { HopRecorder, httpText, type FlowResult } from './kit';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';
import type { SessionServer } from '../server/SessionServer';

/**
 * Đăng nhập bằng mật khẩu và cookie phiên - cách làm trước khi có OAuth.
 *
 * Bài học nằm ở chặng cuối: admin huỷ phiên, và request ngay sau đó bị chặn.
 * Với JWT tự chứa thì không có cách nào làm được điều đó.
 */
export async function runSessionCookie(
  clock: Clock,
  sessions: SessionServer,
  opts: { username: string; password: string; revokeMidway: boolean },
): Promise<FlowResult> {
  const rec = new HopRecorder(clock);

  rec.push({
    from: 'browser',
    to: 'client',
    label: 'POST /login',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'POST',
      url: 'https://spa.example.com/login',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${opts.username}&password=${'*'.repeat(opts.password.length)}`,
    },
    note: tr(
      'Mật khẩu thật của user đi thẳng vào app này. Đó là điểm khác biệt lớn nhất so với OAuth: ở đây app biết mật khẩu, nên mỗi app bạn tin là một chỗ có thể làm rò rỉ nó.',
      "The user's real password goes straight into this app. That's the biggest difference from OAuth: here the app knows the password, so every app you trust is a place it can leak from.",
    ),
  });

  const result = await sessions.login(opts.username, opts.password);

  rec.push({
    from: 'client',
    to: 'client',
    label: tr('PBKDF2 100.000 vòng', 'PBKDF2 100,000 rounds'),
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'INTERNAL',
      url: 'derive(password, salt, iterations=100000)',
      headers: {},
      body: result.hashPreview ? `hash = ${result.hashPreview}...` : undefined,
    },
    note: tr(
      'Server không lưu mật khẩu, chỉ lưu bản băm cùng salt riêng của từng user. PBKDF2 cố tình chạy chậm để kẻ có được database cũng không dò ngược nổi hàng loạt. Đây là PBKDF2-HMAC-SHA256 thật của WebCrypto đang chạy trong máy bạn.',
      "The server never stores the password, only a hash with a per-user salt. PBKDF2 is deliberately slow so that even someone who steals the database can't brute-force it at scale. This is real PBKDF2-HMAC-SHA256 from WebCrypto, running in your machine right now.",
    ),
  });

  if (!result.ok || !result.sid) {
    rec.push({
      from: 'client',
      to: 'browser',
      label: '401 Unauthorized',
      tone: 'blocked',
      http: { kind: 'response', status: 401, statusText: 'Unauthorized', headers: {}, body: httpText({ error: result.reason }) },
      note: result.reason,
    });
    return { packets: rec.packets, outcome: 'failed', summary: result.reason };
  }

  const sid = result.sid;

  rec.push({
    from: 'client',
    to: 'browser',
    label: '200 + Set-Cookie',
    tone: 'success',
    http: {
      kind: 'response',
      status: 200,
      statusText: 'OK',
      headers: { 'Set-Cookie': `sid=${sid}; HttpOnly; Secure; SameSite=Lax; Path=/` },
      body: httpText({ ok: true }),
    },
    note: tr(
      'Cookie chỉ chứa một chuỗi vô nghĩa. Toàn bộ thông tin phiên nằm ở server. HttpOnly để JavaScript không đọc được (chặn XSS lấy phiên), SameSite=Lax để chặn CSRF cơ bản.',
      'The cookie only carries a meaningless string. All session information lives on the server. HttpOnly keeps JavaScript from reading it (blocking XSS session theft), SameSite=Lax blocks basic CSRF.',
    ),
    tokens: [{ label: tr('sid (không phải JWT)', 'sid (not a JWT)'), value: sid }],
  });

  const first = sessions.check(sid);
  rec.push({
    from: 'browser',
    to: 'client',
    label: 'GET /profile',
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://spa.example.com/profile', headers: { Cookie: `sid=${sid}` } },
    note: tr('Mỗi request server phải tra sid trong bảng phiên. Tốn một lần tra, đổi lại nắm được trạng thái.', 'On every request the server must look up the sid in its session table. It costs one lookup, in exchange for holding real state.'),
  });
  rec.push({
    from: 'client',
    to: 'browser',
    label: `${first.status} ${first.ok ? 'OK' : 'Unauthorized'}`,
    tone: first.ok ? 'success' : 'blocked',
    http: { kind: 'response', status: first.status, statusText: first.ok ? 'OK' : 'Unauthorized', headers: {}, body: httpText({ user: first.username }) },
    note: first.reason,
  });

  if (!opts.revokeMidway) {
    return {
      packets: rec.packets,
      outcome: 'success',
      summary: tr(
        'Đăng nhập bằng phiên thành công. Bật "Huỷ phiên giữa luồng" để thấy điều JWT không làm được.',
        'Session-based login succeeded. Turn on "Revoke mid-flow" to see the one thing a JWT cannot do.',
      ),
    };
  }

  // Đây là toàn bộ lý do bài học này tồn tại.
  sessions.revoke(sid);
  rec.push({
    from: 'client',
    to: 'client',
    label: tr('Admin huỷ phiên', 'Admin revokes the session'),
    tone: 'danger',
    http: { kind: 'request', method: 'INTERNAL', url: `revoke(${sid})`, headers: {} },
    note: tr(
      'Nhân viên bị cho nghỉ việc. Admin bấm huỷ phiên. Server chỉ cần đánh dấu một dòng trong bảng.',
      'An employee gets let go. The admin clicks to revoke the session. The server only needs to flag one row in a table.',
    ),
  });

  const second = sessions.check(sid);
  rec.push({
    from: 'browser',
    to: 'client',
    label: tr('GET /profile (lần 2)', 'GET /profile (2nd time)'),
    tone: 'normal',
    http: { kind: 'request', method: 'GET', url: 'https://spa.example.com/profile', headers: { Cookie: `sid=${sid}` } },
    note: tr('Cookie vẫn nguyên như cũ, client không biết gì đã xảy ra.', 'The cookie is exactly the same as before — the client has no idea anything happened.'),
  });
  rec.push({
    from: 'client',
    to: 'browser',
    label: `${second.status} Unauthorized`,
    tone: 'blocked',
    http: { kind: 'response', status: second.status, statusText: 'Unauthorized', headers: {}, body: httpText({ error: second.reason }) },
    note: second.reason,
  });

  return {
    packets: rec.packets,
    outcome: 'success',
    summary: tr(
      'Huỷ phiên có hiệu lực ngay ở request kế tiếp. Với access token JWT thì không: nó vẫn sống tới khi exp trôi qua, và không có ai gọi nó về được. Đó là cái giá của việc bỏ trạng thái ở server.',
      'Revoking a session takes effect right on the very next request. Not so for a JWT access token: it stays alive until exp passes, and nobody can call it back. That is the price of dropping server-side state.',
    ),
  };
}
