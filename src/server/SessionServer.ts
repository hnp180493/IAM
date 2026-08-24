import { b64uEncode, randomBytes, randomToken, utf8 } from '../util/base64url';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';

/** Kiểu byte do randomBytes trả về: nó tự sở hữu ArrayBuffer nên WebCrypto nhận. */
type Bytes = ReturnType<typeof randomBytes>;

interface StoredUser {
  username: string;
  salt: Bytes;
  hash: string;
  iterations: number;
}

interface Session {
  sid: string;
  username: string;
  createdAt: number;
  lastSeen: number;
  revoked: boolean;
}

/**
 * Cách đăng nhập kiểu cũ: mật khẩu băm ở server, phiên nằm trong bộ nhớ server,
 * client chỉ giữ một cái sid vô nghĩa trong cookie.
 *
 * Đối lập với JWT ở đúng một điểm quyết định: ở đây server nắm trạng thái, nên
 * huỷ phiên là có hiệu lực tức thì. Băm mật khẩu là PBKDF2 thật của WebCrypto,
 * không phải giả.
 */
export class SessionServer {
  private users = new Map<string, StoredUser>();
  private sessions = new Map<string, Session>();
  readonly iterations = 100_000;

  constructor(private clock: Clock) {}

  async addUser(username: string, password: string): Promise<void> {
    const salt = randomBytes(16);
    this.users.set(username, {
      username,
      salt,
      hash: await this.derive(password, salt, this.iterations),
      iterations: this.iterations,
    });
  }

  /** PBKDF2-HMAC-SHA256 thật. Chậm là cố ý: đó là toàn bộ mục đích của nó. */
  private async derive(password: string, salt: Bytes, iterations: number): Promise<string> {
    const material = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      material,
      256,
    );
    return b64uEncode(new Uint8Array(bits));
  }

  async login(
    username: string,
    password: string,
    /** sid mà client mang sẵn (cookie). Dùng để mô phỏng session fixation. */
    existingSid?: string,
  ): Promise<{ ok: boolean; sid?: string; reason: string; hashPreview?: string; regenerated?: boolean }> {
    const user = this.users.get(username);
    if (!user) {
      // Cùng một thông báo cho user sai và mật khẩu sai, để không tiết lộ
      // tài khoản nào tồn tại.
      return { ok: false, reason: tr('Sai tên đăng nhập hoặc mật khẩu.', 'Wrong username or password.') };
    }
    const attempt = await this.derive(password, user.salt, user.iterations);
    if (attempt !== user.hash) {
      return { ok: false, reason: tr('Sai tên đăng nhập hoặc mật khẩu.', 'Wrong username or password.'), hashPreview: attempt.slice(0, 22) };
    }

    // Server dễ tổn thương giữ nguyên sid mà client đã mang tới (session
    // fixation). Server an toàn luôn phát sid mới sau khi đăng nhập, vô hiệu
    // hoá mọi sid mà kẻ tấn công đã gài trước.
    const reuse = this.regenerateOnLogin === false && existingSid && !this.sessions.has(existingSid);
    const sid = reuse ? existingSid! : `sid-${randomToken(18)}`;
    this.sessions.set(sid, {
      sid,
      username,
      createdAt: this.clock.nowSec(),
      lastSeen: this.clock.nowSec(),
      revoked: false,
    });
    return {
      ok: true,
      sid,
      reason: reuse
        ? tr(
            `Mật khẩu khớp. Nhưng server GIỮ NGUYÊN sid client mang tới (${sid.slice(0, 12)}...) - đây là lỗ session fixation.`,
            `Password matched. But the server KEPT the sid the client arrived with (${sid.slice(0, 12)}...) — this is the session fixation hole.`,
          )
        : tr(
            `Mật khẩu khớp sau ${this.iterations.toLocaleString('vi-VN')} vòng PBKDF2. Server phát sid MỚI, vô hiệu sid cũ.`,
            `Password matched after ${this.iterations.toLocaleString('en-US')} rounds of PBKDF2. The server issued a NEW sid, invalidating the old one.`,
          ),
      hashPreview: attempt.slice(0, 22),
      regenerated: !reuse,
    };
  }

  /** Red Team / exploit đặt false để mô phỏng lỗ session fixation. */
  regenerateOnLogin = true;

  /** Mỗi request phải tra phiên trong bộ nhớ server - đó là chỗ tốn, và cũng là chỗ mạnh. */
  check(sid: string | undefined): { ok: boolean; status: number; reason: string; username?: string } {
    if (!sid) return { ok: false, status: 401, reason: tr('Request không mang cookie phiên nào.', 'The request carries no session cookie.') };
    const s = this.sessions.get(sid);
    if (!s) return { ok: false, status: 401, reason: tr('sid không tồn tại trong bảng phiên của server.', "This sid isn't in the server's session table.") };
    if (s.revoked) {
      return {
        ok: false,
        status: 401,
        reason: tr(
          'Phiên đã bị huỷ. Server tra bảng thấy revoked nên chặn ngay từ request này - không phải đợi hết hạn.',
          'The session has been revoked. The server looked it up, saw it marked revoked, and blocked it right on this request — no waiting for expiry.',
        ),
      };
    }
    s.lastSeen = this.clock.nowSec();
    return { ok: true, status: 200, reason: tr(`Phiên hợp lệ, chủ phiên là ${s.username}.`, `Valid session, owned by ${s.username}.`), username: s.username };
  }

  /** Điều mà JWT tự chứa không làm được. */
  revoke(sid: string): boolean {
    const s = this.sessions.get(sid);
    if (!s) return false;
    s.revoked = true;
    return true;
  }

  activeCount(): number {
    return [...this.sessions.values()].filter((s) => !s.revoked).length;
  }

  reset(): void {
    this.sessions.clear();
  }
}
