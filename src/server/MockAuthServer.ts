import { generateSigningKey, signJwt, toJwk, type Jwk, type SigningKey } from '../crypto/jose';
import { verifyChallenge, type PkceMethod } from '../crypto/pkce';
import { randomToken } from '../util/base64url';
import type { Clock } from '../core/Clock';
import { tr } from '../i18n';

export interface ClientRegistration {
  clientId: string;
  redirectUris: string[];
  /** Public clients (SPAs, native apps) cannot keep a secret. */
  isPublic: boolean;
  secret?: string;
  /** Nơi auth server gọi tới để báo "phiên này đã đăng xuất". */
  backchannelLogoutUri?: string;
}

/** Phiên SSO nằm ở auth server, không nằm ở app. Đó là toàn bộ cơ chế SSO. */
export interface SsoSession {
  sid: string;
  username: string;
  createdAt: number;
  /** Những client đã nhận token trong phiên này - danh sách cần thông báo khi logout. */
  grantedTo: Set<string>;
}

export interface UserRecord {
  sub: string;
  username: string;
  name: string;
  email: string;
  roles: string[];
}

interface AuthorizationCode {
  code: string;
  clientId: string;
  sub: string;
  scope: string;
  redirectUri: string;
  challenge: string | null;
  method: PkceMethod;
  issuedAt: number;
  used: boolean;
}

export interface HttpResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body?: unknown;
  /** Why the server answered this way - surfaced verbatim in the UI. */
  reason: string;
}

export interface ServerConfig {
  issuer: string;
  audience: string;
  accessTokenTtl: number;
  idTokenTtl: number;
}

/**
 * A deliberately small OAuth 2.0 / OIDC authorization server. It is a mock in
 * the sense that it speaks no real HTTP and stores nothing durably - but every
 * decision it makes is a genuine check against genuine cryptography. A code
 * rejected here is rejected because SHA-256 said so.
 */
export class MockAuthServer {
  readonly config: ServerConfig;
  private clock: Clock;
  private key!: SigningKey;
  private jwk!: Jwk;
  private clients = new Map<string, ClientRegistration>();
  private users = new Map<string, UserRecord>();
  private codes = new Map<string, AuthorizationCode>();
  private issuedTokens: { jti: string; sub: string; expiresAt: number }[] = [];
  /** Red Team mode gắn vào; không có thì server luôn ở trạng thái siết. */
  posture?: {
    flags: {
      allowPlainPkce: boolean;
      requirePkce: boolean;
      codeSingleUse: boolean;
      redirectExactMatch: boolean;
      accessTokenTtl: number;
    };
  };

  constructor(clock: Clock, config: Partial<ServerConfig> = {}) {
    this.clock = clock;
    this.config = {
      issuer: 'https://id.example.com',
      audience: 'https://api.example.com',
      accessTokenTtl: 300,
      idTokenTtl: 300,
      ...config,
    };
  }

  async init(): Promise<void> {
    this.key = await generateSigningKey(`k-${randomToken(4)}`, this.clock.nowMs());
    this.jwk = await toJwk(this.key);

    this.registerClient({
      clientId: 'spa-dashboard',
      redirectUris: ['https://spa.example.com/callback'],
      isPublic: true,
      backchannelLogoutUri: 'https://spa.example.com/backchannel-logout',
    });
    // App thứ hai cố tình không khai backchannel_logout_uri: đó là cách phiên
    // zombie xuất hiện trong thực tế.
    this.registerClient({
      clientId: 'wiki',
      redirectUris: ['https://wiki.example.com/callback'],
      isPublic: true,
    });
    this.addUser({
      sub: 'user-8f21',
      username: 'alice',
      name: 'Alice Nguyen',
      email: 'alice@example.com',
      roles: ['reader', 'writer'],
    });
  }

  registerClient(c: ClientRegistration): void {
    this.clients.set(c.clientId, c);
  }

  addUser(u: UserRecord): void {
    this.users.set(u.username, u);
  }

  get signingKid(): string {
    return this.key.kid;
  }

  /**
   * Chuỗi đại diện cho public key (modulus). Đây là thứ một server dễ tổn thương
   * đem ra làm khoá HMAC, và cũng là thứ AI CŨNG lấy được từ JWKS - đó chính là
   * lý do alg-confusion nguy hiểm. Trả về chuỗi base64url của modulus.
   */
  publicKeyMaterial(): string {
    return this.jwk.n ?? '';
  }

  /** GET /.well-known/jwks.json */
  jwks(): { keys: Jwk[] } {
    return { keys: [this.jwk] };
  }

  discovery(): Record<string, unknown> {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${this.config.issuer}/authorize`,
      token_endpoint: `${this.config.issuer}/token`,
      jwks_uri: `${this.config.issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
    };
  }

  /**
   * GET /authorize - the front channel. Note what it does NOT check: it never
   * sees the code_verifier. It only records the challenge, which is the entire
   * reason PKCE survives an intercepted redirect.
   */
  authorize(params: {
    clientId: string;
    redirectUri: string;
    scope: string;
    state: string;
    codeChallenge: string | null;
    codeChallengeMethod: PkceMethod;
    username: string;
  }): HttpResult {
    const client = this.clients.get(params.clientId);
    if (!client) {
      return this.err(400, 'Bad Request', 'invalid_client', tr(`Không có client_id "${params.clientId}".`, `No such client_id "${params.clientId}".`));
    }

    // Exact-match redirect_uri. Prefix or substring matching here is how open
    // redirects turn into account takeover.
    const exact = this.posture?.flags.redirectExactMatch ?? true;
    const redirectOk = exact
      ? client.redirectUris.includes(params.redirectUri)
      : client.redirectUris.some((u) => params.redirectUri.startsWith(u.slice(0, u.indexOf('/', 8))));
    if (!redirectOk) {
      return this.err(
        400,
        'Bad Request',
        'invalid_request',
        tr(`redirect_uri "${params.redirectUri}" không nằm trong danh sách đã đăng ký của client này. Phải khớp tuyệt đối - so khớp theo tiền tố là lỗ open redirect.`, `redirect_uri "${params.redirectUri}" is not on this client's registered list. It must match exactly — matching by prefix is an open-redirect hole.`),
      );
    }

    if (this.posture) {
      if (this.posture.flags.requirePkce && params.codeChallenge === null) {
        return this.err(400, 'Bad Request', 'invalid_request', tr('Server yêu cầu PKCE nhưng request không có code_challenge.', 'The server requires PKCE but the request has no code_challenge.'));
      }
      if (!this.posture.flags.allowPlainPkce && params.codeChallengeMethod === 'plain') {
        return this.err(400, 'Bad Request', 'invalid_request', tr('code_challenge_method=plain không nằm trong danh sách cho phép. Chỉ S256.', 'code_challenge_method=plain is not in the allowed list. S256 only.'));
      }
    }

    const user = this.users.get(params.username);
    if (!user) {
      return this.err(401, 'Unauthorized', 'access_denied', tr(`Không có user "${params.username}".`, `No such user "${params.username}".`));
    }

    const code: AuthorizationCode = {
      code: `code-${randomToken(16)}`,
      clientId: params.clientId,
      sub: user.sub,
      scope: params.scope,
      redirectUri: params.redirectUri,
      challenge: params.codeChallenge,
      method: params.codeChallengeMethod,
      issuedAt: this.clock.nowSec(),
      used: false,
    };
    this.codes.set(code.code, code);

    const location = `${params.redirectUri}?code=${code.code}&state=${encodeURIComponent(params.state)}`;
    return {
      status: 302,
      statusText: 'Found',
      headers: { Location: location },
      reason:
        params.codeChallenge === null
          ? tr('Đã phát code, không gắn PKCE. Ai nhìn thấy redirect này là đổi được thành token.', 'Code issued with no PKCE binding. Anyone who sees this redirect can redeem it for a token.')
          : tr(`Đã phát code, gắn với code_challenge (${params.codeChallengeMethod}). code_verifier vẫn nằm trong client.`, `Code issued, bound to code_challenge (${params.codeChallengeMethod}). code_verifier stays with the client.`),
    };
  }

  /** POST /token - the back channel, where PKCE is actually enforced. */
  async token(params: {
    grantType: string;
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier?: string;
  }): Promise<HttpResult> {
    if (params.grantType !== 'authorization_code') {
      return this.err(400, 'Bad Request', 'unsupported_grant_type', tr(`Không hỗ trợ grant_type "${params.grantType}".`, `grant_type "${params.grantType}" is not supported.`));
    }

    const record = this.codes.get(params.code);
    if (!record) {
      return this.err(400, 'Bad Request', 'invalid_grant', tr('Không có authorization code này.', 'No such authorization code.'));
    }

    // Single use. Replay of a code is a signal the code leaked.
    if (record.used && (this.posture?.flags.codeSingleUse ?? true)) {
      this.codes.delete(params.code);
      return this.err(
        400,
        'Bad Request',
        'invalid_grant',
        tr('Code này đã đổi rồi. Có lần thứ hai nghĩa là code đã bị lộ - server thật sẽ thu hồi toàn bộ phiên ở đây.', 'This code was already redeemed. A second time means it leaked — a real server would revoke the whole grant here.'),
      );
    }

    if (record.clientId !== params.clientId) {
      return this.err(400, 'Bad Request', 'invalid_grant', tr('Code được phát cho một client_id khác.', 'This code was issued to a different client_id.'));
    }
    if (record.redirectUri !== params.redirectUri) {
      return this.err(400, 'Bad Request', 'invalid_grant', tr('redirect_uri không khớp cái đã dùng ở /authorize.', 'redirect_uri does not match the one used at /authorize.'));
    }
    if (this.clock.nowSec() - record.issuedAt > 60) {
      return this.err(400, 'Bad Request', 'invalid_grant', tr('Authorization code đã hết hạn (chỉ sống 60 giây).', 'Authorization code has expired (only lives 60 seconds).'));
    }

    const pkce = await verifyChallenge(params.codeVerifier, record.challenge, record.method);
    if (!pkce.ok) {
      return this.err(400, 'Bad Request', 'invalid_grant', pkce.reason);
    }

    record.used = true;
    const now = this.clock.nowSec();
    const user = [...this.users.values()].find((u) => u.sub === record.sub)!;
    const jti = randomToken(8);
    const ttl = this.posture?.flags.accessTokenTtl ?? this.config.accessTokenTtl;

    const accessToken = await signJwt(
      {
        iss: this.config.issuer,
        sub: user.sub,
        aud: this.config.audience,
        exp: now + ttl,
        iat: now,
        nbf: now,
        jti,
        scope: record.scope,
        client_id: record.clientId,
        roles: user.roles,
      },
      this.key,
    );

    const idToken = await signJwt(
      {
        iss: this.config.issuer,
        sub: user.sub,
        aud: record.clientId,
        exp: now + this.config.idTokenTtl,
        iat: now,
        auth_time: now,
        name: user.name,
        email: user.email,
        preferred_username: user.username,
      },
      this.key,
    );

    this.issuedTokens.push({ jti, sub: user.sub, expiresAt: now + ttl });
    const refresh = this.mintRefresh(user.sub, record.scope);

    return {
      status: 200,
      statusText: 'OK',
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: {
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refresh,
        token_type: 'Bearer',
        expires_in: ttl,
        scope: record.scope,
      },
      reason: tr(`${pkce.reason} Đã phát access token và ID token, ký RS256 bằng kid "${this.key.kid}".`, `${pkce.reason} Issued an access token and ID token, signed RS256 with kid "${this.key.kid}".`),
    };
  }

  // ---- Refresh token rotation ----

  /** Chuỗi refresh -> (còn dùng được?, family). Reuse của một token đã xoay là dấu hiệu trộm. */
  private refreshTokens = new Map<string, { sub: string; scope: string; used: boolean; family: string }>();
  /** Red Team / exploit đặt false để tắt rotation (lỗ refresh reuse). */
  refreshRotation = true;

  private mintRefresh(sub: string, scope: string, family = randomToken(6)): string {
    const rt = `rt-${randomToken(24)}`;
    this.refreshTokens.set(rt, { sub, scope, used: false, family });
    return rt;
  }

  /**
   * POST /token grant_type=refresh_token.
   *
   * An toàn: mỗi refresh dùng đúng một lần, đổi lấy cặp token mới + refresh mới
   * (rotation). Nếu một refresh đã xoay bị dùng lại, cả "family" bị thu hồi -
   * vì hoặc client hoặc kẻ trộm đang giữ bản cũ, không thể phân biệt nên huỷ hết.
   */
  async refresh(token: string): Promise<HttpResult> {
    const rec = this.refreshTokens.get(token);
    if (!rec) {
      return this.err(400, 'Bad Request', 'invalid_grant', tr('Refresh token không tồn tại hoặc đã bị thu hồi.', 'Refresh token does not exist or has been revoked.'));
    }

    if (rec.used) {
      if (this.refreshRotation) {
        // Reuse detection: huỷ cả family.
        for (const [k, v] of this.refreshTokens) if (v.family === rec.family) this.refreshTokens.delete(k);
        return this.err(
          400,
          'Bad Request',
          'invalid_grant',
          tr('Refresh token này đã được xoay rồi. Dùng lại nghĩa là nó đã lộ - toàn bộ family vừa bị thu hồi. Client thật giờ cũng phải đăng nhập lại.', 'This refresh token has already been rotated. Reusing it means it leaked — the whole family was just revoked. The real client must now log in again too.'),
        );
      }
      // Lỗ: không rotation, token cũ vẫn xài được vô hạn.
    } else if (this.refreshRotation) {
      rec.used = true;
    }

    const now = this.clock.nowSec();
    const user = [...this.users.values()].find((u) => u.sub === rec.sub);
    if (!user) return this.err(400, 'Bad Request', 'invalid_grant', tr('Chủ token không còn tồn tại.', 'The token owner no longer exists.'));

    const ttl = this.posture?.flags.accessTokenTtl ?? this.config.accessTokenTtl;
    const jti = randomToken(8);
    const accessToken = await signJwt(
      { iss: this.config.issuer, sub: user.sub, aud: this.config.audience, exp: now + ttl, iat: now, nbf: now, jti, scope: rec.scope, client_id: 'spa-dashboard', roles: user.roles },
      this.key,
    );
    this.issuedTokens.push({ jti, sub: user.sub, expiresAt: now + ttl });

    // Rotation phát refresh mới cùng family; không rotation thì trả lại chính nó.
    const newRefresh = this.refreshRotation ? this.mintRefresh(rec.sub, rec.scope, rec.family) : token;

    return {
      status: 200,
      statusText: 'OK',
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: { access_token: accessToken, refresh_token: newRefresh, token_type: 'Bearer', expires_in: ttl, scope: rec.scope },
      reason: this.refreshRotation
        ? tr('Đã phát access token mới và refresh token mới. Refresh cũ vừa dùng đã bị đánh dấu, không xài lại được.', 'Issued a new access token and a new refresh token. The refresh just used has been marked spent and cannot be reused.')
        : tr('Đã phát access token mới. Refresh token GIỮ NGUYÊN (không rotation) - dùng lại bao nhiêu lần cũng được.', 'Issued a new access token. The refresh token is UNCHANGED (no rotation) — it can be reused as many times as you like.'),
    };
  }

  // ---- SSO ----

  private sso: SsoSession | null = null;

  /** Người dùng nhập mật khẩu tại chính auth server. App không bao giờ thấy nó. */
  ssoLogin(username: string): SsoSession {
    this.sso = { sid: `sso-${randomToken(14)}`, username, createdAt: this.clock.nowSec(), grantedTo: new Set() };
    return this.sso;
  }

  ssoSession(): SsoSession | null {
    return this.sso;
  }

  noteGrant(clientId: string): void {
    this.sso?.grantedTo.add(clientId);
  }

  /**
   * Đăng xuất. Phần khó của SSO không phải đăng nhập mà là chỗ này: huỷ phiên ở
   * auth server xong thì các app còn lại phải được cho biết, nếu không chúng
   * vẫn giữ phiên nội bộ của riêng chúng.
   */
  ssoLogout(backChannel: boolean): { notified: string[]; stale: string[]; username: string | null } {
    if (!this.sso) return { notified: [], stale: [], username: null };
    const username = this.sso.username;
    const apps = [...this.sso.grantedTo];
    this.sso = null;

    if (!backChannel) {
      return { notified: [], stale: apps, username };
    }
    const notified = apps.filter((id) => this.clients.get(id)?.backchannelLogoutUri);
    const stale = apps.filter((id) => !this.clients.get(id)?.backchannelLogoutUri);
    return { notified, stale, username };
  }

  /** Thử thách cần bật/tắt được cái này lúc chạy để thấy hệ quả. */
  setBackchannelLogoutUri(clientId: string, uri: string | undefined): void {
    const c = this.clients.get(clientId);
    if (!c) return;
    if (uri) c.backchannelLogoutUri = uri;
    else delete c.backchannelLogoutUri;
  }

  client(clientId: string): ClientRegistration | undefined {
    return this.clients.get(clientId);
  }

  activeTokenCount(): number {
    const now = this.clock.nowSec();
    return this.issuedTokens.filter((t) => t.expiresAt > now).length;
  }

  soonestExpiry(): number | null {
    const now = this.clock.nowSec();
    const live = this.issuedTokens.filter((t) => t.expiresAt > now).map((t) => t.expiresAt - now);
    return live.length ? Math.min(...live) : null;
  }

  reset(): void {
    this.codes.clear();
    this.issuedTokens = [];
    this.refreshTokens.clear();
    this.sso = null;
  }

  private err(status: number, statusText: string, error: string, reason: string): HttpResult {
    return {
      status,
      statusText,
      headers: { 'Content-Type': 'application/json' },
      body: { error, error_description: reason },
      reason,
    };
  }
}
