import { challengeFrom, createVerifier, type PkceMethod } from '../crypto/pkce';
import { decodeJwt, verifyJwt, signHs256, signJwt, generateSigningKey, toJwk, type SigningKey } from '../crypto/jose';
import { b64uJson, randomToken, utf8 } from '../util/base64url';
import { parse, flagStr, type ParsedCommand } from '../console/parse';
import { PolicyEngine, type PolicyModel } from './PolicyEngine';
import { WebVulnServer, WEB_HARDENED } from './WebVulnServer';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';
import type { MockAuthServer } from '../server/MockAuthServer';
import type { ResourceApi } from '../server/ResourceApi';
import type { SessionServer } from '../server/SessionServer';
import type { Posture } from './Posture';

export interface LogEntry {
  cmd: string;
  ok: boolean;
  status?: number;
  /** Dữ liệu có cấu trúc để mục tiêu thử thách kiểm tra được. */
  data: Record<string, unknown>;
}

export interface Line {
  text: string;
  tone: 'out' | 'dim' | 'ok' | 'err' | 'warn' | 'echo';
}

/**
 * Trạng thái dùng chung cho console gõ tay.
 *
 * Đây là phần thay thế dropdown: người học phải tự dựng request, tự giữ
 * code_verifier, tự quyết định gửi cái gì. Không có sẵn đáp án để bấm thử.
 */
export class LabSession {
  private policy = new PolicyEngine();
  /** Web app dễ tổn thương cho track OWASP; đọc cùng bộ cờ posture. */
  private web = new WebVulnServer(() => {
    const f = this.posture?.flags;
    if (!f) return WEB_HARDENED;
    return {
      paramQueries: f.paramQueries,
      escapeOutput: f.escapeOutput,
      ssrfGuard: f.ssrfGuard,
      pathConfine: f.pathConfine,
      cmdSafeArgs: f.cmdSafeArgs,
    };
  });
  readonly log: LogEntry[] = [];
  /** Token đặt tên, gọi lại bằng @tên. */
  readonly tokens = new Map<string, string>();

  private lastVerifier: string | null = null;
  private lastMethod: PkceMethod = 'S256';
  private lastCode: string | null = null;
  private lastSid: string | null = null;
  private lastRefresh: string | null = null;
  private prevRefresh: string | null = null;
  /** Cặp khoá của kẻ tấn công, sinh khi cần cho bài jku/embedded-jwk. */
  private attackerKey: SigningKey | null = null;

  constructor(
    private clock: Clock,
    private authServer: MockAuthServer,
    private publicApi: ResourceApi,
    private internalApi: ResourceApi,
    private sessions: SessionServer,
    /** Chỉ Red Team mode truyền vào; các thử thách khác luôn chạy ở trạng thái siết. */
    private posture?: Posture,
  ) {}

  /** Đồng bộ cờ posture xuống các server, để lỗ hổng có tác dụng thật. */
  private applyPosture(): void {
    if (!this.posture) return;
    this.authServer.refreshRotation = this.posture.flags.refreshRotation;
    this.sessions.regenerateOnLogin = this.posture.flags.sessionRegenerate;
  }

  reset(): void {
    this.log.length = 0;
    this.tokens.clear();
    this.lastVerifier = null;
    this.lastCode = null;
    this.lastSid = null;
    this.attackerKey = null;
    this.lastRefresh = null;
    this.prevRefresh = null;
    this.authServer.reset();
    this.publicApi.reset();
    this.internalApi.reset();
    this.web.reset();
    // Xoá override để posture (Red Team, exploit) quyết định. Lesson tự đặt lại.
    this.publicApi.clearAudienceOverride();
    this.internalApi.clearAudienceOverride();
    this.sessions.reset();
  }

  /** Cho phép @tên ở mọi chỗ nhận token. */
  private resolve(ref: string | undefined): string | undefined {
    if (!ref) return undefined;
    if (ref.startsWith('@')) return this.tokens.get(ref.slice(1));
    return ref;
  }

  private record(cmd: string, ok: boolean, data: Record<string, unknown>, status?: number): void {
    this.log.push({ cmd, ok, data, ...(status !== undefined ? { status } : {}) });
  }

  async run(raw: string): Promise<Line[]> {
    const p = parse(raw);
    const head = p.words[0];
    if (!head) return [];

    this.applyPosture();

    try {
      switch (head) {
        case 'help': return this.help(p);
        case 'authorize': return await this.authorize(p);
        case 'token': return await this.token(p);
        case 'refresh': return await this.refreshCmd(p);
        case 'jwt': return await this.jwt(p);
        case 'curl': return await this.curl(p);
        case 'policy': return this.policyEval(p);
        case 'login': return await this.login(p);
        case 'profile': return this.profile(p);
        case 'revoke': return this.revoke(p);
        case 'tokens': return this.listTokens();
        case 'jwks': return this.jwks();
        case 'discovery': return this.discovery();
        case 'pubkey': return this.pubkey();
        case 'status': return this.status();
        case 'audit': return this.auditCmd();
        case 'harden': return this.hardenCmd(p);
        case 'app': return this.app(p, raw);
        default:
          return [{ text: tr(`Không có lệnh "${head}". Gõ help để xem danh sách.`, `No command "${head}". Type help to see the list.`), tone: 'err' }];
      }
    } catch (e) {
      return [{ text: tr(`Lỗi khi chạy lệnh: ${String(e)}`, `Error running command: ${String(e)}`), tone: 'err' }];
    }
  }

  // ---------------------------------------------------------------- help

  private help(p: ParsedCommand): Line[] {
    const topic = p.words[1];
    const H: Record<string, string[]> = {
      authorize: [
        'authorize [--pkce S256|plain|none] [--scope "..."] [--redirect URI] [--client ID] [--user alice]',
        tr('  Gọi /authorize. In ra URL đầy đủ (kể cả code_challenge) rồi lưu code nếu thành công.',
          '  Calls /authorize. Prints the full URL (including code_challenge) and saves the code on success.'),
        tr('  code_verifier được sinh và giữ lại; xem bằng: authorize --show-verifier',
          '  code_verifier is generated and kept; view it with: authorize --show-verifier'),
      ],
      token: [
        'token [--code X] [--verifier Y] [--redirect URI] [--client ID]',
        tr('  Gọi /token. Không truyền --code thì dùng code mới nhất, --verifier thì dùng verifier mới nhất.',
          '  Calls /token. Without --code it uses the latest code; without --verifier it uses the latest verifier.'),
        tr('  Muốn giả làm kẻ tấn công: token --code <code> --verifier <chuỗi tự bịa>',
          '  To play the attacker: token --code <code> --verifier <a made-up string>'),
      ],
      jwt: [
        tr('jwt decode <@tên|token>            đọc header + payload, không verify',
          'jwt decode <@name|token>            read header + payload, no verification'),
        tr('jwt verify <@tên|token> [--aud A] [--iss I]   verify đầy đủ, in từng phép kiểm tra',
          'jwt verify <@name|token> [--aud A] [--iss I]   full verification, prints every check'),
        tr('jwt forge <@tên> --set k=v [--set-header k=v]  sửa claim, GIỮ chữ ký cũ, lưu thành @forged',
          'jwt forge <@name> --set k=v [--set-header k=v]  edit a claim, KEEP the old signature, saved as @forged'),
      ],
      curl: [
        'curl <path> [--token @tên] [--api public|internal] [--scope-required S]',
        tr('  Gọi resource API. Ví dụ: curl /me --token @access', '  Calls a resource API. Example: curl /me --token @access'),
      ],
      policy: [
        'policy eval <user> <action> <resource> [--model rbac|abac|rebac|all] [--hour H]',
        tr('  Ví dụ: policy eval alice delete doc:42 --model all', '  Example: policy eval alice delete doc:42 --model all'),
      ],
      session: [
        tr('login <user> <password>     đăng nhập kiểu cũ, trả về sid', 'login <user> <password>     old-style login, returns an sid'),
        tr('profile [--sid S]           gọi endpoint cần phiên', 'profile [--sid S]           calls an endpoint that requires a session'),
        tr('revoke [--sid S]            huỷ phiên ngay lập tức', 'revoke [--sid S]            revokes the session immediately'),
      ],
      app: [
        tr('Web app dễ tổn thương — track OWASP. Bọc payload có dấu cách/nháy trong "..."',
          'The vulnerable web app — OWASP track. Wrap any payload with spaces/quotes in "..."'),
        tr('app login <user> <pass>       SQL injection (auth bypass)', 'app login <user> <pass>       SQL injection (auth bypass)'),
        tr('app search <term>             SQL injection (UNION exfiltration)', 'app search <term>             SQL injection (UNION exfiltration)'),
        tr('app comment <text> ; app render   Stored XSS', 'app comment <text> ; app render   Stored XSS'),
        tr('app fetch <url>               SSRF', 'app fetch <url>               SSRF'),
        tr('app download <path>           Path traversal', 'app download <path>           Path traversal'),
        tr('app ping <host>               Command injection', 'app ping <host>               Command injection'),
      ],
    };

    if (topic && H[topic]) return H[topic]!.map((text) => ({ text, tone: 'out' as const }));

    return [
      { text: tr('Lệnh có sẵn — gõ help <lệnh> để xem chi tiết', 'Available commands — type help <command> for detail'), tone: 'warn' },
      { text: '', tone: 'dim' },
      { text: tr('  authorize    gọi /authorize, sinh PKCE, lấy code', '  authorize    calls /authorize, generates PKCE, gets a code'), tone: 'out' },
      { text: tr('  token        đổi code lấy token', '  token        exchanges a code for a token'), tone: 'out' },
      { text: '  jwt          decode | verify | forge', tone: 'out' },
      { text: tr('  curl         gọi resource API kèm bearer token', '  curl         calls a resource API with a bearer token'), tone: 'out' },
      { text: tr('  policy       eval quyền theo rbac | abac | rebac', '  policy       evaluate authorization via rbac | abac | rebac'), tone: 'out' },
      { text: tr('  login        đăng nhập kiểu phiên (help session)', '  login        session-style login (help session)'), tone: 'out' },
      { text: tr('  app          web app dễ tổn thương — SQLi/XSS/SSRF/... (help app)', '  app          the vulnerable web app — SQLi/XSS/SSRF/... (help app)'), tone: 'out' },
      { text: tr('  tokens       liệt kê token đang giữ', '  tokens       lists the tokens currently held'), tone: 'out' },
      { text: tr('  jwks         xem public key server công bố', "  jwks         view the server's published public keys"), tone: 'out' },
      { text: tr('  discovery    xem tài liệu cấu hình của auth server', "  discovery    view the auth server's configuration document"), tone: 'out' },
      { text: '', tone: 'dim' },
      { text: tr('Token lưu theo tên, gọi lại bằng @tên. Ví dụ: jwt decode @access', 'Tokens are saved by name, referenced with @name. Example: jwt decode @access'), tone: 'dim' },
      { text: tr('Tab để hoàn tất lệnh, mũi tên lên/xuống để xem lại lịch sử.', 'Tab to autocomplete, up/down arrows for command history.'), tone: 'dim' },
    ];
  }

  // ---------------------------------------------------------- authorize

  private async authorize(p: ParsedCommand): Promise<Line[]> {
    const method = (flagStr(p, 'pkce', 'S256') || 'S256') as PkceMethod;
    if (!['S256', 'plain', 'none'].includes(method)) {
      return [{ text: tr(`--pkce phải là S256, plain hoặc none (nhận "${method}").`, `--pkce must be S256, plain or none (got "${method}").`), tone: 'err' }];
    }

    const client = flagStr(p, 'client', 'spa-dashboard');
    const redirect = flagStr(p, 'redirect', 'https://spa.example.com/callback');
    const scope = flagStr(p, 'scope', 'openid profile read:reports');
    const user = flagStr(p, 'user', 'alice');
    const state = randomToken(8);

    const verifier = createVerifier();
    this.lastVerifier = verifier;
    this.lastMethod = method;

    const finish = (challenge: string | null): Line[] => {
      const url =
        `https://id.example.com/authorize?response_type=code&client_id=${client}` +
        `&redirect_uri=${encodeURIComponent(redirect)}&scope=${encodeURIComponent(scope)}&state=${state}` +
        (challenge ? `&code_challenge=${challenge}&code_challenge_method=${method}` : '');

      const res = this.authServer.authorize({
        clientId: client,
        redirectUri: redirect,
        scope,
        state,
        codeChallenge: challenge,
        codeChallengeMethod: method,
        username: user,
      });

      const lines: Line[] = [
        { text: `GET ${url}`, tone: 'dim' },
      ];

      if (res.status !== 302) {
        this.record('authorize', false, { method, redirect, scope, client }, res.status);
        lines.push({ text: `${res.status} ${res.statusText}`, tone: 'err' });
        lines.push({ text: res.reason, tone: 'err' });
        return lines;
      }

      const code = new URL(res.headers['Location']!).searchParams.get('code')!;
      this.lastCode = code;
      this.record('authorize', true, { method, redirect, scope, client, code, challenge }, 302);

      lines.push({ text: `302 Found`, tone: 'ok' });
      lines.push({ text: `Location: ${res.headers['Location']}`, tone: 'out' });
      lines.push({ text: res.reason, tone: 'dim' });
      if (method === 'S256') {
        lines.push({
          text: tr('code_verifier đang giữ trong client (không nằm trong URL trên). Cần nó ở bước token.',
            'code_verifier is being held by the client (not in the URL above). It is needed at the token step.'),
          tone: 'dim',
        });
      } else if (method === 'plain') {
        lines.push({ text: tr('Chú ý: với plain, code_challenge trong URL CHÍNH LÀ code_verifier.',
          'Note: with plain, the code_challenge in the URL IS the code_verifier.'), tone: 'warn' });
      }
      if (p.flags['show-verifier']) {
        lines.push({ text: `code_verifier = ${verifier}`, tone: 'warn' });
      }
      return lines;
    };

    // SHA-256 thật, nên bước này phải await.
    return finish(await challengeFrom(verifier, method));
  }

  // ------------------------------------------------------------- token

  private async token(p: ParsedCommand): Promise<Line[]> {
    const code = flagStr(p, 'code') || this.lastCode || '';
    const verifierFlag = p.flags['verifier'];
    const verifier =
      typeof verifierFlag === 'string' ? verifierFlag : this.lastMethod === 'none' ? undefined : (this.lastVerifier ?? undefined);
    const client = flagStr(p, 'client', 'spa-dashboard');
    const redirect = flagStr(p, 'redirect', 'https://spa.example.com/callback');

    if (!code) {
      return [{ text: tr('Chưa có code. Chạy authorize trước, hoặc truyền --code.', 'No code yet. Run authorize first, or pass --code.'), tone: 'err' }];
    }

    const res = await this.authServer.token({
      grantType: 'authorization_code',
      code,
      clientId: client,
      redirectUri: redirect,
      ...(verifier ? { codeVerifier: verifier } : {}),
    });

    const lines: Line[] = [
      { text: `POST https://id.example.com/token`, tone: 'dim' },
      {
        text: `  grant_type=authorization_code&code=${code.slice(0, 18)}...` + (verifier ? `&code_verifier=${verifier.slice(0, 14)}...` : ''),
        tone: 'dim',
      },
    ];

    if (res.status !== 200) {
      this.record('token', false, { code, verifierGiven: Boolean(verifier), reason: res.reason }, res.status);
      lines.push({ text: `${res.status} ${res.statusText}`, tone: 'err' });
      lines.push({ text: res.reason, tone: 'err' });
      return lines;
    }

    const body = res.body as Record<string, string>;
    this.tokens.set('access', body['access_token']!);
    this.tokens.set('id', body['id_token']!);
    this.lastRefresh = body['refresh_token'] ?? null;
    this.record('token', true, { code, verifierGiven: Boolean(verifier), scope: body['scope'] }, 200);

    lines.push({ text: '200 OK', tone: 'ok' });
    lines.push({ text: tr(`access_token  -> @access  (${body['access_token']!.length} ký tự)`, `access_token  -> @access  (${body['access_token']!.length} chars)`), tone: 'out' });
    lines.push({ text: `id_token      -> @id`, tone: 'out' });
    lines.push({ text: tr(`refresh_token = ${(body['refresh_token'] ?? '').slice(0, 16)}...  (dùng: refresh)`, `refresh_token = ${(body['refresh_token'] ?? '').slice(0, 16)}...  (use: refresh)`), tone: 'out' });
    lines.push({ text: `expires_in    = ${body['expires_in']}s   scope = ${body['scope']}`, tone: 'out' });
    lines.push({ text: res.reason, tone: 'dim' });
    return lines;
  }

  // ----------------------------------------------------------- refresh

  private async refreshCmd(p: ParsedCommand): Promise<Line[]> {
    // --reuse phát lại đúng refresh vừa bị xoay (mô phỏng kẻ trộm giữ bản cũ).
    const reuse = Boolean(p.flags['reuse']);
    const rt = reuse ? this.prevRefresh ?? '' : p.words[1] ?? this.lastRefresh ?? '';
    if (!rt) {
      return [{
        text: reuse
          ? tr('Chưa có refresh cũ để dùng lại. Gõ refresh một lần trước.', 'No old refresh token to reuse yet. Run refresh once first.')
          : tr('Chưa có refresh token. Chạy authorize + token trước, hoặc: refresh <token>', 'No refresh token yet. Run authorize + token first, or: refresh <token>'),
        tone: 'err',
      }];
    }

    const res = await this.authServer.refresh(rt);
    this.record('refresh', res.status === 200, { tokenPrefix: rt.slice(0, 10) }, res.status);

    const lines: Line[] = [{ text: 'POST /token grant_type=refresh_token', tone: 'dim' }];
    if (res.status !== 200) {
      lines.push({ text: `${res.status} ${res.statusText}`, tone: 'err' }, { text: res.reason, tone: 'err' });
      return lines;
    }
    const body = res.body as Record<string, string>;
    this.tokens.set('access', body['access_token']!);
    const newRt = body['refresh_token'] ?? null;
    lines.push({ text: '200 OK', tone: 'ok' });
    lines.push({ text: tr(`access_token mới -> @access`, `new access_token -> @access`), tone: 'out' });
    if (newRt && newRt !== rt) lines.push({ text: tr(`refresh MỚI = ${newRt.slice(0, 16)}... (cái cũ hết dùng được — thử: refresh --reuse)`, `NEW refresh = ${newRt.slice(0, 16)}... (the old one no longer works — try: refresh --reuse)`), tone: 'out' });
    else lines.push({ text: tr(`refresh giữ nguyên (không rotation)`, `refresh unchanged (no rotation)`), tone: 'warn' });
    // Nhớ token vừa tiêu để --reuse phát lại nó.
    if (newRt && newRt !== rt) this.prevRefresh = rt;
    this.lastRefresh = newRt;
    lines.push({ text: res.reason, tone: 'dim' });
    return lines;
  }

  // --------------------------------------------------------------- jwt

  private async jwt(p: ParsedCommand): Promise<Line[]> {
    const sub = p.words[1];
    const target = this.resolve(p.words[2]);

    if (sub === 'decode') {
      if (!target) return [{ text: tr('Cần token. Ví dụ: jwt decode @access', 'Need a token. Example: jwt decode @access'), tone: 'err' }];
      const d = decodeJwt(target);
      if (!d) return [{ text: tr('Không phải JWT ba khối.', 'Not a three-part JWT.'), tone: 'err' }];
      this.record('jwt decode', true, { claims: d.claims, header: d.header });
      return [
        { text: tr('header', 'header'), tone: 'warn' },
        { text: JSON.stringify(d.header, null, 2), tone: 'out' },
        { text: tr('payload', 'payload'), tone: 'warn' },
        { text: JSON.stringify(d.claims, null, 2), tone: 'out' },
        { text: tr('Base64url không phải mã hoá: ai giữ token cũng đọc được phần này.', 'Base64url is not encryption: anyone holding the token can read this.'), tone: 'dim' },
      ];
    }

    if (sub === 'verify') {
      if (!target) return [{ text: tr('Cần token. Ví dụ: jwt verify @access', 'Need a token. Example: jwt verify @access'), tone: 'err' }];
      const result = await verifyJwt(target, {
        jwks: this.authServer.jwks().keys,
        issuer: flagStr(p, 'iss', this.authServer.config.issuer),
        audience: flagStr(p, 'aud', this.authServer.config.audience),
        now: this.clock.nowSec(),
      });
      this.record('jwt verify', result.valid, {
        failed: result.checks.filter((c) => !c.ok).map((c) => c.name),
        passed: result.checks.filter((c) => c.ok).map((c) => c.name),
      });
      return [
        { text: result.valid ? tr('HỢP LỆ', 'VALID') : tr('KHÔNG HỢP LỆ', 'INVALID'), tone: result.valid ? 'ok' : 'err' },
        ...result.checks.map((c) => ({
          text: `  ${c.ok ? '+' : '!'} ${c.name.padEnd(10)} ${c.detail}`,
          tone: (c.ok ? 'out' : 'err') as Line['tone'],
        })),
      ];
    }

    if (sub === 'forge') {
      if (!target) return [{ text: tr('Cần token gốc. Ví dụ: jwt forge @access --set roles=admin', 'Need a source token. Example: jwt forge @access --set roles=admin'), tone: 'err' }];
      const d = decodeJwt(target);
      if (!d) return [{ text: tr('Không phải JWT ba khối.', 'Not a three-part JWT.'), tone: 'err' }];

      const claims: Record<string, unknown> = { ...d.claims };
      const header: Record<string, unknown> = { ...d.header };
      const applied: string[] = [];

      const apply = (spec: string, into: Record<string, unknown>) => {
        for (const pair of spec.split(';')) {
          const eq = pair.indexOf('=');
          if (eq < 0) continue;
          const k = pair.slice(0, eq);
          const raw = pair.slice(eq + 1);
          let value: unknown = raw;
          if (raw === 'true') value = true;
          else if (raw === 'false') value = false;
          else if (/^-?\d+$/.test(raw)) value = Number(raw);
          else if (raw.includes(',')) value = raw.split(',');
          into[k] = value;
          applied.push(`${k}=${raw}`);
        }
      };

      const setFlag = p.flags['set'];
      if (typeof setFlag === 'string') apply(setFlag, claims);
      const setHeader = p.flags['set-header'];
      if (typeof setHeader === 'string') apply(setHeader, header);

      if (p.flags['own-key']) {
        // Key injection: kẻ tấn công tự sinh cặp khoá, ký token bằng private key
        // của mình, và NHÚNG public key của mình vào header. Server nào tin key
        // nhúng (jwk/jku) sẽ verify bằng đúng key đó - token tự chứng minh.
        if (!this.attackerKey) this.attackerKey = await generateSigningKey('attacker-key', this.clock.nowMs());
        const jwk = await toJwk(this.attackerKey);
        header['jwk'] = jwk;
        header['kid'] = 'attacker-key';
        const signed = await signJwt(claims as never, this.attackerKey, { jwk } as never);
        this.tokens.set('forged', signed);
        this.record('jwt forge', true, { applied: [...applied, 'jwk=attacker'], ownKey: true });
        return [
          { text: tr(`Đã sửa: ${applied.join(', ')}, ký bằng KHOÁ CỦA KẺ TẤN CÔNG`, `Edited: ${applied.join(', ')}, signed with the ATTACKER'S OWN KEY`), tone: 'warn' },
          { text: tr('Public key của kẻ tấn công được nhúng vào header (jwk). Chữ ký khớp key đó.', "The attacker's public key is embedded in the header (jwk). The signature matches that key."), tone: 'dim' },
          { text: tr('Nếu server tin key nhúng, nó chấp nhận. Thử: curl /me --token @forged', 'If the server trusts the embedded key, it accepts this. Try: curl /me --token @forged'), tone: 'out' },
        ];
      }

      const hs256 = p.flags['hs256'];
      if (hs256 !== undefined) {
        // Tấn công alg-confusion: ép alg=HS256 rồi KÝ LẠI bằng HMAC, secret là
        // chuỗi mà kẻ tấn công cung cấp (thường là public key lấy từ JWKS). Đây
        // là chữ ký hợp lệ theo HS256, khác hẳn kiểu forge giữ chữ ký cũ.
        const secret = typeof hs256 === 'string' && hs256 ? hs256 : this.authServer.publicKeyMaterial();
        header['alg'] = 'HS256';
        const input = `${b64uJson(header)}.${b64uJson(claims)}`;
        const sig = await signHs256(input, utf8(secret));
        const forged = `${input}.${sig}`;
        this.tokens.set('forged', forged);
        this.record('jwt forge', true, { applied: [...applied, 'alg=HS256'], hs256: true });
        return [
          { text: tr(`Đã sửa: ${applied.join(', ')}, và KÝ LẠI bằng HS256`, `Edited: ${applied.join(', ')}, and RE-SIGNED with HS256`), tone: 'warn' },
          { text: tr(`Secret dùng để ký: "${secret.slice(0, 24)}..." (lấy từ JWKS - ai cũng có).`, `Secret used to sign: "${secret.slice(0, 24)}..." (taken from JWKS — anyone has it).`), tone: 'dim' },
          { text: tr('Chữ ký HS256 này HỢP LỆ. Nếu server tin trường alg, nó sẽ chấp nhận. Thử: curl /me --token @forged', 'This HS256 signature is VALID. If the server trusts the alg field, it will accept this. Try: curl /me --token @forged'), tone: 'out' },
        ];
      }

      if (!applied.length) {
        return [{ text: tr('Chưa sửa gì. Dùng --set roles=admin, --set-header alg=none, hoặc --hs256 <secret>.', 'Nothing edited yet. Use --set roles=admin, --set-header alg=none, or --hs256 <secret>.'), tone: 'err' }];
      }

      // Giữ nguyên chữ ký gốc: đó là toàn bộ khả năng của kẻ không có private key.
      const forged = `${b64uJson(header)}.${b64uJson(claims)}.${d.parts[2]}`;
      this.tokens.set('forged', forged);
      this.record('jwt forge', true, { applied });

      return [
        { text: tr(`Đã sửa: ${applied.join(', ')}`, `Edited: ${applied.join(', ')}`), tone: 'warn' },
        { text: tr('Chữ ký giữ nguyên bản gốc (không ký lại - bạn không có private key).', "Signature kept from the original (not re-signed — you don't have the private key)."), tone: 'dim' },
        { text: tr('Lưu thành @forged. Thử: curl /me --token @forged', 'Saved as @forged. Try: curl /me --token @forged'), tone: 'out' },
      ];
    }

    return [{ text: tr('jwt decode | jwt verify | jwt forge. Gõ help jwt.', 'jwt decode | jwt verify | jwt forge. Type help jwt.'), tone: 'err' }];
  }

  // -------------------------------------------------------------- curl

  private async curl(p: ParsedCommand): Promise<Line[]> {
    const path = p.words[1] ?? '/me';
    const token = this.resolve(flagStr(p, 'token') || '@access');
    const which = flagStr(p, 'api', 'public');
    const api = which === 'internal' ? this.internalApi : this.publicApi;
    const required = flagStr(p, 'scope-required', 'read:reports');

    if (p.flags['no-aud-check']) api.setAudienceCheck(false);

    const res = await api.request(path, token, required);
    this.record('curl', res.status === 200, {
      path,
      api: which,
      failed: res.verification?.checks.filter((c) => !c.ok).map((c) => c.name) ?? [],
      tokenRef: flagStr(p, 'token') || '@access',
    }, res.status);

    const host = which === 'internal' ? 'api-internal.example.com' : 'api.example.com';
    return [
      { text: `GET https://${host}${path}`, tone: 'dim' },
      { text: `  Authorization: Bearer ${token ? token.slice(0, 20) + '...' : tr('(không có)', '(none)')}`, tone: 'dim' },
      { text: `${res.status} ${res.statusText}`, tone: res.status === 200 ? 'ok' : 'err' },
      { text: JSON.stringify(res.body, null, 2), tone: 'out' },
      { text: res.reason, tone: res.status === 200 ? 'dim' : 'warn' },
    ];
  }

  // ------------------------------------------------------------ policy

  private policyEval(p: ParsedCommand): Line[] {
    if (p.words[1] !== 'eval') return [{ text: tr('Chỉ có: policy eval <user> <action> <resource>', 'Only: policy eval <user> <action> <resource>'), tone: 'err' }];
    const user = p.words[2] ?? 'alice';
    const action = p.words[3] ?? 'delete';
    const resourceRef = p.words[4] ?? 'doc:42';
    const model = flagStr(p, 'model', 'all');
    const hour = Number(flagStr(p, 'hour', '14'));

    const [kind, id] = resourceRef.split(':');
    const subject = {
      sub: user === 'alice' ? 'user-8f21' : 'user-b0b0',
      username: user,
      roles: user === 'alice' ? ['reader', 'writer'] : ['reader'],
      department: 'sales',
      atHour: Number.isFinite(hour) ? hour : 14,
    };
    const resource = {
      id: id ?? '42',
      kind: kind ?? 'doc',
      ownerSub: 'user-b0b0',
      department: 'sales',
      classification: 'confidential' as const,
    };

    const models: PolicyModel[] = model === 'all' ? ['rbac', 'abac', 'rebac'] : [model as PolicyModel];
    const decisions = models.map((m) => this.policy.evaluate(m, subject, resource, action));
    const disagree = new Set(decisions.map((d) => d.allow)).size > 1;

    this.record('policy eval', true, {
      user, action, resource: resourceRef,
      results: decisions.map((d) => ({ model: d.model, allow: d.allow })),
      disagree,
    });

    const lines: Line[] = [{ text: tr(`${user} muốn "${action}" trên ${resourceRef} (chủ sở hữu: bob, ${subject.atHour}h)`, `${user} wants to "${action}" ${resourceRef} (owner: bob, ${subject.atHour}h)`), tone: 'dim' }];
    for (const d of decisions) {
      lines.push({ text: `${d.model.toUpperCase().padEnd(6)} ${d.allow ? tr('CHO PHÉP', 'ALLOW') : tr('TỪ CHỐI ', 'DENY   ')}`, tone: d.allow ? 'warn' : 'ok' });
      for (const t of d.trace) {
        lines.push({ text: `    ${t.decisive ? '>' : ' '} ${t.rule} -> ${t.result}`, tone: 'dim' });
      }
      lines.push({ text: `    ${d.summary}`, tone: 'out' });
    }
    if (disagree) {
      lines.push({ text: tr('Ba mô hình không đồng thuận. Chênh lệch đó chính là lỗ hổng phân quyền.', 'The three models disagree. That gap is the authorization vulnerability.'), tone: 'warn' });
    }
    return lines;
  }

  // ----------------------------------------------------------- session

  private async login(p: ParsedCommand): Promise<Line[]> {
    const user = p.words[1] ?? 'alice';
    const password = p.words[2] ?? '';
    // --sid mô phỏng cookie mà kẻ tấn công đã gài sẵn trên trình duyệt nạn nhân.
    const preset = flagStr(p, 'sid') || undefined;
    const res = await this.sessions.login(user, password, preset);
    this.record('login', res.ok, { user, presetSid: preset ?? null, regenerated: res.regenerated ?? true, resultSid: res.sid ?? null }, res.ok ? 200 : 401);
    if (!res.ok) return [{ text: `401 ${res.reason}`, tone: 'err' }];
    this.lastSid = res.sid!;
    return [
      { text: '200 OK', tone: 'ok' },
      { text: `Set-Cookie: sid=${res.sid}; HttpOnly; Secure; SameSite=Lax`, tone: 'out' },
      { text: res.reason, tone: res.regenerated ? 'dim' : 'warn' },
    ];
  }

  private profile(p: ParsedCommand): Line[] {
    const sid = flagStr(p, 'sid') || this.lastSid || undefined;
    const res = this.sessions.check(sid);
    this.record('profile', res.ok, { sid }, res.status);
    return [
      { text: `${res.status} ${res.ok ? 'OK' : 'Unauthorized'}`, tone: res.ok ? 'ok' : 'err' },
      { text: res.reason, tone: res.ok ? 'dim' : 'warn' },
    ];
  }

  private revoke(p: ParsedCommand): Line[] {
    const sid = flagStr(p, 'sid') || p.words[1] || this.lastSid || '';
    const ok = this.sessions.revoke(sid);
    this.record('revoke', ok, { sid });
    return ok
      ? [{ text: tr(`Đã huỷ phiên ${sid}. Thử lại: profile`, `Session ${sid} revoked. Try again: profile`), tone: 'ok' }]
      : [{ text: tr('Không thấy phiên đó.', 'No such session found.'), tone: 'err' }];
  }

  // ------------------------------------------------------------- misc

  // ------------------------------------------------- phòng thủ (Red Team)

  private status(): Line[] {
    if (!this.posture) return [{ text: tr('Lệnh này chỉ dùng trong Red Team mode.', 'This command is only available in Red Team mode.'), tone: 'err' }];
    const f = this.posture.flags;
    return [
      { text: tr('Trạng thái phòng thủ hiện tại', 'Current defensive posture'), tone: 'warn' },
      ...Object.entries(f).map(([k, v]) => ({
        text: `  ${k.padEnd(22)} ${String(v)}`,
        tone: 'out' as const,
      })),
      { text: tr('Gõ audit để biết cái nào đang là lỗ hổng.', 'Type audit to see which one is currently a hole.'), tone: 'dim' },
    ];
  }

  private auditCmd(): Line[] {
    if (!this.posture) return [{ text: tr('Lệnh này chỉ dùng trong Red Team mode.', 'This command is only available in Red Team mode.'), tone: 'err' }];
    const checks = this.posture.audit();
    const failed = checks.filter((c) => !c.pass);
    this.record('audit', failed.length === 0, { failed: failed.map((c) => c.id) });
    return [
      ...checks.map((c) => ({
        text: `  ${c.pass ? 'PASS' : 'FAIL'}  ${c.title}`,
        tone: (c.pass ? 'ok' : 'err') as Line['tone'],
      })),
      { text: tr(`${checks.length - failed.length}/${checks.length} đạt`, `${checks.length - failed.length}/${checks.length} passed`), tone: failed.length ? 'warn' : 'ok' },
      ...failed.flatMap((c) => [
        { text: `${c.title}: ${c.detail}`, tone: 'warn' as const },
        { text: tr(`  sửa: ${c.fix}`, `  fix: ${c.fix}`), tone: 'out' as const },
      ]),
    ];
  }

  private hardenCmd(p: ParsedCommand): Line[] {
    if (!this.posture) return [{ text: tr('Lệnh này chỉ dùng trong Red Team mode.', 'This command is only available in Red Team mode.'), tone: 'err' }];
    const name = p.words[1];
    const value = p.words[2];
    if (!name || !value) {
      return [{ text: tr('harden <cấu hình> <on|off|số>. Ví dụ: harden plain off', 'harden <setting> <on|off|number>. Example: harden plain off'), tone: 'err' }];
    }
    const [ok, message] = this.posture.harden(name, value);
    this.record('harden', ok, { name, value });
    return [{ text: message, tone: ok ? 'ok' : 'err' }];
  }

  private listTokens(): Line[] {
    if (!this.tokens.size) return [{ text: tr('Chưa giữ token nào.', 'No tokens held yet.'), tone: 'dim' }];
    return [...this.tokens.entries()].map(([k, v]) => ({
      text: `@${k.padEnd(8)} ${v.slice(0, 46)}...`,
      tone: 'out' as const,
    }));
  }

  private jwks(): Line[] {
    const keys = this.authServer.jwks().keys;
    return [
      { text: JSON.stringify({ keys: keys.map((k) => ({ kty: k.kty, alg: k.alg, use: k.use, kid: k.kid, n: k.n?.slice(0, 30) + '...' })) }, null, 2), tone: 'out' },
      { text: tr('Chỉ có public key. API verify được nhưng không phát token được.', 'Only public keys here. An API can verify but never mint tokens.'), tone: 'dim' },
      { text: tr('Chuỗi "n" là modulus - đầy đủ lấy bằng: pubkey', 'The "n" string is the modulus — get the full value with: pubkey'), tone: 'dim' },
    ];
  }

  private pubkey(): Line[] {
    const material = this.authServer.publicKeyMaterial();
    return [
      { text: tr('Public key material (modulus, base64url) — công khai qua JWKS:', 'Public key material (modulus, base64url) — public via JWKS:'), tone: 'warn' },
      { text: material, tone: 'out' },
      { text: tr('Đây là thứ dùng cho alg-confusion: jwt forge @access --set roles=admin --hs256 <chuỗi này>', 'This is what alg-confusion uses: jwt forge @access --set roles=admin --hs256 <this string>'), tone: 'dim' },
    ];
  }

  private discovery(): Line[] {
    return [{ text: JSON.stringify(this.authServer.discovery(), null, 2), tone: 'out' }];
  }

  // ------------------------------------------------- web app (OWASP)

  /** Cổng vào web app dễ tổn thương. Mỗi subcommand nhắm một lỗ OWASP. */
  private app(p: ParsedCommand, _raw: string): Line[] {
    const sub = p.words[1];
    let r;
    switch (sub) {
      case 'login':
        r = this.web.login(p.words[2] ?? '', p.words[3] ?? '');
        break;
      case 'search':
        r = this.web.search(p.words[2] ?? '');
        break;
      case 'comment':
        r = this.web.comment(p.words[2] ?? '');
        break;
      case 'render':
        r = this.web.render();
        break;
      case 'fetch':
        r = this.web.fetch(p.words[2] ?? '');
        break;
      case 'download':
        r = this.web.download(p.words[2] ?? '');
        break;
      case 'ping':
        r = this.web.ping(p.words[2] ?? '');
        break;
      default:
        return [{ text: tr('app <login|search|comment|render|fetch|download|ping>. Gõ: help app', 'app <login|search|comment|render|fetch|download|ping>. Type: help app'), tone: 'err' }];
    }
    this.record(`app ${sub}`, r.status < 400, r.data, r.status);
    return r.lines as Line[];
  }
}
