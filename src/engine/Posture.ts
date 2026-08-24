import { tr } from '../i18n';
export interface PostureFlags {
  /** Cho phép code_challenge_method=plain. */
  allowPlainPkce: boolean;
  /** Bắt buộc phải có PKCE. */
  requirePkce: boolean;
  /** Authorization code chỉ đổi được một lần. */
  codeSingleUse: boolean;
  /** So khớp redirect_uri tuyệt đối (tắt = so theo tiền tố, tức là lỗ open redirect). */
  redirectExactMatch: boolean;
  checkAudiencePublic: boolean;
  checkAudienceInternal: boolean;
  /** Có verify chữ ký JWT hay không. */
  checkSignature: boolean;
  /** Chấp nhận alg=none. */
  allowAlgNone: boolean;
  /** Chấp nhận cả HS256 lẫn RS256 và tin trường alg - lỗ alg-confusion. */
  allowHs256: boolean;
  accessTokenTtl: number;
  /** Auth server có gọi back-channel logout tới các app. */
  backchannelLogout: boolean;
  /** Xoay refresh token mỗi lần dùng và phát hiện reuse. */
  refreshRotation: boolean;
  /** Phát sid mới sau đăng nhập (chống session fixation). */
  sessionRegenerate: boolean;
  /** Client có kiểm tra state ở callback (chống login CSRF). */
  stateChecked: boolean;
  /** Tin header jku/jwks_uri trong token để nạp key verify (lỗ SSRF/key injection). */
  trustJku: boolean;
}

export const HARDENED: PostureFlags = {
  allowPlainPkce: false,
  requirePkce: true,
  codeSingleUse: true,
  redirectExactMatch: true,
  checkAudiencePublic: true,
  checkAudienceInternal: true,
  checkSignature: true,
  allowAlgNone: false,
  allowHs256: false,
  accessTokenTtl: 300,
  backchannelLogout: true,
  refreshRotation: true,
  sessionRegenerate: true,
  stateChecked: true,
  trustJku: false,
};

export interface AuditCheck {
  id: string;
  title: string;
  pass: boolean;
  detail: string;
  fix: string;
}

/** Tên thân thiện người chơi gõ -> khoá thật. */
const ALIASES: Record<string, keyof PostureFlags> = {
  plain: 'allowPlainPkce',
  pkce: 'requirePkce',
  code: 'codeSingleUse',
  redirect: 'redirectExactMatch',
  aud: 'checkAudiencePublic',
  'aud-internal': 'checkAudienceInternal',
  signature: 'checkSignature',
  alg: 'allowAlgNone',
  hs256: 'allowHs256',
  ttl: 'accessTokenTtl',
  logout: 'backchannelLogout',
  refresh: 'refreshRotation',
  session: 'sessionRegenerate',
  state: 'stateChecked',
  jku: 'trustJku',
};

/**
 * Trạng thái phòng thủ hiện tại của hệ thống trong lab.
 *
 * Mọi cờ ở đây đều tác động thật tới hành vi của auth server và resource API -
 * không có cờ nào chỉ để trưng. Nhờ vậy `audit` nói thật, và tấn công phá được
 * thật.
 */
export class Posture {
  flags: PostureFlags = { ...HARDENED };

  reset(): void {
    this.flags = { ...HARDENED };
  }

  /** Trả về [ok, thông báo] để console in ra. */
  harden(name: string, value: string): [boolean, string] {
    const key = ALIASES[name];
    if (!key) {
      return [false, `Không có cấu hình "${name}". Các tên: ${Object.keys(ALIASES).join(', ')}`];
    }

    if (key === 'accessTokenTtl') {
      const n = Number(value);
      if (!Number.isFinite(n) || n <= 0) return [false, tr('ttl phải là số giây dương.', 'ttl must be a positive number of seconds.')];
      this.flags.accessTokenTtl = n;
      return [true, `accessTokenTtl = ${n}s`];
    }

    const on = ['on', 'true', 'yes', 'strict', 'exact', 'single-use', 's256', '1'].includes(value.toLowerCase());
    const off = ['off', 'false', 'no', 'loose', 'plain', 'none', '0'].includes(value.toLowerCase());
    if (!on && !off) return [false, tr(`Giá trị "${value}" không hiểu. Dùng on hoặc off.`, `Value "${value}" not understood. Use on or off.`)];

    // Hai cờ này đảo nghĩa: bật bảo mật = tắt cờ.
    const inverted = key === 'allowPlainPkce' || key === 'allowAlgNone' || key === 'allowHs256' || key === 'trustJku';
    this.flags[key] = inverted ? !on : on;

    return [true, `${name} -> ${tr(on ? 'siết' : 'nới', on ? 'hardened' : 'loosened')}`];
  }

  audit(): AuditCheck[] {
    const f = this.flags;
    return [
      {
        id: 'require-pkce', title: tr('Bắt buộc PKCE', 'Require PKCE'), pass: f.requirePkce,
        detail: f.requirePkce ? tr('Request không có code_challenge bị từ chối.', 'Requests without a code_challenge are rejected.') : tr('Server nhận request KHÔNG có PKCE - code thành bearer thuần.', 'The server accepts requests with NO PKCE — the code becomes a plain bearer credential.'),
        fix: 'harden pkce on',
      },
      {
        id: 'no-plain', title: tr('Chỉ cho phép S256', 'S256 only'), pass: !f.allowPlainPkce,
        detail: f.allowPlainPkce ? tr('method=plain đang được chấp nhận - verifier nằm cleartext trong URL.', 'method=plain is being accepted — the verifier sits in cleartext in the URL.') : tr('Chỉ S256.', 'S256 only.'),
        fix: 'harden plain off',
      },
      {
        id: 'code-single-use', title: tr('Code chỉ dùng một lần', 'Code is single-use'), pass: f.codeSingleUse,
        detail: f.codeSingleUse ? tr('Code đã đổi không đổi lại được.', 'A redeemed code cannot be redeemed again.') : tr('Cùng một code đổi được nhiều lần - replay tự do.', 'The same code can be redeemed multiple times — free replay.'),
        fix: 'harden code on',
      },
      {
        id: 'redirect-exact', title: tr('redirect_uri khớp tuyệt đối', 'redirect_uri exact match'), pass: f.redirectExactMatch,
        detail: f.redirectExactMatch ? tr('Khớp chuỗi tuyệt đối.', 'Exact string match.') : tr('Đang so theo tiền tố - tên miền lạ bắt đầu bằng chuỗi hợp lệ sẽ hứng được code.', 'Matching by prefix — an unfamiliar domain that starts with a valid string will catch the code.'),
        fix: 'harden redirect on',
      },
      {
        id: 'aud-public', title: tr('API công khai kiểm tra aud', 'Public API checks aud'), pass: f.checkAudiencePublic,
        detail: f.checkAudiencePublic ? tr('Có so aud.', 'aud is compared.') : tr('Bỏ kiểm tra aud - nhận token của API khác.', 'Skips the aud check — accepts tokens meant for another API.'),
        fix: 'harden aud on',
      },
      {
        id: 'aud-internal', title: tr('API nội bộ kiểm tra aud', 'Internal API checks aud'), pass: f.checkAudienceInternal,
        detail: f.checkAudienceInternal ? tr('Có so aud.', 'aud is compared.') : tr('API nội bộ nhận token không dành cho nó - đường leo thang quyền.', 'The internal API accepts tokens not meant for it — a privilege-escalation path.'),
        fix: 'harden aud-internal on',
      },
      {
        id: 'signature', title: tr('Verify chữ ký JWT', 'Verify JWT signature'), pass: f.checkSignature,
        detail: f.checkSignature ? tr('Chữ ký được verify bằng public key.', 'The signature is verified against the public key.') : tr('KHÔNG verify chữ ký - ai cũng tự sửa claim thành admin được.', 'Signature is NOT verified — anyone can edit a claim to admin.'),
        fix: 'harden signature on',
      },
      {
        id: 'hs256-confusion', title: tr('Chỉ chấp nhận RS256 (không HS256)', 'RS256 only (no HS256)'), pass: !f.allowHs256,
        detail: f.allowHs256 ? tr('Server nhận cả HS256 và tin trường alg - kẻ tấn công ký lại token bằng public key.', 'The server accepts both HS256 and RS256 and trusts alg — an attacker re-signs a token using the public key.') : tr('Chỉ RS256.', 'RS256 only.'),
        fix: 'harden hs256 on',
      },
      {
        id: 'alg-none', title: tr('Từ chối alg=none', 'Reject alg=none'), pass: !f.allowAlgNone,
        detail: f.allowAlgNone ? tr('Chấp nhận alg=none - token không ký cũng qua.', 'Accepts alg=none — an unsigned token still gets through.') : tr('Chỉ nhận RS256.', 'RS256 only.'),
        fix: 'harden alg on',
      },
      {
        id: 'ttl', title: tr('Access token sống ngắn (<= 900s)', 'Access token is short-lived (<= 900s)'), pass: f.accessTokenTtl <= 900,
        detail: `accessTokenTtl = ${f.accessTokenTtl}s`,
        fix: 'harden ttl 300',
      },
      {
        id: 'refresh-rotation', title: tr('Xoay refresh token + phát hiện reuse', 'Refresh token rotation + reuse detection'), pass: f.refreshRotation,
        detail: f.refreshRotation ? tr('Refresh dùng một lần, reuse thu hồi cả family.', 'Refresh is single-use; reuse revokes the whole family.') : tr('Refresh token không xoay - trộm được là dùng mãi.', 'Refresh tokens do not rotate — a stolen one works forever.'),
        fix: 'harden refresh on',
      },
      {
        id: 'session-fixation', title: tr('Phát sid mới sau đăng nhập', 'Issue a fresh sid after login'), pass: f.sessionRegenerate,
        detail: f.sessionRegenerate ? tr('sid được làm mới, vô hiệu sid gài trước.', 'sid is regenerated, invalidating any pre-planted one.') : tr('Server giữ nguyên sid client mang tới - session fixation.', 'The server keeps whatever sid the client arrives with — session fixation.'),
        fix: 'harden session on',
      },
      {
        id: 'state-csrf', title: tr('Client kiểm tra state ở callback', 'Client checks state at callback'), pass: f.stateChecked,
        detail: f.stateChecked ? tr('state được so khớp, chống login CSRF.', 'state is compared, blocking login CSRF.') : tr('Không kiểm state - kẻ tấn công ép nạn nhân đăng nhập vào tài khoản của chúng.', "state is not checked — an attacker can force the victim to log into the attacker's account."),
        fix: 'harden state on',
      },
      {
        id: 'jku-ssrf', title: tr('Không tin jku/jwks_uri trong token', "Don't trust jku/jwks_uri in the token"), pass: !f.trustJku,
        detail: f.trustJku ? tr('Server nạp key verify từ URL trong token - kẻ tấn công trỏ về key của chúng (SSRF + key injection).', "The server fetches the verification key from a URL inside the token — an attacker points it at their own key (SSRF + key injection).") : tr('Chỉ dùng JWKS đã cấu hình sẵn.', 'Only the pre-configured JWKS is used.'),
        fix: 'harden jku on',
      },
      {
        id: 'logout', title: tr('Back-channel logout bật', 'Back-channel logout is on'), pass: f.backchannelLogout,
        detail: f.backchannelLogout ? tr('Auth server báo cho các app khi đăng xuất.', 'The auth server notifies apps on logout.') : tr('Đăng xuất không lan ra app khác - phiên zombie.', 'Logout does not propagate to other apps — zombie sessions.'),
        fix: 'harden logout on',
      },
    ];
  }

  get weaknesses(): AuditCheck[] {
    return this.audit().filter((c) => !c.pass);
  }
}
