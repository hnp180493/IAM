import { tr } from '../i18n';
import { b64uDecode, b64uEncode, b64uJson, b64uToJson, utf8 } from '../util/base64url';

export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [k: string]: unknown;
}

export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [k: string]: unknown;
}

export interface SigningKey {
  kid: string;
  alg: 'RS256';
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  createdAt: number;
}

export interface Jwk {
  kty: string;
  n?: string;
  e?: string;
  kid: string;
  alg: string;
  use: string;
}

const RSA_PARAMS: RsaHashedKeyGenParams = {
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: 'SHA-256',
};

/** A real 2048-bit RSA keypair, generated in the browser. */
export async function generateSigningKey(kid: string, now: number): Promise<SigningKey> {
  const pair = await crypto.subtle.generateKey(RSA_PARAMS, true, ['sign', 'verify']);
  return { kid, alg: 'RS256', publicKey: pair.publicKey, privateKey: pair.privateKey, createdAt: now };
}

/** The public half, in the shape a real /.well-known/jwks.json serves. */
export async function toJwk(key: SigningKey): Promise<Jwk> {
  const raw = (await crypto.subtle.exportKey('jwk', key.publicKey)) as JsonWebKey;
  return { kty: raw.kty!, n: raw.n, e: raw.e, kid: key.kid, alg: key.alg, use: 'sig' };
}

export async function importJwk(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  );
}

/**
 * Ký HMAC-SHA256. Có mặt ở đây vì bài alg-confusion cần nó: kẻ tấn công ký lại
 * token bằng HS256, dùng chính public key RSA (lấy từ JWKS công khai) làm secret.
 * Một server verify mà tin vào trường alg sẽ đem public key ra làm khoá HMAC và
 * xác nhận thành công.
 */
export async function signHs256(headerPayload: string, secretBytes: Uint8Array): Promise<string> {
  const buf = secretBytes.slice().buffer;
  const key = await crypto.subtle.importKey('raw', buf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, utf8(headerPayload));
  return b64uEncode(new Uint8Array(sig));
}

export async function signJwt(claims: JwtClaims, key: SigningKey, headerExtra: Partial<JwtHeader> = {}): Promise<string> {
  const header: JwtHeader = { alg: key.alg, typ: 'JWT', kid: key.kid, ...headerExtra };
  const input = `${b64uJson(header)}.${b64uJson(claims)}`;
  const sig = await crypto.subtle.sign(RSA_PARAMS.name, key.privateKey, utf8(input));
  return `${input}.${b64uEncode(new Uint8Array(sig))}`;
}

export interface DecodedJwt {
  header: JwtHeader;
  claims: JwtClaims;
  signature: string;
  parts: [string, string, string];
}

/** Decode without verifying — what an attacker can do to any JWT they hold. */
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  try {
    return { header: b64uToJson<JwtHeader>(h), claims: b64uToJson<JwtClaims>(p), signature: s, parts: [h, p, s] };
  } catch {
    return null;
  }
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

export interface VerifyOptions {
  jwks: Jwk[];
  issuer?: string;
  audience?: string;
  /** Simulated wall clock, in seconds. */
  now: number;
  /**
   * Cho phép hạ tiêu chuẩn verify - dùng cho Red Team mode, khi một cuộc tấn công
   * đã tắt một phép kiểm tra. Phép kiểm tra bị tắt vẫn hiện trong danh sách, ghi
   * rõ là ĐANG BỎ QUA, chứ không lặng lẽ biến mất.
   */
  policy?: {
    checkSignature?: boolean;
    allowAlgNone?: boolean;
    allowHs256?: boolean;
    hmacSecret?: Uint8Array;
    /** Tin key nhúng trong header (jwk/jku) - lỗ key injection. */
    trustEmbeddedJwk?: boolean;
  };
}

export interface VerifyResult {
  valid: boolean;
  checks: Check[];
  decoded: DecodedJwt | null;
}

/**
 * Verify a JWT the way a resource server should: signature first, then every
 * registered claim, and report each check individually. A single boolean would
 * hide exactly the thing this lab exists to show.
 */
export async function verifyJwt(token: string, opts: VerifyOptions): Promise<VerifyResult> {
  const checks: Check[] = [];
  const decoded = decodeJwt(token);

  if (!decoded) {
    checks.push({ name: 'format', ok: false, detail: tr('Không phải ba khối base64url nối bằng dấu chấm.', 'Not three base64url segments joined by dots.') });
    return { valid: false, checks, decoded: null };
  }
  checks.push({ name: 'format', ok: true, detail: tr('Đúng dạng header.payload.signature', 'Correctly shaped header.payload.signature') });

  const { header, claims, parts } = decoded;

  // alg — the check whose absence enables the classic "alg: none" bypass.
  if (header.alg === 'none') {
    const tolerated = opts.policy?.allowAlgNone === true;
    checks.push({
      name: 'alg',
      ok: tolerated,
      detail: tolerated
        ? tr('ĐANG BỎ QUA: cấu hình cho phép alg="none". Token không có chữ ký vẫn được nhận.', 'BEING SKIPPED: config allows alg="none". An unsigned token still gets accepted.')
        : tr('Header khai alg="none" - token không có chữ ký. Server nào tin vào header ở đây thì chấp nhận mọi thứ.', 'Header declares alg="none" — the token carries no signature. Any server that trusts this header accepts anything.'),
    });
  } else if (header.alg === 'HS256' && opts.policy?.allowHs256) {
    checks.push({
      name: 'alg',
      ok: true,
      detail: tr('ĐANG BỎ QUA: cấu hình chấp nhận cả HS256 lẫn RS256, và tin trường alg để chọn cách verify. Đây là lỗ alg-confusion.', 'BEING SKIPPED: config accepts both HS256 and RS256, and trusts the alg field to choose how to verify. This is the alg-confusion hole.'),
    });
  } else if (header.alg !== 'RS256') {
    checks.push({
      name: 'alg',
      ok: false,
      detail: tr(`Header alg="${header.alg}" không nằm trong danh sách cho phép (RS256). Đừng bao giờ để token tự chọn thuật toán của nó.`, `Header alg="${header.alg}" is not in the allowed list (RS256). Never let a token pick its own algorithm.`),
    });
  } else {
    checks.push({ name: 'alg', ok: true, detail: tr('RS256, khớp danh sách thuật toán cho phép.', 'RS256, matches the allowed algorithm list.') });
  }

  // Key injection: token tự đính kèm key verify trong header (jwk). Thư viện
  // ngây thơ (hoặc bật jku) sẽ dùng chính key đó - nghĩa là token tự chứng minh
  // cho chính nó. Đây là họ lỗ jwk/jku header injection.
  const embedded = (header as { jwk?: Jwk }).jwk;
  if (embedded && opts.policy?.trustEmbeddedJwk) {
    checks.push({
      name: 'kid',
      ok: true,
      detail: tr('ĐANG BỎ QUA: dùng key NHÚNG trong header token (jwk/jku), không phải JWKS đã cấu hình. Token tự chứng minh cho chính nó.', 'BEING SKIPPED: using the key EMBEDDED in the token header (jwk/jku), not the configured JWKS. The token vouches for itself.'),
    });
    let ok = false;
    try {
      const pub = await importJwk(embedded);
      ok = await crypto.subtle.verify(RSA_PARAMS.name, pub, b64uDecode(parts[2]), utf8(`${parts[0]}.${parts[1]}`));
    } catch {
      ok = false;
    }
    checks.push({
      name: 'signature',
      ok,
      detail: ok
        ? tr('Chữ ký khớp với key nhúng trong token - nhưng key đó do kẻ tấn công cung cấp, nên vô nghĩa.', "The signature matches the key embedded in the token — but the attacker supplied that key, so it means nothing.")
        : tr('Chữ ký không khớp cả key nhúng.', 'The signature does not even match the embedded key.'),
    });
    // Bỏ qua phần verify chuẩn ở dưới bằng cách gộp phần claim vào đây.
    return finishClaims(checks, claims, opts, decoded);
  }

  // kid -> JWKS lookup
  const jwk = header.kid ? opts.jwks.find((k) => k.kid === header.kid) : opts.jwks[0];
  if (!jwk) {
    checks.push({ name: 'kid', ok: false, detail: tr(`Không có key nào mang kid="${header.kid}" trong JWKS. Không kiểm tra được chữ ký.`, `No key with kid="${header.kid}" in the JWKS. The signature cannot be checked.`) });
    return { valid: false, checks, decoded };
  }
  checks.push({ name: 'kid', ok: true, detail: tr(`Khớp key "${jwk.kid}" trong JWKS của auth server.`, `Matches key "${jwk.kid}" in the auth server's JWKS.`) });

  // signature
  let sigOk = false;
  if (header.alg === 'HS256' && opts.policy?.allowHs256 && opts.policy.hmacSecret) {
    // Server dễ tổn thương: đem public key (thứ ai cũng lấy được từ JWKS) ra làm
    // khoá HMAC. Kẻ tấn công ký bằng đúng chuỗi đó nên chữ ký khớp.
    try {
      const key = await crypto.subtle.importKey('raw', opts.policy.hmacSecret.slice().buffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      sigOk = await crypto.subtle.verify('HMAC', key, b64uDecode(parts[2]), utf8(`${parts[0]}.${parts[1]}`));
    } catch {
      sigOk = false;
    }
  } else if (header.alg === 'RS256') {
    try {
      const pub = await importJwk(jwk);
      sigOk = await crypto.subtle.verify(RSA_PARAMS.name, pub, b64uDecode(parts[2]), utf8(`${parts[0]}.${parts[1]}`));
    } catch {
      sigOk = false;
    }
  }
  if (opts.policy?.checkSignature === false) {
    checks.push({
      name: 'signature',
      ok: true,
      detail: tr('ĐANG BỎ QUA: cấu hình đã tắt verify chữ ký. Mọi payload sửa tay đều lọt.', 'BEING SKIPPED: signature verification is turned off in config. Any hand-edited payload gets through.'),
    });
  } else
  checks.push({
    name: 'signature',
    ok: sigOk,
    detail: sigOk
      ? tr('Chữ ký RSA phủ lên header.payload khớp với public key đã công bố.', 'The RSA signature over header.payload matches the published public key.')
      : tr('Chữ ký không khớp. Payload đã bị sửa, hoặc token được ký bằng key khác.', 'The signature does not match. The payload was edited, or the token was signed with a different key.'),
  });

  return finishClaims(checks, claims, opts, decoded);
}

/** Phần kiểm tra claim (iss/aud/exp/nbf), dùng chung cho cả đường verify chuẩn lẫn đường key-injection. */
function finishClaims(checks: Check[], claims: JwtClaims, opts: VerifyOptions, decoded: DecodedJwt): VerifyResult {
  if (opts.issuer !== undefined) {
    const ok = claims.iss === opts.issuer;
    checks.push({
      name: 'iss',
      ok,
      detail: ok ? tr(`Do ${claims.iss} phát ra.`, `Issued by ${claims.iss}.`) : tr(`Cần iss="${opts.issuer}" nhưng nhận được "${claims.iss}".`, `Expected iss="${opts.issuer}" but got "${claims.iss}".`),
    });
  }

  if (opts.audience !== undefined) {
    const auds = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
    const ok = auds.includes(opts.audience);
    checks.push({
      name: 'aud',
      ok,
      detail: ok
        ? tr(`API này (${opts.audience}) nằm trong danh sách nhận token.`, `This API (${opts.audience}) is in the token's intended audience.`)
        : tr(`Token được phát cho [${auds.join(', ') || 'không ai'}], không phải cho ${opts.audience}. Vẫn nhận thì đó là lỗi audience confusion.`, `The token was issued for [${auds.join(', ') || 'nobody'}], not for ${opts.audience}. Accepting it anyway is audience confusion.`),
    });
  }

  if (claims.exp === undefined) {
    checks.push({ name: 'exp', ok: false, detail: tr('Không có claim exp - token này tự nó không bao giờ hết hạn.', 'No exp claim — this token never expires on its own.') });
  } else {
    const ok = opts.now < claims.exp;
    const delta = Math.round(Math.abs(claims.exp - opts.now));
    checks.push({
      name: 'exp',
      ok,
      detail: ok ? tr(`Còn hiệu lực ${delta}s nữa.`, `Valid for another ${delta}s.`) : tr(`Đã hết hạn ${delta}s trước.`, `Expired ${delta}s ago.`),
    });
  }

  if (claims.nbf !== undefined) {
    const ok = opts.now >= claims.nbf;
    checks.push({ name: 'nbf', ok, detail: ok ? tr('Đã tới thời điểm có hiệu lực.', 'Already within its valid window.') : tr(`Chưa có hiệu lực, còn ${Math.round(claims.nbf - opts.now)}s nữa.`, `Not valid yet, ${Math.round(claims.nbf - opts.now)}s to go.`) });
  }

  return { valid: checks.every((c) => c.ok), checks, decoded };
}
