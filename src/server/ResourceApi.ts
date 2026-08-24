import { verifyJwt, type Jwk, type VerifyResult } from '../crypto/jose';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';

/**
 * A resource server. It shares no state with the authorization server - it only
 * knows the issuer's public keys, which is the whole point of asymmetric
 * signing. It fetches JWKS once and caches it, exactly like the real thing.
 */
export class ResourceApi {
  private jwksCache: Jwk[] | null = null;

  constructor(
    private clock: Clock,
    private readonly audience: string,
    private readonly issuer: string,
    private readonly fetchJwks: () => { keys: Jwk[] },
    /**
     * Bỏ kiểm tra aud là lỗi audience confusion. Để tắt được nó ở đây là cố ý:
     * bài học chỉ thuyết phục khi thấy chính API này chấp nhận token không dành
     * cho nó.
     */
    private checkAudience = true,
    /** Red Team mode gắn posture vào để tấn công tắt được phép kiểm tra. */
    public posture?: {
      flags: {
        checkSignature: boolean;
        allowAlgNone: boolean;
        allowHs256: boolean;
        checkAudiencePublic: boolean;
        checkAudienceInternal: boolean;
        trustJku: boolean;
      };
    },
    /** Vật liệu public key, để mô phỏng server dễ tổn thương dùng nó làm HMAC secret. */
    public publicKeyMaterial?: () => string,
    /** Khi có posture, đọc cờ audience nào (public API vs internal API). */
    private audienceFlag: 'checkAudiencePublic' | 'checkAudienceInternal' = 'checkAudiencePublic',
  ) {}

  /** null = không có override, đọc theo posture (hoặc mặc định). */
  private audienceOverride: boolean | null = null;

  /**
   * Thứ tự ưu tiên: override do lesson đặt tay -> posture (Red Team, exploit) ->
   * mặc định siết. Nhờ vậy lesson aud-confusion và exploit aud-confusion không
   * giẫm lên nhau dù cùng một API.
   */
  private get audienceOn(): boolean {
    if (this.audienceOverride !== null) return this.audienceOverride;
    if (this.posture) return this.posture.flags[this.audienceFlag];
    return this.checkAudience;
  }

  setAudienceCheck(on: boolean): void {
    this.audienceOverride = on;
  }

  clearAudienceOverride(): void {
    this.audienceOverride = null;
  }

  /** First call is the cache miss - worth showing as its own hop. */
  loadJwks(): { keys: Jwk[]; cached: boolean } {
    if (this.jwksCache) return { keys: this.jwksCache, cached: true };
    this.jwksCache = this.fetchJwks().keys;
    return { keys: this.jwksCache, cached: false };
  }

  async request(
    path: string,
    bearer: string | undefined,
    requiredScope: string,
  ): Promise<{
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: unknown;
    reason: string;
    verification: VerifyResult | null;
  }> {
    if (!bearer) {
      return {
        status: 401,
        statusText: 'Unauthorized',
        headers: { 'WWW-Authenticate': 'Bearer' },
        body: { error: 'invalid_request', error_description: tr('Không có header Authorization.', 'No Authorization header.') },
        reason: tr('Không trình ra bearer token nào.', 'No bearer token was presented.'),
        verification: null,
      };
    }

    const { keys } = this.loadJwks();
    const result = await verifyJwt(bearer, {
      jwks: keys,
      issuer: this.issuer,
      ...(this.audienceOn ? { audience: this.audience } : {}),
      now: this.clock.nowSec(),
      ...(this.posture
        ? {
            policy: {
              checkSignature: this.posture.flags.checkSignature,
              allowAlgNone: this.posture.flags.allowAlgNone,
              allowHs256: this.posture.flags.allowHs256,
              trustEmbeddedJwk: this.posture.flags.trustJku,
              ...(this.posture.flags.allowHs256 && this.publicKeyMaterial
                ? { hmacSecret: new TextEncoder().encode(this.publicKeyMaterial()) }
                : {}),
            },
          }
        : {}),
    });

    if (!result.valid) {
      const failed = result.checks.filter((c) => !c.ok);
      return {
        status: 401,
        statusText: 'Unauthorized',
        headers: { 'WWW-Authenticate': 'Bearer error="invalid_token"' },
        body: {
          error: 'invalid_token',
          error_description: failed.map((c) => `${c.name}: ${c.detail}`).join(' | '),
        },
        reason: tr(`Token bị từ chối ở ${failed.length} phép kiểm tra: ${failed.map((c) => c.name).join(', ')}.`, `Token rejected at ${failed.length} check(s): ${failed.map((c) => c.name).join(', ')}.`),
        verification: result,
      };
    }

    // Authentication succeeded. Authorization is a separate question.
    const scopes = String(result.decoded?.claims['scope'] ?? '').split(' ').filter(Boolean);
    if (!scopes.includes(requiredScope)) {
      return {
        status: 403,
        statusText: 'Forbidden',
        headers: {},
        body: {
          error: 'insufficient_scope',
          error_description: tr(`Endpoint này cần scope "${requiredScope}". Token chỉ mang [${scopes.join(', ')}].`, `This endpoint requires scope "${requiredScope}". The token only carries [${scopes.join(', ')}].`),
        },
        reason: tr(
          `Đã xác thực được là ${result.decoded?.claims.sub} nhưng thiếu scope "${requiredScope}". 401 là "anh là ai?", 403 là "anh không được phép".`,
          `Authenticated as ${result.decoded?.claims.sub} but missing scope "${requiredScope}". 401 means "who are you?", 403 means "you may not".`,
        ),
        verification: result,
      };
    }

    return {
      status: 200,
      statusText: 'OK',
      headers: { 'Content-Type': 'application/json' },
      body: {
        path,
        sub: result.decoded?.claims.sub,
        roles: result.decoded?.claims['roles'],
        data: tr('dữ liệu được bảo vệ mà bạn cần lấy', 'the protected data you came for'),
      },
      reason: tr(`Cả ${result.checks.length} phép kiểm tra đều đạt, và scope "${requiredScope}" có trong token.`, `All ${result.checks.length} checks passed, and scope "${requiredScope}" is present on the token.`),
      verification: result,
    };
  }

  reset(): void {
    this.jwksCache = null;
  }
}
