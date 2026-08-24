import { b64uEncode, randomToken, utf8 } from '../util/base64url';
import { tr } from '../i18n';

export type PkceMethod = 'S256' | 'plain' | 'none';

/** RFC 7636 code_verifier: 43-128 chars of unreserved ASCII. */
export function createVerifier(): string {
  return randomToken(32);
}

/** RFC 7636 4.2 — real SHA-256, not a stand-in. */
export async function challengeFrom(verifier: string, method: PkceMethod): Promise<string | null> {
  if (method === 'none') return null;
  if (method === 'plain') return verifier;
  const digest = await crypto.subtle.digest('SHA-256', utf8(verifier));
  return b64uEncode(new Uint8Array(digest));
}

/**
 * Server side of the PKCE check. Returns why it failed, not just that it did —
 * the whole point of the lab is that a rejection is explainable.
 */
export async function verifyChallenge(
  verifier: string | undefined,
  challenge: string | null,
  method: PkceMethod,
): Promise<{ ok: boolean; reason: string }> {
  if (method === 'none' || challenge === null) {
    return { ok: true, reason: tr('Authorization code này không gắn PKCE - ai giữ code cũng đổi được thành token.', 'This authorization code has no PKCE binding — whoever holds the code can redeem it for a token.') };
  }
  if (!verifier) {
    return { ok: false, reason: tr('Code đã được gắn code_challenge nhưng không thấy code_verifier nào được trình ra.', 'The code was bound to a code_challenge but no code_verifier was presented.') };
  }
  const derived = await challengeFrom(verifier, method);
  if (derived === challenge) {
    return { ok: true, reason: tr(`code_verifier băm ra đúng code_challenge đã gắn (${method}).`, `code_verifier hashes to the bound code_challenge (${method}).`) };
  }
  return {
    ok: false,
    reason:
      method === 'S256'
        ? tr(
            'SHA-256(code_verifier) không khớp code_challenge đã gắn. code_verifier chưa bao giờ rời khỏi client thật, nên code bị trộm là vô dụng.',
            'SHA-256(code_verifier) does not match the bound code_challenge. code_verifier never left the real client, so a stolen code is useless.',
          )
        : tr('code_verifier không bằng code_challenge đã gắn.', 'code_verifier does not equal the bound code_challenge.'),
  };
}
