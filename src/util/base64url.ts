const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64uEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Byte helpers below allocate their own ArrayBuffer rather than returning
 * whatever a built-in handed back. WebCrypto's BufferSource will not accept a
 * view that might sit on a SharedArrayBuffer, so owning the buffer keeps every
 * call site assignable without casts.
 */
function alloc(len: number) {
  return new Uint8Array(new ArrayBuffer(len));
}

export function b64uDecode(input: string) {
  const pad = input.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4));
  const out = alloc(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

export function b64uJson(obj: unknown): string {
  return b64uEncode(enc.encode(JSON.stringify(obj)));
}

export function b64uToJson<T = unknown>(part: string): T {
  return JSON.parse(dec.decode(b64uDecode(part))) as T;
}

export function utf8(s: string) {
  const encoded = enc.encode(s);
  const out = alloc(encoded.length);
  out.set(encoded);
  return out;
}

export function randomBytes(n: number) {
  return crypto.getRandomValues(alloc(n));
}

export function randomToken(bytes = 32): string {
  return b64uEncode(randomBytes(bytes));
}
