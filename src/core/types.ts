import { tr } from '../i18n';
import type { VerifyResult } from '../crypto/jose';

export type Lane = 'browser' | 'client' | 'client2' | 'authserver' | 'idp' | 'api' | 'api2' | 'attacker';

export function laneList(): { id: Lane; label: string; sub: string }[] {
  return [
    { id: 'browser', label: 'Browser', sub: 'user agent' },
    { id: 'client', label: 'App 1', sub: 'spa.example.com' },
    { id: 'client2', label: 'App 2', sub: 'wiki.example.com' },
    { id: 'authserver', label: 'Auth Server', sub: 'id.example.com' },
    { id: 'idp', label: tr('IdP ngoài', 'External IdP'), sub: 'login.partner.com' },
    { id: 'api', label: 'Resource API', sub: 'api.example.com' },
    { id: 'api2', label: tr('API nội bộ', 'Internal API'), sub: 'api-internal.example.com' },
    { id: 'attacker', label: 'Attacker', sub: 'evil.example.com' },
  ];
}

export interface HttpMessage {
  kind: 'request' | 'response';
  method?: string;
  url?: string;
  status?: number;
  statusText?: string;
  headers: Record<string, string>;
  body?: string;
}

export interface TokenRef {
  label: string;
  value: string;
}

export interface Packet {
  id: string;
  seq: number;
  from: Lane;
  to: Lane;
  label: string;
  http: HttpMessage;
  /** Plain-language explanation of what this hop accomplishes. */
  note: string;
  tone: 'normal' | 'danger' | 'success' | 'blocked';
  tokens?: TokenRef[];
  atSec: number;
  /** Present only on hops where a server actually validated the token. */
  verification?: VerifyResult | null;
}
