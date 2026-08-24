export interface ParsedCommand {
  /** Các từ không phải cờ: 'jwt', 'decode', '@access'... */
  words: string[];
  /** --key value, hoặc --key (cờ bật). */
  flags: Record<string, string | true>;
  raw: string;
}

/**
 * Tách dòng lệnh. Hỗ trợ nháy để scope có dấu cách nằm gọn trong một tham số:
 *   authorize --scope "openid profile read:reports"
 */
export function parse(raw: string): ParsedCommand {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;

  for (const ch of raw.trim()) {
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ' ') {
      if (current) tokens.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);

  const words: string[] = [];
  const flags: Record<string, string | true> = {};

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (!t.startsWith('--')) {
      words.push(t);
      continue;
    }
    const key = t.slice(2);
    const next = tokens[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      // --set roles=admin có thể xuất hiện nhiều lần: gộp bằng dấu ;
      if (flags[key] !== undefined && typeof flags[key] === 'string') {
        flags[key] = `${flags[key] as string};${next}`;
      } else {
        flags[key] = next;
      }
      i += 1;
    } else {
      flags[key] = true;
    }
  }

  return { words, flags, raw: raw.trim() };
}

export function flagStr(p: ParsedCommand, key: string, fallback = ''): string {
  const v = p.flags[key];
  return typeof v === 'string' ? v : fallback;
}

export function flagBool(p: ParsedCommand, key: string): boolean {
  return p.flags[key] === true || p.flags[key] === 'true';
}
