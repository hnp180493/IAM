import { tr } from '../i18n';

export type PolicyModel = 'rbac' | 'abac' | 'rebac';

export interface Subject {
  sub: string;
  username: string;
  roles: string[];
  department: string;
  /** Giờ trong ngày, 0-23. Dùng cho ABAC. */
  atHour: number;
}

export interface Resource {
  id: string;
  kind: string;
  ownerSub: string;
  department: string;
  classification: 'public' | 'internal' | 'confidential';
}

export interface Decision {
  allow: boolean;
  model: PolicyModel;
  /** Từng bước suy luận, để người học thấy vì sao ra kết quả đó. */
  trace: { rule: string; result: string; decisive: boolean }[];
  summary: string;
}

/**
 * Ba cách trả lời cùng một câu hỏi: alice có được xoá tài liệu này không?
 *
 * Mỗi model trả về vết suy luận đầy đủ chứ không chỉ true/false, vì điểm cần
 * học chính là chỗ ba model bắt đầu lệch nhau.
 */
export class PolicyEngine {
  /** Ai có role thì làm được, hết. Không biết tài nguyên là của ai. */
  private rbac(s: Subject, _r: Resource, action: string): Decision {
    const trace: Decision['trace'] = [];
    const rolePerms: Record<string, string[]> = {
      reader: ['read'],
      writer: ['read', 'update', 'delete'],
      admin: ['read', 'update', 'delete', 'grant'],
    };

    trace.push({ rule: tr('Lấy role từ token', 'Read roles from the token'), result: s.roles.join(', ') || tr('(không có)', '(none)'), decisive: false });

    for (const role of s.roles) {
      const perms = rolePerms[role] ?? [];
      const hit = perms.includes(action);
      trace.push({
        rule: tr(`role "${role}" cho phép: ${perms.join(', ') || '(không gì)'}`, `role "${role}" permits: ${perms.join(', ') || '(nothing)'}`),
        result: hit ? tr(`có "${action}" -> CHO PHÉP`, `has "${action}" -> ALLOW`) : tr(`không có "${action}"`, `does not have "${action}"`),
        decisive: hit,
      });
      if (hit) {
        return {
          allow: true,
          model: 'rbac',
          trace,
          summary: tr(
            `Cho phép, chỉ vì ${s.username} mang role "${role}". RBAC không hề nhìn tới việc tài liệu này thuộc về ai. ${s.username} xoá được tài liệu của bất kỳ ai trong hệ thống.`,
            `Allowed, purely because ${s.username} carries role "${role}". RBAC never looks at who the document belongs to. ${s.username} can delete anyone's document in the system.`,
          ),
        };
      }
    }

    return {
      allow: false,
      model: 'rbac',
      trace,
      summary: tr(`Từ chối: không role nào của ${s.username} chứa quyền "${action}".`, `Denied: none of ${s.username}'s roles carry the "${action}" permission.`),
    };
  }

  /** Xét thuộc tính của cả subject và resource, cộng cả bối cảnh. */
  private abac(s: Subject, r: Resource, action: string): Decision {
    const trace: Decision['trace'] = [];

    const sameDept = s.department === r.department;
    trace.push({
      rule: tr('Cùng phòng ban?', 'Same department?'),
      result: `${s.department} vs ${r.department} -> ${sameDept ? tr('có', 'yes') : tr('KHÔNG', 'NO')}`,
      decisive: !sameDept,
    });
    if (!sameDept) {
      return {
        allow: false,
        model: 'abac',
        trace,
        summary: tr(
          `Từ chối: tài liệu thuộc phòng ${r.department}, ${s.username} ở phòng ${s.department}. RBAC đã bỏ qua chi tiết này.`,
          `Denied: the document belongs to ${r.department}, ${s.username} is in ${s.department}. RBAC skipped this detail entirely.`,
        ),
      };
    }

    const inHours = s.atHour >= 8 && s.atHour < 18;
    trace.push({
      rule: tr('Trong giờ làm việc (8h-18h)?', 'During business hours (8h-18h)?'),
      result: `${s.atHour}h -> ${inHours ? tr('có', 'yes') : tr('KHÔNG', 'NO')}`,
      decisive: !inHours,
    });
    if (!inHours) {
      return {
        allow: false,
        model: 'abac',
        trace,
        summary: tr(
          `Từ chối: thao tác "${action}" trên dữ liệu ${r.classification} chỉ được làm trong giờ làm việc. Hiện là ${s.atHour}h.`,
          `Denied: "${action}" on ${r.classification} data is only allowed during business hours. It is currently ${s.atHour}h.`,
        ),
      };
    }

    const needsWriter = ['update', 'delete'].includes(action);
    const hasWriter = s.roles.includes('writer') || s.roles.includes('admin');
    trace.push({
      rule: needsWriter ? tr('Thao tác ghi, cần role writer', 'Write action, needs role writer') : tr('Thao tác đọc', 'Read action'),
      result: needsWriter ? (hasWriter ? tr('có writer', 'has writer') : tr('KHÔNG có writer', 'NO writer')) : tr('không cần role ghi', 'no write role needed'),
      decisive: needsWriter && !hasWriter,
    });
    if (needsWriter && !hasWriter) {
      return { allow: false, model: 'abac', trace, summary: tr('Từ chối: thiếu role ghi.', 'Denied: missing a write role.') };
    }

    return {
      allow: true,
      model: 'abac',
      trace,
      summary: tr(
        `Cho phép: cùng phòng ban, trong giờ làm việc, đủ role. Chặt hơn RBAC nhưng vẫn chưa hỏi "tài liệu này của ai" - nên ${s.username} vẫn xoá được tài liệu của đồng nghiệp cùng phòng.`,
        `Allowed: same department, business hours, sufficient role. Stricter than RBAC but still never asks "whose document is this" — so ${s.username} can still delete a colleague's document in the same department.`,
      ),
    };
  }

  /** Hỏi thẳng câu quan trọng nhất: giữa người này và vật này có quan hệ gì? */
  private rebac(s: Subject, r: Resource, action: string): Decision {
    const trace: Decision['trace'] = [];

    const isOwner = r.ownerSub === s.sub;
    trace.push({
      rule: tr(`Quan hệ giữa ${s.username} và ${r.kind}:${r.id}`, `Relationship between ${s.username} and ${r.kind}:${r.id}`),
      result: isOwner ? tr('owner', 'owner') : tr(`không có quan hệ (chủ sở hữu là ${r.ownerSub})`, `no relationship (owner is ${r.ownerSub})`),
      decisive: true,
    });

    const ownerCan = ['read', 'update', 'delete', 'share'];
    if (isOwner && ownerCan.includes(action)) {
      return {
        allow: true,
        model: 'rebac',
        trace,
        summary: tr(`Cho phép: ${s.username} là owner của tài liệu này, và owner được "${action}".`, `Allowed: ${s.username} is the owner of this document, and owners may "${action}".`),
      };
    }

    if (!isOwner) {
      trace.push({
        rule: tr('Có được chia sẻ trực tiếp?', 'Shared directly?'),
        result: tr('không có bản ghi chia sẻ nào', 'no sharing record found'),
        decisive: true,
      });
      return {
        allow: false,
        model: 'rebac',
        trace,
        summary: tr(
          `Từ chối: ${s.username} không có quan hệ nào với ${r.kind}:${r.id}. Role không cứu được ở đây, vì câu hỏi không phải "anh là ai" mà là "anh với vật này liên quan gì". Đây là mô hình chặn được IDOR.`,
          `Denied: ${s.username} has no relationship to ${r.kind}:${r.id}. A role doesn't save you here, because the question isn't "who are you" but "how are you related to this thing". This is the model that blocks IDOR.`,
        ),
      };
    }

    return { allow: false, model: 'rebac', trace, summary: tr(`Từ chối: owner không có quyền "${action}".`, `Denied: the owner does not have "${action}" permission.`) };
  }

  evaluate(model: PolicyModel, s: Subject, r: Resource, action: string): Decision {
    if (model === 'rbac') return this.rbac(s, r, action);
    if (model === 'abac') return this.abac(s, r, action);
    return this.rebac(s, r, action);
  }

  /** Chạy cả ba trên cùng một yêu cầu - đó là cách duy nhất thấy được chỗ chúng lệch nhau. */
  evaluateAll(s: Subject, r: Resource, action: string): Decision[] {
    return (['rbac', 'abac', 'rebac'] as PolicyModel[]).map((m) => this.evaluate(m, s, r, action));
  }
}
