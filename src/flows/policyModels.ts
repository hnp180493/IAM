import { PolicyEngine, type Resource, type Subject } from '../engine/PolicyEngine';
import { HopRecorder, httpText, type FlowResult } from './kit';
import { tr } from '../i18n';
import type { Clock } from '../core/Clock';

const MODEL_LABEL: Record<string, string> = {
  rbac: 'RBAC',
  abac: 'ABAC',
  rebac: 'ReBAC',
};

/**
 * One request, three authorization models, three different answers.
 *
 * The scenario is chosen so the three models are forced to disagree: alice has
 * the writer role (so RBAC lets it through), is in the same department as the
 * document and it's during business hours (so ABAC also lets it through), but
 * the document belongs to bob (so ReBAC blocks it).
 */
export async function runPolicyModels(clock: Clock, opts: { atHour: number }): Promise<FlowResult> {
  const rec = new HopRecorder(clock);
  const engine = new PolicyEngine();

  const alice: Subject = {
    sub: 'user-8f21',
    username: 'alice',
    roles: ['reader', 'writer'],
    department: 'sales',
    atHour: opts.atHour,
  };
  const doc: Resource = {
    id: '42',
    kind: 'doc',
    ownerSub: 'user-b0b0',
    department: 'sales',
    classification: 'confidential',
  };
  const action = 'delete';

  rec.push({
    from: 'client',
    to: 'api',
    label: 'DELETE /docs/42',
    tone: 'normal',
    http: {
      kind: 'request',
      method: 'DELETE',
      url: 'https://api.example.com/docs/42',
      headers: { Authorization: 'Bearer eyJ...' },
    },
    note: tr(
      `alice yêu cầu xoá doc:42. Token của cô ấy hoàn toàn hợp lệ, chữ ký đúng, chưa hết hạn. ` +
        `Câu hỏi còn lại không phải "alice là ai" mà "alice có được xoá cái này không". ` +
        `Tài liệu này thuộc về bob, cùng phòng sales, mức confidential. Hiện là ${opts.atHour}h.`,
      `alice requests to delete doc:42. Her token is completely valid — correct signature, not expired. ` +
        `The remaining question isn't "who is alice" but "is alice allowed to delete this". ` +
        `The document belongs to bob, same sales department, confidential classification. It's currently ${opts.atHour}h.`,
    ),
  });

  const decisions = engine.evaluateAll(alice, doc, action);

  for (const d of decisions) {
    const traceText = d.trace.map((t) => `${t.decisive ? '>>' : '  '} ${t.rule}\n     ${t.result}`).join('\n');
    rec.push({
      from: 'api',
      to: 'api',
      label: `${MODEL_LABEL[d.model]}: ${d.allow ? tr('CHO PHÉP', 'ALLOW') : tr('TỪ CHỐI', 'DENY')}`,
      tone: d.allow ? 'danger' : 'success',
      http: {
        kind: 'request',
        method: 'EVAL',
        url: `${d.model}(alice, doc:42, delete)`,
        headers: {},
        body: traceText,
      },
      note: d.summary,
    });
  }

  const rebac = decisions.find((d) => d.model === 'rebac')!;
  const rbac = decisions.find((d) => d.model === 'rbac')!;

  rec.push({
    from: 'api',
    to: 'client',
    label: rebac.allow ? '204 No Content' : '403 Forbidden',
    tone: rebac.allow ? 'success' : 'blocked',
    http: {
      kind: 'response',
      status: rebac.allow ? 204 : 403,
      statusText: rebac.allow ? 'No Content' : 'Forbidden',
      headers: {},
      body: rebac.allow
        ? undefined
        : httpText({ error: 'forbidden', error_description: tr('Bạn không có quan hệ nào với tài nguyên này.', 'You have no relationship to this resource.') }),
    },
    note: tr(`Kết quả cuối dùng ReBAC - mô hình chặt nhất trong ba. ${rebac.summary}`, `The final result uses ReBAC — the strictest of the three models. ${rebac.summary}`),
  });

  return {
    packets: rec.packets,
    outcome: rebac.allow ? 'success' : 'failed',
    summary:
      rbac.allow && !rebac.allow
        ? tr(
            'Cùng một yêu cầu: RBAC cho qua, ReBAC chặn. Chênh lệch đó chính là lỗ IDOR. Role trả lời "anh là ai", quan hệ trả lời "cái này có phải của anh" - và hầu hết lỗ hổng phân quyền nằm ở câu thứ hai.',
            'The same request: RBAC lets it through, ReBAC blocks it. That gap is exactly the IDOR hole. A role answers "who are you", a relationship answers "is this yours" — and most authorization vulnerabilities live in the second question.',
          )
        : tr(
            'Cả ba mô hình đồng thuận ở tình huống này. Đổi giờ sang ngoài giờ làm việc để thấy ABAC tách khỏi RBAC.',
            'All three models agree in this scenario. Change the hour to outside business hours to see ABAC diverge from RBAC.',
          ),
  };
}
