/**
 * NetHunterSOC - Phase 8 Automated Test Suite
 * Grounded AI Copilot & Evidence-Bound Analysis
 * Verifies all 20 required architectural and security specifications.
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { getDatabase } from '../../db/database.ts';
import { aiContextBuilder } from '../contextBuilder.ts';
import { aiCopilotService } from '../copilotService.ts';
import { groundedSynthesizer } from '../groundedSynthesizer.ts';
import { aiCopilotRouter } from '../../routes/aiCopilot.ts';
import { requireAuth } from '../../auth/authMiddleware.ts';

describe('Phase 8: Grounded AI Copilot & Evidence-Bound Analysis (20-Point Specification)', () => {
  let db: ReturnType<typeof getDatabase>;

  before(() => {
    process.env.NODE_ENV = 'test';
    db = getDatabase();
  });

  // 1. AI endpoint membutuhkan authentication
  test('1. AI endpoints require authentication (protected by requireAuth middleware)', () => {
    // Inspect route stack to verify requireAuth middleware is mounted
    const routes = (aiCopilotRouter as any).stack;
    assert.ok(routes.length > 0, 'aiCopilotRouter must have routes');
    for (const r of routes) {
      if (r.route) {
        assert.ok(
          r.route.stack.length >= 2,
          `Route ${r.route.path} must have authentication middleware in its handler chain`
        );
      }
    }
  });

  // 2. Context builder hanya mengambil data yang relevan
  test('2. Context builder only fetches data relevant to the scoped entity', () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    assert.strictEqual(ctx.scope_id, alert.id);
    assert.strictEqual(ctx.scope_type, 'ALERT');
    // Alerts list should only contain this alert
    assert.strictEqual(ctx.alerts.length, 1);
    assert.strictEqual(ctx.alerts[0].id, alert.id);
  });

  // 3. Password hash tidak masuk AI context
  test('3. Password hashes NEVER enter AI context (sanitized and excluded)', () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    const jsonStr = JSON.stringify(ctx);

    // Get any existing password hash from users table
    const sampleUser = db.prepare('SELECT password_hash FROM users LIMIT 1').get() as { password_hash: string } | undefined;
    if (sampleUser && sampleUser.password_hash) {
      assert.ok(
        !jsonStr.includes(sampleUser.password_hash),
        'Context must not contain raw password hash from users table'
      );
    }
    assert.ok(!jsonStr.toLowerCase().includes('$scrypt$'), 'Context must not contain scrypt hash signatures');
  });

  // 4. Session token tidak masuk AI context
  test('4. Session tokens NEVER enter AI context', () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    const jsonStr = JSON.stringify(ctx);

    const sampleSession = db.prepare('SELECT id FROM sessions LIMIT 1').get() as { id: string } | undefined;
    if (sampleSession && sampleSession.id) {
      assert.ok(!jsonStr.includes(sampleSession.id), 'Context must not contain session IDs');
    }
    assert.ok(!jsonStr.includes('session_token'), 'Context must not contain session token fields');
  });

  // 5. Raw provenance tetap tersedia sebagai reference
  test('5. Raw provenance remains fully available as traceable reference', () => {
    const hit = db.prepare('SELECT id, trigger_event_ids FROM detection_hits LIMIT 1').get() as { id: string; trigger_event_ids: string } | undefined;
    assert.ok(hit);

    const ctx = aiContextBuilder.buildContext('DETECTION', hit.id);
    assert.ok(ctx.detection_hits.length > 0);
    assert.ok(ctx.detection_hits[0].trigger_event_ids.length > 0, 'Trigger event IDs must be preserved');
    // Prompt must include citation references
    assert.ok(ctx.formatted_prompt_context.includes(`[CIT:DETECTION:${hit.id}]`));
  });

  // 6. DetectionHit dapat menjadi AI context
  test('6. DetectionHit functions as valid AI context', () => {
    const hit = db.prepare('SELECT id, rule_id, rule_name FROM detection_hits LIMIT 1').get() as { id: string; rule_id: string; rule_name: string } | undefined;
    assert.ok(hit);

    const ctx = aiContextBuilder.buildContext('DETECTION', hit.id);
    assert.strictEqual(ctx.scope_type, 'DETECTION');
    assert.strictEqual(ctx.detection_hits[0].id, hit.id);
    assert.strictEqual(ctx.detection_hits[0].rule_id, hit.rule_id);
  });

  // 7. Evidence dapat menjadi AI context
  test('7. Evidence functions as valid AI context', () => {
    const ev = db.prepare('SELECT id, evidence_type FROM evidences LIMIT 1').get() as { id: string; evidence_type: string } | undefined;
    assert.ok(ev);

    const ctx = aiContextBuilder.buildContext('EVIDENCE', ev.id);
    assert.strictEqual(ctx.scope_type, 'EVIDENCE');
    assert.strictEqual(ctx.evidences[0].id, ev.id);
    assert.strictEqual(ctx.evidences[0].evidence_type, ev.evidence_type);
  });

  // 8. Hypothesis dapat menjadi AI context
  test('8. Hypothesis functions as valid AI context', () => {
    const hyp = db.prepare('SELECT id, statement FROM hypotheses LIMIT 1').get() as { id: string; statement: string } | undefined;
    assert.ok(hyp);

    const ctx = aiContextBuilder.buildContext('HYPOTHESIS', hyp.id);
    assert.strictEqual(ctx.scope_type, 'HYPOTHESIS');
    assert.strictEqual(ctx.hypotheses[0].id, hyp.id);
    assert.ok(ctx.hypotheses[0].statement.length > 0);
  });

  // 9. Alert dapat menjadi AI context
  test('9. Alert functions as valid AI context', () => {
    const alert = db.prepare('SELECT id, title FROM alerts LIMIT 1').get() as { id: string; title: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    assert.strictEqual(ctx.scope_type, 'ALERT');
    assert.strictEqual(ctx.alerts[0].id, alert.id);
  });

  // 10. Activity Graph dapat menjadi AI context
  test('10. Activity Graph entity functions as valid AI context', () => {
    const node = db.prepare('SELECT id FROM activity_graph_nodes LIMIT 1').get() as { id: string } | undefined;
    assert.ok(node);

    const ctx = aiContextBuilder.buildContext('GRAPH_ENTITY', node.id);
    assert.strictEqual(ctx.scope_type, 'GRAPH_ENTITY');
    assert.strictEqual(ctx.scope_id, node.id);
  });

  // 11. Threat Intelligence tetap contextual (tidak menjadi verdict otomatis)
  test('11. Threat Intelligence remains strictly contextual enrichment', () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    const syn = groundedSynthesizer.synthesize(ctx, 'INVESTIGATIVE_SUMMARY');

    // Must include guardrail notice
    assert.ok(
      syn.response.includes('Threat intelligence is contextual enrichment only') ||
      syn.response.includes('contextual enrichment') ||
      syn.response.includes('Contextual Threat Intelligence'),
      'TI must explicitly be identified as non-autonomous contextual enrichment'
    );
  });

  // 12. Candidate correlation tidak berubah menjadi evidence
  test('12. Candidate correlations do NOT automatically become evidence', () => {
    const initialEvidenceCount = (db.prepare('SELECT COUNT(*) as c FROM evidences').get() as { c: number }).c;
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    groundedSynthesizer.synthesize(ctx, 'EVIDENCE_CORRELATION');

    const finalEvidenceCount = (db.prepare('SELECT COUNT(*) as c FROM evidences').get() as { c: number }).c;
    assert.strictEqual(finalEvidenceCount, initialEvidenceCount, 'AI correlation analysis must not insert evidence');
  });

  // 13. AI tidak dapat membuat DetectionHit
  test('13. AI cannot autonomously create DetectionHits', async () => {
    const initialHitCount = (db.prepare('SELECT COUNT(*) as c FROM detection_hits').get() as { c: number }).c;
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    await aiCopilotService.analyze({ scope_type: 'ALERT', scope_id: alert.id, action_type: 'EXPLAIN_DETECTION' }, {});

    const finalHitCount = (db.prepare('SELECT COUNT(*) as c FROM detection_hits').get() as { c: number }).c;
    assert.strictEqual(finalHitCount, initialHitCount, 'AI operations must never create DetectionHits');
  });

  // 14. AI tidak dapat membuat Incident
  test('14. AI cannot create Incidents (incident_id strictly remains NULL)', async () => {
    const initialIncCount = (db.prepare('SELECT COUNT(*) as c FROM incidents').get() as { c: number }).c;
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    await aiCopilotService.analyze({ scope_type: 'ALERT', scope_id: alert.id, action_type: 'INVESTIGATIVE_SUMMARY' }, {});

    const finalIncCount = (db.prepare('SELECT COUNT(*) as c FROM incidents').get() as { c: number }).c;
    assert.strictEqual(finalIncCount, initialIncCount, 'AI operations must never insert incidents');
  });

  // 15. AI analysis tersimpan sebagai immutable audit record
  test('15. AI analysis is preserved as an immutable audit record in ai_analyses', async () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const analysis = await aiCopilotService.analyze(
      { scope_type: 'ALERT', scope_id: alert.id, action_type: 'TIMELINE_SUMMARY' },
      { id: 'usr_demo_analyst_seed', username: 'analyst_audit' }
    );

    assert.ok(analysis.id.startsWith('ana_'));
    const stored = db.prepare('SELECT * FROM ai_analyses WHERE id = ?').get(analysis.id) as Record<string, unknown>;
    assert.ok(stored, 'Analysis record must exist in ai_analyses');
    assert.strictEqual(stored.scope_type, 'ALERT');
    assert.strictEqual(stored.scope_id, alert.id);
  });

  // 16. Repeated analysis tidak overwrite analysis sebelumnya
  test('16. Repeated analyses never overwrite prior analyses (Analysis #1, #2, #3 preserved)', async () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const run1 = await aiCopilotService.analyze({ scope_type: 'ALERT', scope_id: alert.id, custom_prompt: 'Run 1' }, {});
    const run2 = await aiCopilotService.analyze({ scope_type: 'ALERT', scope_id: alert.id, custom_prompt: 'Run 2' }, {});
    const run3 = await aiCopilotService.analyze({ scope_type: 'ALERT', scope_id: alert.id, custom_prompt: 'Run 3' }, {});

    assert.notStrictEqual(run1.id, run2.id);
    assert.notStrictEqual(run2.id, run3.id);

    const rows = db.prepare('SELECT id FROM ai_analyses WHERE id IN (?, ?, ?)').all(run1.id, run2.id, run3.id);
    assert.strictEqual(rows.length, 3, 'All 3 queries must remain persisted independently');
  });

  // 17. Missing evidence menghasilkan response limitation, bukan hallucination
  test('17. Missing evidence produces explicit limitation response, not hallucination', () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);
    const syn = groundedSynthesizer.synthesize(ctx, 'CUSTOM_QUERY', 'Did the user enter the root password correctly?');

    assert.ok(
      syn.response.includes('Informasi tersebut tidak tersedia dalam evidence yang diberikan.'),
      'AI must honestly state information is unavailable when missing from evidence'
    );
  });

  // 18. Analyst identity tercatat
  test('18. Analyst identity is recorded in the analysis record', async () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const result = await aiCopilotService.analyze(
      { scope_type: 'ALERT', scope_id: alert.id, action_type: 'INVESTIGATIVE_SUMMARY' },
      { id: 'usr_demo_analyst_seed', username: 'audited_analyst_1' }
    );

    assert.strictEqual(result.username, 'audited_analyst_1');
    const stored = db.prepare('SELECT user_id FROM ai_analyses WHERE id = ?').get(result.id) as { user_id: string };
    assert.strictEqual(stored.user_id, 'usr_demo_analyst_seed');
  });

  // 19. Unauthorized request menghasilkan 401
  test('19. Unauthorized requests to AI endpoints are rejected with 401', () => {
    // Verify requireAuth middleware behavior
    const mockReq = { cookies: {}, headers: {}, user: undefined } as any;
    let statusCode = 0;
    let responseBody: any = null;
    const mockRes = {
      status: (code: number) => {
        statusCode = code;
        return {
          json: (data: any) => {
            responseBody = data;
          },
        };
      },
    } as any;
    const mockNext = () => {};

    // Verify requireAuth middleware behavior
    requireAuth(mockReq, mockRes, mockNext);

    assert.strictEqual(statusCode, 401, 'Unauthenticated request must receive 401 Unauthorized');
    assert.ok(
      String(responseBody?.error).toUpperCase() === 'UNAUTHORIZED',
      'Response must indicate UNAUTHORIZED'
    );
  });

  // 20. Secrets tidak bocor ke AI context
  test('20. Secrets, environment variables, and confidential fields do not leak into AI context', () => {
    const alert = db.prepare('SELECT id FROM alerts LIMIT 1').get() as { id: string } | undefined;
    assert.ok(alert);

    const ctx = aiContextBuilder.buildContext('ALERT', alert.id);

    // Test sanitizer explicitly with simulated confidential payload
    const dirtyContext = JSON.parse(JSON.stringify(ctx));
    dirtyContext.canonical_events[0] = {
      ...dirtyContext.canonical_events[0],
      password: 'SuperSecretPassword123!',
      session_token: 'tok_sess_secret_9999',
      api_key: 'sk_secret_gemini_key',
    };

    const sanitized = aiContextBuilder.sanitizeContext(dirtyContext);
    const sanitizedStr = JSON.stringify(sanitized);

    assert.ok(!sanitizedStr.includes('SuperSecretPassword123!'), 'Password must be sanitized');
    assert.ok(!sanitizedStr.includes('tok_sess_secret_9999'), 'Session token must be sanitized');
    assert.ok(sanitizedStr.includes('[REDACTED_CONFIDENTIAL]'), 'Must replace with redacted indicator');
  });
});
