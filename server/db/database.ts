import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { config } from '../config.ts';
import { logger } from '../logger.ts';
import { hashPassword } from '../auth/authService.ts';
import { seedInvestigationDemoData } from '../investigation/seedInvestigationDemo.ts';
import { seedThreatIntelData } from '../threatintel/seedThreatIntel.ts';
import { activityGraphService } from '../investigation/activityGraphService.ts';

let dbInstance: DatabaseSync | null = null;

export function getDatabase(): DatabaseSync {
  if (dbInstance) {
    return dbInstance;
  }

  const dbDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    logger.info('Database', `Created database directory at ${dbDir}`);
  }

  logger.info('Database', `Opening SQLite database at ${config.dbPath}`);
  dbInstance = new DatabaseSync(config.dbPath);

  // Configure WAL (Write-Ahead Logging) and Performance Pragmas
  dbInstance.exec('PRAGMA journal_mode = WAL;');
  dbInstance.exec('PRAGMA synchronous = NORMAL;');
  dbInstance.exec('PRAGMA foreign_keys = ON;');

  // Initialize Schema
  initSchema(dbInstance);

  // Seed Initial Demo & IOC Data
  seedInitialData(dbInstance);

  return dbInstance;
}

function initSchema(db: DatabaseSync): void {
  try {
    // Run pre-migration in case normalized_events already exists from Phase 1
    migrateColumns(db);

    const schemaPath = path.join(process.cwd(), 'server', 'db', 'schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      db.exec(schemaSql);
      migrateColumns(db);
      logger.info('Database', 'Database schema initialized successfully with WAL mode');
    } else {
      logger.error('Database', `Schema file not found at ${schemaPath}`);
    }
  } catch (error) {
    logger.error('Database', 'Failed to initialize database schema', {
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

function seedInitialData(db: DatabaseSync): void {
  try {
    // 1. Seed Demo Analyst Account if enabled (without hardcoded passwords)
    if (config.demoEnabled) {
      const demoUser = config.demoUsername;
      const existingUser = db.prepare(
        'SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?'
      ).get(demoUser.toLowerCase(), `${demoUser.toLowerCase()}@nethuntersoc.local`);

      if (!existingUser) {
        // Use DEMO_PASSWORD environment variable if provided; otherwise generate random scrypt hash
        const rawPassword = config.demoPassword || crypto.randomUUID();
        const passwordHash = hashPassword(rawPassword);
        const now = new Date().toISOString();
        const userId = 'usr_demo_analyst_seed';
        db.prepare(`
          INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at, last_login_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(userId, demoUser, `${demoUser}@nethuntersoc.local`, passwordHash, 'analyst', now, now, null);
        logger.info('Database', `Seeded development demo account: ${demoUser} (role: analyst)`);
      }
    }

    // 2. Seed Default Local IOCs if table is empty (local observational watchlists)
    const iocCountRow = db.prepare('SELECT COUNT(*) as count FROM local_iocs').get() as { count: number } | undefined;
    if (iocCountRow && Number(iocCountRow.count) === 0) {
      const seedIocs = [
        { id: 'ioc_01', val: '198.51.100.45', type: 'IP', cat: 'external_c2_watchlist', desc: 'Local watchlist indicator: external rendezvous node' },
        { id: 'ioc_02', val: '203.0.113.88', type: 'IP', cat: 'controller_ip_watchlist', desc: 'Local watchlist indicator: suspicious controller host' },
        { id: 'ioc_03', val: 'c2-malicious-traffic.com', type: 'DOMAIN', cat: 'suspicious_domain_watchlist', desc: 'Local watchlist indicator: flagged domain' },
        { id: 'ioc_04', val: 'evil-telemetry-drop.net', type: 'DOMAIN', cat: 'phishing_domain_watchlist', desc: 'Local watchlist indicator: flagged exfiltration domain' },
      ];
      const insertIoc = db.prepare(
        'INSERT OR IGNORE INTO local_iocs (id, ioc_value, ioc_type, threat_category, description, is_active, added_date) VALUES (?, ?, ?, ?, ?, 1, ?)'
      );
      const now = new Date().toISOString();
      for (const i of seedIocs) {
        insertIoc.run(i.id, i.val, i.type, i.cat, i.desc, now);
      }
      logger.info('Database', `Seeded ${seedIocs.length} initial local IOCs`);
    }

    // 3. Seed Default Suppression Rule (Authorized Vulnerability Scanner) if table is empty
    const suppressionCountRow = db.prepare('SELECT COUNT(*) as count FROM suppression_rules').get() as { count: number } | undefined;
    if (suppressionCountRow && Number(suppressionCountRow.count) === 0) {
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO suppression_rules (id, ip_cidr, target_port, detection_rule_id, reason, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
      `).run(
        'sup_authorized_sec_scanner',
        '192.168.1.10',
        null,
        'PS-001',
        'Authorized internal vulnerability scanner (Nessus/OpenVAS host) - scan activity is expected and documented',
        now
      );
      logger.info('Database', 'Seeded initial suppression rule for authorized scanner 192.168.1.10 (PS-001)');
    }

    // 4. Seed Phase 4 Investigation Demo Scenario (Hypothesis & Evidence)
    seedInvestigationDemoData();

    // 5. Seed Phase 6 Threat Intelligence & Contextual Enrichment Demo Data
    seedThreatIntelData();

    // 6. Build Phase 7 Activity Graph & Explainable Correlation Model
    activityGraphService.buildGraph({ scopeId: 'global', temporalWindowSeconds: 60 });
  } catch (err) {
    logger.warn('Database', 'Notice during seedInitialData execution', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

function migrateColumns(db: DatabaseSync): void {
  try {
    const tblCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='normalized_events';").all();
    if (tblCheck.length === 0) return;

    const tableInfo = db.prepare('PRAGMA table_info(normalized_events);').all() as Array<{ name: string }>;
    const existingCols = new Set(tableInfo.map((c) => c.name));

    const newColumns: Array<{ name: string; type: string }> = [
      { name: 'bytes_in', type: 'INTEGER' },
      { name: 'bytes_out', type: 'INTEGER' },
      { name: 'application_protocol', type: 'TEXT' },
      { name: 'dns_query', type: 'TEXT' },
      { name: 'dns_qtype', type: 'TEXT' },
      { name: 'dns_rcode', type: 'TEXT' },
      { name: 'event_type', type: "TEXT DEFAULT 'flow'" },
      { name: 'alert_signature', type: 'TEXT' },
      { name: 'alert_category', type: 'TEXT' },
      { name: 'alert_severity', type: 'INTEGER' },
      { name: 'ioc_indicator', type: 'TEXT' },
      { name: 'source_format', type: "TEXT NOT NULL DEFAULT 'unknown'" },
      { name: 'source_file', type: 'TEXT' },
      { name: 'source_event_type', type: 'TEXT' },
      { name: 'src_ip_scope', type: 'TEXT' },
      { name: 'dst_ip_scope', type: 'TEXT' },
    ];

    for (const col of newColumns) {
      if (!existingCols.has(col.name)) {
        db.exec(`ALTER TABLE normalized_events ADD COLUMN ${col.name} ${col.type};`);
        logger.info('Database', `Migrated column normalized_events.${col.name}`);
      }
    }

    // Ensure new indices exist
    db.exec(`CREATE INDEX IF NOT EXISTS idx_events_event_type ON normalized_events(event_type);`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_events_proto_time ON normalized_events(protocol, timestamp);`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_events_batch ON normalized_events(ingest_batch_id);`);

    // Ensure detection_hits table and indices exist
    db.exec(`
      CREATE TABLE IF NOT EXISTS detection_hits (
        id TEXT PRIMARY KEY,
        fingerprint TEXT UNIQUE NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        detection_reason TEXT NOT NULL,
        threshold REAL NOT NULL,
        observed_value REAL NOT NULL,
        window_start TEXT NOT NULL,
        window_end TEXT NOT NULL,
        trigger_event_ids TEXT NOT NULL,
        ioc_id TEXT,
        ioc_value TEXT,
        ioc_type TEXT,
        ioc_source TEXT,
        suppression_rule_id TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_detection_hits_timestamp ON detection_hits(timestamp);
      CREATE INDEX IF NOT EXISTS idx_detection_hits_rule ON detection_hits(rule_id);
      CREATE INDEX IF NOT EXISTS idx_detection_hits_status ON detection_hits(status);
      CREATE INDEX IF NOT EXISTS idx_detection_hits_src ON detection_hits(src_ip);
      CREATE INDEX IF NOT EXISTS idx_detection_hits_dst ON detection_hits(dst_ip);
      CREATE INDEX IF NOT EXISTS idx_detection_hits_fingerprint ON detection_hits(fingerprint);
    `);

    // Phase 4 Evidence Model Schema Migration
    const evidencesCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='evidences';").all();
    if (evidencesCheck.length > 0) {
      const evInfo = db.prepare('PRAGMA table_info(evidences);').all() as Array<{ name: string; notnull: number }>;
      const evAlertId = evInfo.find((c) => c.name === 'alert_id');
      if (evAlertId && evAlertId.notnull === 1) {
        db.exec(`
          CREATE TABLE IF NOT EXISTS evidences_p4 (
            id TEXT PRIMARY KEY,
            alert_id TEXT,
            event_id TEXT,
            detection_hit_id TEXT,
            hypothesis_id TEXT,
            evidence_type TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_ref TEXT NOT NULL,
            evidence_role TEXT NOT NULL DEFAULT 'SUPPORTING',
            description TEXT NOT NULL,
            extracted_value TEXT NOT NULL DEFAULT '{}',
            relevance TEXT NOT NULL DEFAULT 'HIGH',
            timestamp TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
            FOREIGN KEY (event_id) REFERENCES normalized_events(id) ON DELETE SET NULL,
            FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
            FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
          );
          INSERT INTO evidences_p4 (id, alert_id, event_id, evidence_type, description, extracted_value, relevance, created_at)
          SELECT id, alert_id, event_id, evidence_type, description, extracted_value, relevance, created_at FROM evidences;
          DROP TABLE evidences;
          ALTER TABLE evidences_p4 RENAME TO evidences;
        `);
      } else {
        const evCols = new Set(evInfo.map((c) => c.name));
        const evNewCols: Array<{ name: string; type: string }> = [
          { name: 'detection_hit_id', type: 'TEXT' },
          { name: 'hypothesis_id', type: 'TEXT' },
          { name: 'source_type', type: "TEXT NOT NULL DEFAULT 'normalized_event'" },
          { name: 'source_ref', type: "TEXT NOT NULL DEFAULT 'unknown'" },
          { name: 'evidence_role', type: "TEXT NOT NULL DEFAULT 'SUPPORTING'" },
          { name: 'timestamp', type: 'TEXT' },
          { name: 'created_by', type: 'TEXT' },
        ];
        for (const col of evNewCols) {
          if (!evCols.has(col.name)) {
            db.exec(`ALTER TABLE evidences ADD COLUMN ${col.name} ${col.type};`);
          }
        }
      }
    }

    // Phase 4 Hypotheses Model Schema Migration
    const hypothesesCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='hypotheses';").all();
    if (hypothesesCheck.length > 0) {
      const hypInfo = db.prepare('PRAGMA table_info(hypotheses);').all() as Array<{ name: string; notnull: number }>;
      const hypAlertId = hypInfo.find((c) => c.name === 'alert_id');
      if (hypAlertId && hypAlertId.notnull === 1) {
        db.exec(`
          CREATE TABLE IF NOT EXISTS hypotheses_p4 (
            id TEXT PRIMARY KEY,
            alert_id TEXT,
            incident_id TEXT,
            title TEXT NOT NULL DEFAULT '',
            statement TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            resolution_reason TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
          );
          INSERT INTO hypotheses_p4 (id, alert_id, statement, status, created_at, updated_at)
          SELECT id, alert_id, statement, status, created_at, created_at FROM hypotheses;
          DROP TABLE hypotheses;
          ALTER TABLE hypotheses_p4 RENAME TO hypotheses;
        `);
      } else {
        const hypCols = new Set(hypInfo.map((c) => c.name));
        const hypNewCols: Array<{ name: string; type: string }> = [
          { name: 'incident_id', type: 'TEXT' },
          { name: 'title', type: "TEXT NOT NULL DEFAULT ''" },
          { name: 'resolution_reason', type: 'TEXT' },
          { name: 'created_by', type: 'TEXT' },
          { name: 'updated_at', type: "TEXT NOT NULL DEFAULT ''" },
        ];
        for (const col of hypNewCols) {
          if (!hypCols.has(col.name)) {
            db.exec(`ALTER TABLE hypotheses ADD COLUMN ${col.name} ${col.type};`);
          }
        }
      }
    }

    // Phase 4 Hypothesis Evidence Junction Table
    db.exec(`
      CREATE TABLE IF NOT EXISTS hypothesis_evidence (
        hypothesis_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_role TEXT NOT NULL DEFAULT 'SUPPORTING',
        added_by TEXT,
        added_at TEXT NOT NULL,
        PRIMARY KEY (hypothesis_id, evidence_id),
        FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_hyp_ev_hyp ON hypothesis_evidence(hypothesis_id);
      CREATE INDEX IF NOT EXISTS idx_hyp_ev_ev ON hypothesis_evidence(evidence_id);
    `);

    // Phase 4 Analyst Notes Migration
    const notesCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='analyst_notes';").all();
    if (notesCheck.length > 0) {
      const noteInfo = db.prepare('PRAGMA table_info(analyst_notes);').all() as Array<{ name: string; notnull: number }>;
      const noteIncidentId = noteInfo.find((c) => c.name === 'incident_id');
      if (noteIncidentId && noteIncidentId.notnull === 1) {
        db.exec(`
          CREATE TABLE IF NOT EXISTS analyst_notes_p4 (
            id TEXT PRIMARY KEY,
            incident_id TEXT,
            alert_id TEXT,
            hypothesis_id TEXT,
            evidence_id TEXT,
            detection_hit_id TEXT,
            note_type TEXT NOT NULL DEFAULT 'INVESTIGATION',
            author TEXT NOT NULL,
            user_id TEXT,
            note_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
            FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL,
            FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE SET NULL,
            FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
          );
          INSERT INTO analyst_notes_p4 (id, incident_id, author, note_text, created_at)
          SELECT id, incident_id, author, note_text, created_at FROM analyst_notes;
          DROP TABLE analyst_notes;
          ALTER TABLE analyst_notes_p4 RENAME TO analyst_notes;
        `);
      } else {
        const noteCols = new Set(noteInfo.map((c) => c.name));
        const noteNewCols: Array<{ name: string; type: string }> = [
          { name: 'alert_id', type: 'TEXT' },
          { name: 'hypothesis_id', type: 'TEXT' },
          { name: 'evidence_id', type: 'TEXT' },
          { name: 'detection_hit_id', type: 'TEXT' },
          { name: 'note_type', type: "TEXT NOT NULL DEFAULT 'INVESTIGATION'" },
          { name: 'user_id', type: 'TEXT' },
        ];
        for (const col of noteNewCols) {
          if (!noteCols.has(col.name)) {
            db.exec(`ALTER TABLE analyst_notes ADD COLUMN ${col.name} ${col.type};`);
          }
        }
      }
    }

    // Phase 5 Alerts Model Schema Migration
    const alertsCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';").all();
    if (alertsCheck.length > 0) {
      const alertInfo = db.prepare('PRAGMA table_info(alerts);').all() as Array<{ name: string; notnull: number }>;
      const alertCols = new Set(alertInfo.map((c) => c.name));
      const alertNewCols: Array<{ name: string; type: string }> = [
        { name: 'assessment_id', type: 'TEXT' },
        { name: 'hypothesis_id', type: 'TEXT' },
        { name: 'detection_hit_id', type: 'TEXT' },
        { name: 'summary', type: "TEXT NOT NULL DEFAULT ''" },
        { name: 'analyst_rationale', type: "TEXT NOT NULL DEFAULT ''" },
        { name: 'created_by', type: 'TEXT' },
        { name: 'updated_at', type: "TEXT NOT NULL DEFAULT ''" },
      ];
      for (const col of alertNewCols) {
        if (!alertCols.has(col.name)) {
          db.exec(`ALTER TABLE alerts ADD COLUMN ${col.name} ${col.type};`);
          logger.info('Database', `Migrated column alerts.${col.name}`);
        }
      }
      // Populate updated_at if empty
      db.exec(`UPDATE alerts SET updated_at = created_at WHERE updated_at = '' OR updated_at IS NULL;`);
    }

    // Phase 5 Analyst Assessments Table Migration
    db.exec(`
      CREATE TABLE IF NOT EXISTS analyst_assessments (
        id TEXT PRIMARY KEY,
        hypothesis_id TEXT NOT NULL,
        status TEXT NOT NULL,
        analyst_conclusion TEXT NOT NULL,
        rationale TEXT NOT NULL,
        relevant_evidence_ids TEXT NOT NULL DEFAULT '[]',
        analyst_notes TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_assessments_hypothesis ON analyst_assessments(hypothesis_id);
      CREATE INDEX IF NOT EXISTS idx_assessments_status ON analyst_assessments(status);
      CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON analyst_assessments(created_at);
    `);

    // Phase 5 Alert Status History Table Migration
    db.exec(`
      CREATE TABLE IF NOT EXISTS alert_status_history (
        id TEXT PRIMARY KEY,
        alert_id TEXT NOT NULL,
        previous_status TEXT NOT NULL,
        new_status TEXT NOT NULL,
        changed_by TEXT,
        rationale TEXT,
        changed_at TEXT NOT NULL,
        FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
        FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON alert_status_history(alert_id);
      CREATE INDEX IF NOT EXISTS idx_alert_history_changed_at ON alert_status_history(changed_at);
      CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
      CREATE INDEX IF NOT EXISTS idx_alerts_hypothesis_id ON alerts(hypothesis_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_assessment_id ON alerts(assessment_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_detection_hit_id ON alerts(detection_hit_id);
    `);

    // Ensure Phase 4 indices exist
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_evidences_event ON evidences(event_id);
      CREATE INDEX IF NOT EXISTS idx_evidences_detection_hit ON evidences(detection_hit_id);
      CREATE INDEX IF NOT EXISTS idx_evidences_hypothesis ON evidences(hypothesis_id);
      CREATE INDEX IF NOT EXISTS idx_evidences_role ON evidences(evidence_role);
      CREATE INDEX IF NOT EXISTS idx_evidences_created_at ON evidences(created_at);
      CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);
      CREATE INDEX IF NOT EXISTS idx_hypotheses_created_at ON hypotheses(created_at);
      CREATE INDEX IF NOT EXISTS idx_notes_hypothesis ON analyst_notes(hypothesis_id);
      CREATE INDEX IF NOT EXISTS idx_notes_evidence ON analyst_notes(evidence_id);
      CREATE INDEX IF NOT EXISTS idx_notes_detection_hit ON analyst_notes(detection_hit_id);
      CREATE INDEX IF NOT EXISTS idx_notes_created_at ON analyst_notes(created_at);
    `);

    // Phase 6 Threat Intelligence & Contextual Enrichment Migration
    db.exec(`
      CREATE TABLE IF NOT EXISTS threat_intelligence_records (
        id TEXT PRIMARY KEY,
        observable_value TEXT NOT NULL UNIQUE,
        observable_type TEXT NOT NULL,
        source TEXT NOT NULL,
        source_reference TEXT,
        category TEXT NOT NULL,
        description TEXT,
        first_seen TEXT,
        last_seen TEXT,
        confidence REAL,
        lifecycle_status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        created_by TEXT,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ti_observable_value ON threat_intelligence_records(observable_value);
      CREATE INDEX IF NOT EXISTS idx_ti_observable_type ON threat_intelligence_records(observable_type);
      CREATE INDEX IF NOT EXISTS idx_ti_lifecycle_status ON threat_intelligence_records(lifecycle_status);
      CREATE INDEX IF NOT EXISTS idx_ti_category ON threat_intelligence_records(category);
      CREATE INDEX IF NOT EXISTS idx_ti_source ON threat_intelligence_records(source);

      CREATE TABLE IF NOT EXISTS observable_enrichments (
        id TEXT PRIMARY KEY,
        intelligence_id TEXT NOT NULL,
        observable_value TEXT NOT NULL,
        observable_type TEXT NOT NULL,
        matched_field TEXT NOT NULL,
        source TEXT NOT NULL,
        source_reference TEXT,
        event_id TEXT,
        detection_hit_id TEXT,
        evidence_id TEXT,
        alert_id TEXT,
        context_description TEXT NOT NULL,
        enriched_at TEXT NOT NULL,
        FOREIGN KEY (intelligence_id) REFERENCES threat_intelligence_records(id) ON DELETE RESTRICT,
        FOREIGN KEY (event_id) REFERENCES normalized_events(id) ON DELETE CASCADE,
        FOREIGN KEY (detection_hit_id) REFERENCES detection_hits(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_id) REFERENCES evidences(id) ON DELETE SET NULL,
        FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_enrichment_intel ON observable_enrichments(intelligence_id);
      CREATE INDEX IF NOT EXISTS idx_enrichment_value ON observable_enrichments(observable_value);
      CREATE INDEX IF NOT EXISTS idx_enrichment_type ON observable_enrichments(observable_type);
      CREATE INDEX IF NOT EXISTS idx_enrichment_event ON observable_enrichments(event_id);
      CREATE INDEX IF NOT EXISTS idx_enrichment_hit ON observable_enrichments(detection_hit_id);
      CREATE INDEX IF NOT EXISTS idx_enrichment_evidence ON observable_enrichments(evidence_id);
      CREATE INDEX IF NOT EXISTS idx_enrichment_alert ON observable_enrichments(alert_id);
      CREATE INDEX IF NOT EXISTS idx_enrichment_time ON observable_enrichments(enriched_at);
    `);

    // Phase 7 Activity Graph & Evidence Correlation Schema Migration
    const nodesCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_graph_nodes';").all();
    if (nodesCheck.length > 0) {
      const nodeCols = (db.prepare('PRAGMA table_info(activity_graph_nodes);').all() as Array<{ name: string; pk: number }>);
      const colNames = nodeCols.map((c) => c.name);
      const scopeCol = nodeCols.find((c) => c.name === 'scope_id');
      if (!colNames.includes('scope_id') || !colNames.includes('source_type') || !scopeCol || scopeCol.pk === 0) {
        db.exec(`
          DROP TABLE IF EXISTS activity_graph_edges;
          DROP TABLE IF EXISTS activity_graph_nodes;
        `);
      }
    }

    db.exec(`
      CREATE TABLE IF NOT EXISTS activity_graph_nodes (
        id TEXT NOT NULL,
        scope_id TEXT NOT NULL DEFAULT 'global',
        incident_id TEXT,
        node_type TEXT NOT NULL,
        node_label TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_id TEXT NOT NULL,
        properties TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (id, scope_id),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_graph_nodes_incident ON activity_graph_nodes(incident_id);
      CREATE INDEX IF NOT EXISTS idx_graph_nodes_scope ON activity_graph_nodes(scope_id);
      CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON activity_graph_nodes(node_type);
      CREATE INDEX IF NOT EXISTS idx_graph_nodes_source ON activity_graph_nodes(source_type, source_id);

      CREATE TABLE IF NOT EXISTS activity_graph_edges (
        id TEXT NOT NULL,
        scope_id TEXT NOT NULL DEFAULT 'global',
        incident_id TEXT,
        source_node_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        relation_label TEXT NOT NULL,
        correlation_rule TEXT NOT NULL,
        correlation_reason TEXT NOT NULL,
        source_type TEXT,
        source_id TEXT,
        properties TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (id, scope_id),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_graph_edges_incident ON activity_graph_edges(incident_id);
      CREATE INDEX IF NOT EXISTS idx_graph_edges_scope ON activity_graph_edges(scope_id);
      CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON activity_graph_edges(source_node_id);
      CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON activity_graph_edges(target_node_id);
      CREATE INDEX IF NOT EXISTS idx_graph_edges_relation ON activity_graph_edges(relation_label);
      CREATE INDEX IF NOT EXISTS idx_graph_edges_rule ON activity_graph_edges(correlation_rule);
    `);

    // Phase 8 Grounded AI Copilot & Analysis Schema Migration
    const aiCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_analyses';").all();
    if (aiCheck.length > 0) {
      const aiCols = db.prepare('PRAGMA table_info(ai_analyses);').all() as Array<{ name: string; notnull: number }>;
      const colNames = aiCols.map((c) => c.name);
      if (!colNames.includes('scope_type') || !colNames.includes('citations') || colNames.includes('incident_id')) {
        // Migrate or recreate ai_analyses table to Phase 8 standard
        db.exec(`
          DROP TABLE IF EXISTS ai_analyses;
          CREATE TABLE IF NOT EXISTS ai_analyses (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            scope_type TEXT NOT NULL,
            scope_id TEXT NOT NULL,
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            model TEXT NOT NULL,
            source_references TEXT NOT NULL DEFAULT '[]',
            evidence_references TEXT NOT NULL DEFAULT '[]',
            citations TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'COMPLETED',
            error_message TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
          );
          CREATE INDEX IF NOT EXISTS idx_ai_scope ON ai_analyses(scope_type, scope_id);
          CREATE INDEX IF NOT EXISTS idx_ai_user ON ai_analyses(user_id);
          CREATE INDEX IF NOT EXISTS idx_ai_created_at ON ai_analyses(created_at);
        `);
        logger.info('Database', 'Migrated ai_analyses table to Phase 8 Grounded Copilot schema');
      }
    } else {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ai_analyses (
          id TEXT PRIMARY KEY,
          user_id TEXT,
          scope_type TEXT NOT NULL,
          scope_id TEXT NOT NULL,
          prompt TEXT NOT NULL,
          response TEXT NOT NULL,
          model TEXT NOT NULL,
          source_references TEXT NOT NULL DEFAULT '[]',
          evidence_references TEXT NOT NULL DEFAULT '[]',
          citations TEXT NOT NULL DEFAULT '[]',
          status TEXT NOT NULL DEFAULT 'COMPLETED',
          error_message TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ai_scope ON ai_analyses(scope_type, scope_id);
        CREATE INDEX IF NOT EXISTS idx_ai_user ON ai_analyses(user_id);
        CREATE INDEX IF NOT EXISTS idx_ai_created_at ON ai_analyses(created_at);
      `);
    }
  } catch (err) {
    logger.warn('Database', 'Column migration check completed or non-critical notice', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

export interface DatabaseStats {
  status: 'connected' | 'disconnected';
  path: string;
  journalMode: string;
  tableCounts: Record<string, number>;
}

export function getDatabaseStats(): DatabaseStats {
  const db = getDatabase();
  const tables = [
    'users',
    'sessions',
    'normalized_events',
    'detection_hits',
    'alerts',
    'evidences',
    'hypotheses',
    'incidents',
    'analyst_notes',
    'ai_analyses',
    'activity_graph_nodes',
    'activity_graph_edges',
    'local_iocs',
    'suppression_rules',
    'hypothesis_evidence',
    'analyst_assessments',
    'alert_status_history',
    'threat_intelligence_records',
    'observable_enrichments',
  ];

  const tableCounts: Record<string, number> = {};

  try {
    const journalModeResult = db.prepare('PRAGMA journal_mode;').all() as Array<Record<string, unknown>>;
    const journalMode = (journalModeResult[0]?.journal_mode as string) || 'unknown';

    for (const table of tables) {
      try {
        const result = db.prepare(`SELECT COUNT(*) as count FROM ${table}`).all() as Array<{ count: number }>;
        tableCounts[table] = Number(result[0]?.count ?? 0);
      } catch {
        tableCounts[table] = 0;
      }
    }

    return {
      status: 'connected',
      path: config.dbPath,
      journalMode,
      tableCounts,
    };
  } catch (error) {
    logger.error('Database', 'Failed to gather database statistics', {
      error: error instanceof Error ? error.message : String(error),
    });
    return {
      status: 'disconnected',
      path: config.dbPath,
      journalMode: 'unknown',
      tableCounts,
    };
  }
}
