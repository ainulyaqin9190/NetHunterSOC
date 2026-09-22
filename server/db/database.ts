import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { config } from '../config.ts';
import { logger } from '../logger.ts';
import { hashPassword } from '../auth/authService.ts';

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
    // 1. Seed Demo Analyst Account if enabled
    if (config.demoAccountEnabled) {
      const existingUser = db.prepare(
        'SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?'
      ).get('demo', 'demo@nethuntersoc.local');

      if (!existingUser) {
        const passwordHash = hashPassword(config.demoPassword);
        const now = new Date().toISOString();
        const userId = 'usr_demo_analyst_seed';
        db.prepare(`
          INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at, last_login_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(userId, 'demo', 'demo@nethuntersoc.local', passwordHash, 'analyst', now, now, null);
        logger.info('Database', 'Seeded development demo account: demo (role: analyst)');
      }
    }

    // 2. Seed Default Local IOCs if table is empty
    const iocCountRow = db.prepare('SELECT COUNT(*) as count FROM local_iocs').get() as { count: number } | undefined;
    if (iocCountRow && Number(iocCountRow.count) === 0) {
      const seedIocs = [
        { id: 'ioc_01', val: '198.51.100.45', type: 'IP', cat: 'C2_INFRASTRUCTURE', desc: 'Known Cobalt Strike / C2 beacon endpoint' },
        { id: 'ioc_02', val: '203.0.113.88', type: 'IP', cat: 'BOTNET_CONTROLLER', desc: 'Observed botnet rendezvous node' },
        { id: 'ioc_03', val: 'c2-malicious-traffic.com', type: 'DOMAIN', cat: 'MALICIOUS_DOMAIN', desc: 'Associated with malware exfiltration' },
        { id: 'ioc_04', val: 'evil-telemetry-drop.net', type: 'DOMAIN', cat: 'PHISHING_DROP', desc: 'Active phishing payload domain' },
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
