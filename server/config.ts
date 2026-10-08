import path from 'path';

export interface AppConfig {
  port: number;
  dataDir: string;
  dbPath: string;
  sessionSecret: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  env: string;
  demoEnabled: boolean;
  demoUsername: string;
  demoPassword?: string;
}

const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const dbPath = process.env.DB_PATH || path.join(dataDir, 'nethuntersoc.db');
const env = process.env.NODE_ENV || 'development';
const isDev = env !== 'production';

// Demo account security: only enabled if explicitly configured or running in development
// In production, DEMO_ENABLED must be explicitly "true" and must have a valid DEMO_PASSWORD set
const demoEnabled = process.env.DEMO_ENABLED === 'true' || (isDev && process.env.DEMO_ENABLED !== 'false' && process.env.DEMO_ACCOUNT_ENABLED !== 'false');
const demoUsername = process.env.DEMO_USERNAME || 'demo';
const demoPassword = process.env.DEMO_PASSWORD || undefined;

export const config: AppConfig = {
  port: 3000,
  dataDir,
  dbPath,
  sessionSecret: process.env.SESSION_SECRET || 'nethuntersoc-dev-secret-key-32chars',
  logLevel: (process.env.LOG_LEVEL as AppConfig['logLevel']) || 'info',
  env,
  demoEnabled,
  demoUsername,
  demoPassword,
};
