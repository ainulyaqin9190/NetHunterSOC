import path from 'path';

export interface AppConfig {
  port: number;
  dataDir: string;
  dbPath: string;
  sessionSecret: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  env: string;
  demoAccountEnabled: boolean;
  demoPassword: string;
}

const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const dbPath = process.env.DB_PATH || path.join(dataDir, 'nethuntersoc.db');

export const config: AppConfig = {
  port: 3000,
  dataDir,
  dbPath,
  sessionSecret: process.env.SESSION_SECRET || 'nethuntersoc-dev-secret-key-32chars',
  logLevel: (process.env.LOG_LEVEL as AppConfig['logLevel']) || 'info',
  env: process.env.NODE_ENV || 'development',
  demoAccountEnabled: process.env.DEMO_ACCOUNT_ENABLED !== 'false',
  demoPassword: process.env.DEMO_PASSWORD || 'DemoHunter2026!',
};

