import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import { config } from './server/config.ts';
import { logger } from './server/logger.ts';
import { getDatabase } from './server/db/database.ts';
import { apiRouter } from './server/routes/api.ts';

async function startServer(): Promise<void> {
  const app = express();
  const PORT = config.port;

  // Initialize SQLite database and schema
  try {
    logger.info('Server', 'Bootstrapping SQLite storage layer...');
    getDatabase();
    logger.info('Server', 'Storage layer initialized successfully');
  } catch (error) {
    logger.error('Server', 'Fatal error during database bootstrapping', {
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }

  // Middleware
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));
  app.use(cookieParser());

  // Mount API routes FIRST
  app.use('/api', apiRouter);

  // Vite middleware setup
  if (process.env.NODE_ENV !== 'production') {
    logger.info('Server', 'Attaching Vite development middleware...');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    logger.info('Server', `Serving production static assets from ${distPath}`);
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    logger.info('Server', `NetHunterSOC server active on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  logger.error('Server', 'Unhandled bootstrap failure', {
    error: err instanceof Error ? err.message : String(err),
  });
});
