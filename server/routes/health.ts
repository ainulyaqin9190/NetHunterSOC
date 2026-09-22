import { Router, Request, Response } from 'express';
import { getDatabaseStats } from '../db/database.ts';
import { logger } from '../logger.ts';

export const healthRouter = Router();

healthRouter.get('/health', (req: Request, res: Response) => {
  try {
    const dbStats = getDatabaseStats();
    const uptimeSeconds = process.uptime();

    const responsePayload = {
      status: dbStats.status === 'connected' ? 'healthy' : 'degraded',
      service: 'NetHunterSOC',
      version: '1.0.0-mvp.phase1',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(uptimeSeconds),
      database: dbStats,
      environment: process.env.NODE_ENV || 'development',
    };

    logger.debug('HealthCheck', 'Health endpoint queried', { status: responsePayload.status });
    res.json(responsePayload);
  } catch (error) {
    logger.error('HealthCheck', 'Error processing health check', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({
      status: 'error',
      service: 'NetHunterSOC',
      message: 'Internal error during health check evaluation',
    });
  }
});
