import { Request, Response, NextFunction } from 'express';
import { validateSession, SafeUser } from './authService.ts';

declare global {
  namespace Express {
    interface Request {
      user?: SafeUser;
      sessionId?: string;
    }
  }
}

export function extractSessionToken(req: Request): string | null {
  // 1. Check HTTP-only cookie
  if (req.cookies && req.cookies.nethuntersoc_session) {
    return req.cookies.nethuntersoc_session;
  }

  // 2. Check Authorization: Bearer <token>
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }

  return null;
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = extractSessionToken(req);
  if (token) {
    const user = validateSession(token);
    if (user) {
      req.user = user;
      req.sessionId = token;
    }
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = extractSessionToken(req);
  if (!token) {
    res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Authentication required. Please sign in to access this resource.',
    });
    return;
  }

  const user = validateSession(token);
  if (!user) {
    res.status(401).json({
      error: 'SESSION_EXPIRED',
      message: 'Session has expired or is invalid. Please sign in again.',
    });
    return;
  }

  req.user = user;
  req.sessionId = token;
  next();
}
