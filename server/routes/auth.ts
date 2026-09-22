import { Router, Request, Response } from 'express';
import {
  createUser,
  authenticateUser,
  createSession,
  deleteSession,
  validateEmail,
  validateUsername,
  validatePassword,
} from '../auth/authService.ts';
import { requireAuth, extractSessionToken } from '../auth/authMiddleware.ts';
import { logger } from '../logger.ts';

export const authRouter = Router();

// 1. Sign Up
authRouter.post('/signup', (req: Request, res: Response) => {
  try {
    const { username, email, password, role } = req.body || {};

    if (!username || !validateUsername(username)) {
      res.status(400).json({
        error: 'INVALID_USERNAME',
        message: 'Username must be between 3 and 30 alphanumeric characters or underscores.',
      });
      return;
    }

    if (!email || !validateEmail(email)) {
      res.status(400).json({
        error: 'INVALID_EMAIL',
        message: 'A valid email address is required.',
      });
      return;
    }

    if (!password || !validatePassword(password)) {
      res.status(400).json({
        error: 'WEAK_PASSWORD',
        message: 'Password must be at least 8 characters long.',
      });
      return;
    }

    const assignedRole = role === 'admin' ? 'admin' : 'analyst';
    const user = createUser(username, email, password, assignedRole);
    const { sessionId, expiresAt } = createSession(user.id);

    // Set HTTP-only session cookie
    res.cookie('nethuntersoc_session', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      user,
      token: sessionId,
      expiresAt,
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg === 'DUPLICATE_USERNAME') {
      res.status(409).json({
        error: 'DUPLICATE_USERNAME',
        message: 'This username is already taken. Please choose another.',
      });
      return;
    }
    if (msg === 'DUPLICATE_EMAIL') {
      res.status(409).json({
        error: 'DUPLICATE_EMAIL',
        message: 'An account with this email already exists.',
      });
      return;
    }
    if (msg === 'DUPLICATE_USER_EMAIL') {
      res.status(409).json({
        error: 'DUPLICATE_USER_EMAIL',
        message: 'Username and email are already registered.',
      });
      return;
    }

    logger.error('AuthRoute', 'Signup failed with internal error', { error: msg });
    res.status(500).json({
      error: 'SERVER_ERROR',
      message: 'Failed to complete registration. Please try again.',
    });
  }
});

// 2. Sign In
authRouter.post('/signin', (req: Request, res: Response) => {
  try {
    const { identifier, password } = req.body || {};

    if (!identifier || !password) {
      res.status(400).json({
        error: 'MISSING_FIELDS',
        message: 'Username/email and password are required.',
      });
      return;
    }

    const user = authenticateUser(identifier, password);
    const { sessionId, expiresAt } = createSession(user.id);

    res.cookie('nethuntersoc_session', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    res.json({
      success: true,
      message: 'Signed in successfully',
      user,
      token: sessionId,
      expiresAt,
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg === 'INVALID_CREDENTIALS') {
      // Generic error to prevent enumeration
      res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid username/email or password.',
      });
      return;
    }

    logger.error('AuthRoute', 'Signin error', { error: msg });
    res.status(500).json({
      error: 'SERVER_ERROR',
      message: 'Authentication failed due to an unexpected server error.',
    });
  }
});

// 3. Sign Out
authRouter.post('/signout', (req: Request, res: Response) => {
  try {
    const token = extractSessionToken(req);
    if (token) {
      deleteSession(token);
    }

    res.clearCookie('nethuntersoc_session', { path: '/' });
    res.json({
      success: true,
      message: 'Signed out successfully',
    });
  } catch (error) {
    logger.error('AuthRoute', 'Signout error', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.clearCookie('nethuntersoc_session', { path: '/' });
    res.json({
      success: true,
      message: 'Signed out successfully',
    });
  }
});

// 4. Current User Verification (/api/auth/me)
authRouter.get('/me', requireAuth, (req: Request, res: Response) => {
  res.json({
    authenticated: true,
    user: req.user,
  });
});
