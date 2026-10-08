import crypto from 'node:crypto';
import { getDatabase } from '../db/database.ts';
import { logger } from '../logger.ts';

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export type SafeUser = Omit<UserRecord, 'password_hash'>;

// Standard cryptographic password hashing using scrypt with random salt
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;
    const [salt, key] = parts;
    const keyBuffer = Buffer.from(key, 'hex');
    const derivedKey = crypto.scryptSync(password, salt, 64);
    if (keyBuffer.length !== derivedKey.length) return false;
    return crypto.timingSafeEqual(keyBuffer, derivedKey);
  } catch (error) {
    logger.error('AuthService', 'Error during password verification', {
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
}

export function validateUsername(username: string): boolean {
  const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
  return usernameRegex.test(username.trim());
}

export function validatePassword(password: string): boolean {
  return typeof password === 'string' && password.length >= 8;
}

export function createUser(username: string, email: string, password: string, role: string = 'analyst'): SafeUser {
  const db = getDatabase();
  const cleanUsername = username.trim();
  const cleanEmail = email.trim().toLowerCase();

  // Check duplicate username or email
  const existing = db.prepare(
    'SELECT id, username, email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)'
  ).all(cleanUsername, cleanEmail) as Array<{ id: string; username: string; email: string }>;

  if (existing.length > 0) {
    const isUsername = existing.some((u) => u.username.toLowerCase() === cleanUsername.toLowerCase());
    const isEmail = existing.some((u) => u.email.toLowerCase() === cleanEmail.toLowerCase());
    if (isUsername && isEmail) {
      throw new Error('DUPLICATE_USER_EMAIL');
    } else if (isUsername) {
      throw new Error('DUPLICATE_USERNAME');
    } else {
      throw new Error('DUPLICATE_EMAIL');
    }
  }

  const userId = `usr_${crypto.randomUUID()}`;
  const passwordHash = hashPassword(password);
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at, last_login_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(userId, cleanUsername, cleanEmail, passwordHash, role, now, now, null);

  logger.info('AuthService', `New user registered: ${cleanUsername} (${cleanEmail})`, { userId, role });

  return {
    id: userId,
    username: cleanUsername,
    email: cleanEmail,
    role,
    created_at: now,
    updated_at: now,
    last_login_at: null,
  };
}

export function authenticateUser(identifier: string, password: string): SafeUser {
  const db = getDatabase();
  const cleanIdentifier = identifier.trim().toLowerCase();

  const user = db.prepare(
    'SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?'
  ).get(cleanIdentifier, cleanIdentifier) as UserRecord | undefined;

  if (!user) {
    throw new Error('INVALID_CREDENTIALS');
  }

  const isValid = verifyPassword(password, user.password_hash);
  if (!isValid) {
    throw new Error('INVALID_CREDENTIALS');
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now, user.id);

  logger.info('AuthService', `User authenticated successfully: ${user.username}`, { userId: user.id });

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
    updated_at: user.updated_at,
    last_login_at: now,
  };
}

export function createSession(userId: string): { sessionId: string; expiresAt: string } {
  const db = getDatabase();
  const sessionId = `ses_${crypto.randomBytes(32).toString('hex')}`;
  // 7 days expiration
  const expiresDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const expiresAt = expiresDate.toISOString();
  const now = new Date().toISOString();

  db.prepare(
    'INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).run(sessionId, userId, now, expiresAt);

  return { sessionId, expiresAt };
}

export function validateSession(sessionId: string): SafeUser | null {
  if (!sessionId) return null;
  const db = getDatabase();
  const now = new Date().toISOString();

  const sessionRecord = db.prepare(`
    SELECT s.id as session_id, s.expires_at, u.id, u.username, u.email, u.role, u.created_at, u.updated_at, u.last_login_at
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = ? AND s.expires_at > ?
  `).get(sessionId, now) as (SafeUser & { session_id: string; expires_at: string }) | undefined;

  if (!sessionRecord) {
    return null;
  }

  return {
    id: sessionRecord.id,
    username: sessionRecord.username,
    email: sessionRecord.email,
    role: sessionRecord.role,
    created_at: sessionRecord.created_at,
    updated_at: sessionRecord.updated_at,
    last_login_at: sessionRecord.last_login_at,
  };
}

export function deleteSession(sessionId: string): void {
  if (!sessionId) return;
  const db = getDatabase();
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}
