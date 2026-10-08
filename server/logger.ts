export interface LogEntry {
  timestamp: string;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
  module: string;
  message: string;
  metadata?: Record<string, unknown>;
}

class Logger {
  private format(level: LogEntry['level'], module: string, message: string, metadata?: Record<string, unknown>): string {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      module,
      message,
      ...(metadata ? { metadata } : {}),
    };
    return JSON.stringify(entry);
  }

  debug(module: string, message: string, metadata?: Record<string, unknown>): void {
    if (process.env.LOG_LEVEL === 'debug') {
      console.debug(this.format('DEBUG', module, message, metadata));
    }
  }

  info(module: string, message: string, metadata?: Record<string, unknown>): void {
    console.log(this.format('INFO', module, message, metadata));
  }

  warn(module: string, message: string, metadata?: Record<string, unknown>): void {
    console.warn(this.format('WARN', module, message, metadata));
  }

  error(module: string, message: string, metadata?: Record<string, unknown>): void {
    console.error(this.format('ERROR', module, message, metadata));
  }
}

export const logger = new Logger();
