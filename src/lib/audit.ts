import type { Request, Response, NextFunction } from "express";
import Database from "better-sqlite3";

// Ensure the audit table exists (idempotent)
export function ensureAuditTable(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      user_id TEXT,
      ip TEXT NOT NULL,
      route TEXT NOT NULL,
      payload_bytes INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS audit_logs_ts ON audit_logs(ts);
    CREATE INDEX IF NOT EXISTS audit_logs_route ON audit_logs(route);
  `);
}

const INSERT_SQL = `
  INSERT INTO audit_logs (ts, user_id, ip, route, payload_bytes)
  VALUES (@ts, @user_id, @ip, @route, @payload_bytes)
`;

export function makeAuditMiddleware(db: Database.Database) {
  const insert = db.prepare(INSERT_SQL);

  return function audit(routeName: string) {
    return function (req: Request, _res: Response, next: NextFunction) {
      const contentLen = Number(req.headers["content-length"] || 0);
      let payload_bytes = Number.isFinite(contentLen) && contentLen > 0
        ? contentLen
        : (() => {
            try { return req.body ? Buffer.byteLength(JSON.stringify(req.body)) : 0; }
            catch { return 0; }
          })();

      const ip =
        (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
        req.ip || "unknown";

      const user_id =
        (req as any).session?.userId ||
        (req as any).user?.id ||
        null;

      try {
        insert.run({
          ts: Date.now(),
          user_id,
          ip,
          route: routeName,
          payload_bytes,
        });
      } catch {
        // best-effort: never block the request
      }
      next();
    };
  };
}
