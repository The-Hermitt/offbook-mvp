import type { Request, Response, NextFunction } from "express";
import { dbRun } from "./db";

export function makeAuditMiddleware() {
  return function audit(routeName: string) {
    return function (req: Request, _res: Response, next: NextFunction) {
      const contentLen = Number(req.headers["content-length"] || 0);
      const payload_bytes = Number.isFinite(contentLen) && contentLen > 0
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

      // best-effort, never block request
      void dbRun(
        "INSERT INTO audit_logs (ts, user_id, ip, route, payload_bytes) VALUES (?, ?, ?, ?, ?)",
        [Date.now(), user_id, ip, routeName, payload_bytes]
      ).catch(() => {});

      next();
    };
  };
}
