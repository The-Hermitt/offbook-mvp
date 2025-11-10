import type { Request, Response, NextFunction } from "express";

type Key = string;
type Bucket = { count: number; resetAt: number };

function readLimit(val: any, fallback: number) {
  const s = (val ?? "").toString().trim();
  const n = Number(s);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function keyFor(req: Request) {
  const userId = (req as any).session?.userId || (req as any).user?.id || "";
  const ip =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
    req.ip ||
    "unknown";
  return userId ? `u:${userId}` : `ip:${ip}`;
}

export function makeRateLimiters(opts?: {
  rendersPerHour?: number;
  debugReqsPerMin?: number;
}) {
  const rendersPerHour =
    opts?.rendersPerHour ?? readLimit(process.env.RATE_LIMIT_RENDERS_PER_HOUR, 20);
  const debugPerMin =
    opts?.debugReqsPerMin ?? readLimit(process.env.RATE_LIMIT_DEBUG_PER_MIN, 120);

  const renderMap = new Map<Key, Bucket>();
  const debugMap = new Map<Key, Bucket>();

  function take(map: Map<Key, Bucket>, key: Key, limit: number, windowMs: number) {
    const now = Date.now();
    let b = map.get(key);
    if (!b || b.resetAt <= now) {
      b = { count: 0, resetAt: now + windowMs };
      map.set(key, b);
    }
    b.count++;
    const remaining = Math.max(0, limit - b.count);
    return { allowed: b.count <= limit, resetMs: Math.max(0, b.resetAt - now), remaining };
  }

  const debugLimiter = (req: Request, res: Response, next: NextFunction) => {
    const key = keyFor(req);
    const { allowed, resetMs, remaining } = take(debugMap, key, debugPerMin, 60_000);
    if (!allowed) {
      return res.status(429).json({
        error: "Too many requests",
        detail: "Please wait a moment and try again.",
        resetMs,
        remaining: 0,
      });
    }
    res.setHeader("X-RateLimit-Remaining", String(remaining));
    next();
  };

  const renderLimiter = (req: Request, res: Response, next: NextFunction) => {
    const key = keyFor(req);
    const { allowed, resetMs, remaining } = take(renderMap, key, rendersPerHour, 3_600_000);
    if (!allowed) {
      return res.status(429).json({
        error: "Render limit reached",
        detail: "You’ve hit the hourly render cap. Try again later.",
        resetMs,
        remaining: 0,
      });
    }
    res.setHeader("X-RenderLimit-Remaining", String(remaining));
    next();
  };

  return { debugLimiter, renderLimiter };
}
