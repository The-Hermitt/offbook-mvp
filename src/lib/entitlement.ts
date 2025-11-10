import type { Request } from "express";
import { devSessions, type DevSession } from "./devSessions";

const INCLUDED_RENDERS_PER_MONTH = Number(process.env.INCLUDED_RENDERS_PER_MONTH || 0);

export type Entitlement = {
  plan: string;
  included_quota: number;
  renders_used: number;
  credits_available: number;
  period_start?: string | null;
  period_end?: string | null;
};

function sidFromRequest(req: Request): string | undefined {
  const cookies = (req as any).cookies as Record<string, unknown> | undefined;
  const fromParser = cookies?.["ob_sid"];
  if (typeof fromParser === "string" && fromParser.trim()) {
    return fromParser.trim();
  }

  const header = req.headers?.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [rawKey, ...rawVal] = part.trim().split("=");
    if (!rawKey) continue;
    if (rawKey === "ob_sid") {
      return decodeURIComponent(rawVal.join("="));
    }
  }
  return undefined;
}

function sessionFromRequest(req: Request): DevSession | undefined {
  const sid = sidFromRequest(req);
  if (!sid) return undefined;
  return devSessions.get(sid);
}

export function buildEntitlementFor(req: Request, override?: DevSession | null): Entitlement {
  const sess = override ?? sessionFromRequest(req);
  return {
    plan: sess?.plan || "none",
    included_quota: INCLUDED_RENDERS_PER_MONTH,
    renders_used: Number(sess?.rendersUsed ?? 0),
    credits_available: Number(sess?.creditsAvailable ?? 0),
    period_start: sess?.periodStart || null,
    period_end: sess?.periodEnd || null,
  };
}
