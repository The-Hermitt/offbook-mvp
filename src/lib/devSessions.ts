export type DevSession = {
  regChallenge?: string;
  authChallenge?: string;
  userId?: string;
  credentialId?: string;
  loggedIn?: boolean;
  plan?: "none" | "dev";
  rendersUsed?: number;
  creditsAvailable?: number;
  periodStart?: string;
  periodEnd?: string;
};

export const devSessions = new Map<string, DevSession>();
