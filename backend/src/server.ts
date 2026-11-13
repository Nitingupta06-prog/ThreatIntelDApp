import "dotenv/config";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import express from "express";
import {
  MongoNetworkError,
  MongoParseError,
  MongoServerError,
  MongoServerSelectionError,
  ObjectId,
  type Collection,
} from "mongodb";
import { connectDatabase, MissingMongoUriError } from "./config/database.js";

const threatTypes = [
  "Credential stuffing",
  "Authentication failures",
  "Port scanning",
  "Phishing infrastructure",
] as const;

type ThreatType = (typeof threatTypes)[number];
type ThreatReport = {
  ipAddress: string;
  threatType: ThreatType;
  summary: string;
  evidence?: string;
  submittedAt: Date;
  status: "pending_review";
};

type ThreatAlert = {
  ipAddress: string;
  ruleId: string;
  ruleName: string;
  status: "open";
  reportCount?: number;
  attemptCount?: number;
  restrictionLevel?: number;
  threshold: number;
  windowMinutes: number;
  windowStartedAt: Date;
  firstObservedAt: Date;
  lastObservedAt: Date;
  createdAt: Date;
  updatedAt: Date;
};

type DemoRestriction = {
  ipAddress: string;
  durationMinutes: 5 | 15 | 30;
  createdAt: Date;
  expiresAt: Date;
  status: "active" | "expired" | "revoked";
  alertId?: ObjectId;
  revokedAt?: Date;
  source?: "automatic_login_attempt" | "manual";
};

type LoginAttemptRecord = {
  username: string;
  ipAddress: string;
  attemptedAt: Date;
  success: boolean;
};

type LoginRestriction = {
  username: string;
  ipAddress: string;
  level: 1 | 2 | 3;
  status: "active" | "expired" | "revoked" | "locked";
  durationMinutes: number;
  createdAt: Date;
  expiresAt: Date | null;
  incidentHash: string;
  revokedAt?: Date;
};

// These are heuristics over submitted reports and failed demo logins,
// not live network traffic or real login detection beyond this app.
const REPORT_BURST_THRESHOLD = 3;
const REPORT_BURST_WINDOW_MINUTES = 10;
const REPORT_BURST_WINDOW_MS = REPORT_BURST_WINDOW_MINUTES * 60 * 1000;
const REPORT_BURST_RULE_ID = "same_ip_report_burst_10m_v1";

const LOGIN_FAILED_ATTEMPT_THRESHOLD = 4;
const LOGIN_ATTEMPT_WINDOW_MINUTES = 10;
const LOGIN_ATTEMPT_WINDOW_MS = LOGIN_ATTEMPT_WINDOW_MINUTES * 60 * 1000;
const LOGIN_RESTRICTION_RULE_ID = "failed_login_burst_10m_v1";
const LOGIN_RESTRICTION_DURATIONS: Record<1 | 2, number> = { 1: 30, 2: 48 * 60 };

const app = express();
const port = Number(process.env.PORT) || 3001;

const trustProxy = process.env.TRUST_PROXY?.trim();
if (trustProxy) {
  app.set("trust proxy", trustProxy === "true" ? true : /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);
}

let databaseConnection: Awaited<ReturnType<typeof connectDatabase>> | undefined;
let reportsCollection: Collection<ThreatReport> | undefined;
let alertsCollection: Collection<ThreatAlert> | undefined;
let demoRestrictionsCollection: Collection<DemoRestriction> | undefined;
let loginAttemptsCollection: Collection<LoginAttemptRecord> | undefined;
let loginRestrictionsCollection: Collection<LoginRestriction> | undefined;

app.use(express.json({ limit: "16kb" }));

app.use("/api", (request, response, next) => {
  const allowedOrigin = "http://localhost:3000";

  if (request.headers.origin === allowedOrigin) {
    response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    response.setHeader("Vary", "Origin");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
    response.setHeader("Access-Control-Allow-Credentials", "true");
  }

  if (request.method === "OPTIONS") {
    if (request.headers.origin !== allowedOrigin) {
      response.sendStatus(403);
      return;
    }

    response.sendStatus(204);
    return;
  }

  next();
});

function getConnectionFailureCategory(error: unknown): string {
  if (error instanceof MissingMongoUriError) {
    return "missing MONGODB_URI";
  }

  if (error instanceof MongoParseError) {
    return "invalid MongoDB URI format";
  }

  if (
    error instanceof MongoServerError &&
    (error.code === 18 ||
      error.codeName === "AuthenticationFailed" ||
      (error.code === 8000 && error.codeName === "AtlasError"))
  ) {
    return "authentication rejected";
  }

  if (error instanceof MongoServerSelectionError || error instanceof MongoNetworkError) {
    return "network/server-selection failure";
  }

  return "other MongoDB connection failure";
}

function getSafeErrorDetails(error: unknown): { errorName: string; code?: string } {
  const rawName = error instanceof Error ? error.name : "UnknownError";
  const errorName = /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(rawName)
    ? rawName
    : "UnknownError";

  const rawCode =
    typeof error === "object" && error !== null && "code" in error
      ? error.code
      : undefined;
  const codeValue =
    typeof rawCode === "string" || typeof rawCode === "number"
      ? String(rawCode)
      : undefined;
  const code = codeValue && /^[A-Z0-9_]{1,16}$/.test(codeValue) ? codeValue : undefined;

  return { errorName, ...(code ? { code } : {}) };
}

app.get("/health", (_request, response) => {
  response.json({ status: "ok" });
});

app.get("/api/reports", async (_request, response) => {
  if (!reportsCollection) {
    response.status(503).json({ error: "Report storage is unavailable." });
    return;
  }

  try {
    const [reports, total] = await Promise.all([
      reportsCollection.find({}).sort({ submittedAt: -1, _id: -1 }).limit(50).toArray(),
      reportsCollection.countDocuments({}),
    ]);
    response.json({ reports, total });
  } catch {
    response.status(500).json({ error: "Unable to retrieve threat reports." });
  }
});

app.get("/api/alerts", async (_request, response) => {
  if (!alertsCollection) {
    response.status(503).json({ error: "Alert storage is unavailable." });
    return;
  }

  try {
    const openFilter = { status: "open" as const };
    const [alerts, total] = await Promise.all([
      alertsCollection.find(openFilter).sort({ lastObservedAt: -1, _id: -1 }).limit(50).toArray(),
      alertsCollection.countDocuments(openFilter),
    ]);
    response.json({ alerts, total });
  } catch {
    response.status(500).json({ error: "Unable to retrieve alerts." });
  }
});

async function updateOpenBurstAlert(ipAddress: string, reportCount: number, observedAt: Date) {
  if (!alertsCollection) {
    throw new Error("Alert storage is unavailable.");
  }

  const filter = { ipAddress, ruleId: REPORT_BURST_RULE_ID, status: "open" as const };
  const windowStartedAt = new Date(observedAt.getTime() - REPORT_BURST_WINDOW_MS);
  const update = {
    $set: {
      reportCount,
      windowStartedAt,
      lastObservedAt: observedAt,
      updatedAt: observedAt,
    },
    $setOnInsert: {
      ruleName: "Same IP report burst",
      threshold: REPORT_BURST_THRESHOLD,
      windowMinutes: REPORT_BURST_WINDOW_MINUTES,
      firstObservedAt: observedAt,
      createdAt: observedAt,
    },
  };

  try {
    await alertsCollection.updateOne(filter, update, { upsert: true });
  } catch (error) {
    if (!(error instanceof MongoServerError) || error.code !== 11000) {
      throw error;
    }

    await alertsCollection.updateOne(filter, { $set: update.$set });
  }
}

app.post("/api/reports", async (request, response) => {
  if (!reportsCollection) {
    response.status(503).json({ error: "Report storage is unavailable." });
    return;
  }

  const body: unknown = request.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    response.status(400).json({ error: "Request body must be a JSON object." });
    return;
  }

  const data = body as Record<string, unknown>;
  if (typeof data.ipAddress !== "string" || isIP(data.ipAddress.trim()) === 0) {
    response.status(400).json({ error: "ipAddress must be a valid IPv4 or IPv6 address." });
    return;
  }

  if (
    typeof data.threatType !== "string" ||
    !threatTypes.some((threatType) => threatType === data.threatType)
  ) {
    response.status(400).json({
      error: `threatType must be one of: ${threatTypes.join(", ")}.`,
    });
    return;
  }

  if (typeof data.summary !== "string" || data.summary.trim().length === 0 || data.summary.length > 280) {
    response.status(400).json({ error: "summary must contain 1 to 280 characters." });
    return;
  }

  if (
    data.evidence !== undefined &&
    (typeof data.evidence !== "string" || data.evidence.length > 10_000)
  ) {
    response.status(400).json({ error: "evidence must be text no longer than 10000 characters." });
    return;
  }

  const report: ThreatReport = {
    ipAddress: data.ipAddress.trim(),
    threatType: data.threatType as ThreatType,
    summary: data.summary.trim(),
    ...(typeof data.evidence === "string" ? { evidence: data.evidence } : {}),
    submittedAt: new Date(),
    status: "pending_review",
  };

  try {
    const result = await reportsCollection.insertOne(report);
    const windowStart = new Date(report.submittedAt.getTime() - REPORT_BURST_WINDOW_MS);
    const reportCount = await reportsCollection.countDocuments({
      ipAddress: report.ipAddress,
      submittedAt: { $gte: windowStart, $lte: report.submittedAt },
    });

    if (reportCount >= REPORT_BURST_THRESHOLD) {
      await updateOpenBurstAlert(report.ipAddress, reportCount, report.submittedAt);
    }

    response.status(201).json({ report: { ...report, _id: result.insertedId } });
  } catch {
    response.status(500).json({ error: "Unable to save the threat report." });
  }
});

app.get("/api/demo-restrictions", async (_request, response) => {
  if (!demoRestrictionsCollection) {
    response.status(503).json({ error: "Demo restriction storage is unavailable." });
    return;
  }

  try {
    const now = new Date();
    await demoRestrictionsCollection.updateMany(
      { status: "active", expiresAt: { $lte: now } },
      { $set: { status: "expired" } },
    );
    const activeFilter = { status: "active" as const, expiresAt: { $gt: now } };
    const [restrictions, total] = await Promise.all([
      demoRestrictionsCollection.find(activeFilter).sort({ createdAt: -1, _id: -1 }).toArray(),
      demoRestrictionsCollection.countDocuments(activeFilter),
    ]);
    response.json({ restrictions, total });
  } catch {
    response.status(500).json({ error: "Unable to retrieve demo restrictions." });
  }
});

app.post("/api/demo-restrictions", async (request, response) => {
  if (!demoRestrictionsCollection) {
    response.status(503).json({ error: "Demo restriction storage is unavailable." });
    return;
  }

  const body: unknown = request.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    response.status(400).json({ error: "Request body must be a JSON object." });
    return;
  }

  const data = body as Record<string, unknown>;
  if (typeof data.ipAddress !== "string" || isIP(data.ipAddress.trim()) === 0) {
    response.status(400).json({ error: "ipAddress must be a valid IPv4 or IPv6 address." });
    return;
  }

  if (typeof data.durationMinutes !== "number" || ![5, 15, 30].includes(data.durationMinutes)) {
    response.status(400).json({ error: "durationMinutes must be 5, 15, or 30." });
    return;
  }

  if (
    data.alertId !== undefined &&
    (typeof data.alertId !== "string" || !/^[a-f\d]{24}$/i.test(data.alertId))
  ) {
    response.status(400).json({ error: "alertId must be a valid alert identifier." });
    return;
  }

  const createdAt = new Date();
  const durationMinutes = data.durationMinutes as DemoRestriction["durationMinutes"];
  const restriction: DemoRestriction = {
    ipAddress: data.ipAddress.trim().toLowerCase(),
    durationMinutes,
    createdAt,
    expiresAt: new Date(createdAt.getTime() + durationMinutes * 60 * 1000),
    status: "active",
    source: "manual",
    ...(typeof data.alertId === "string" ? { alertId: new ObjectId(data.alertId) } : {}),
  };

  try {
    const result = await demoRestrictionsCollection.insertOne(restriction);
    response.status(201).json({ restriction: { ...restriction, _id: result.insertedId } });
  } catch {
    response.status(500).json({ error: "Unable to create demo restriction." });
  }
});

app.post("/api/demo-restrictions/:id/revoke", async (request, response) => {
  if (!demoRestrictionsCollection) {
    response.status(503).json({ error: "Demo restriction storage is unavailable." });
    return;
  }

  const { id } = request.params;
  if (!/^[a-f\d]{24}$/i.test(id)) {
    response.status(400).json({ error: "id must be a valid restriction identifier." });
    return;
  }

  try {
    const revokedAt = new Date();
    const result = await demoRestrictionsCollection.updateOne(
      { _id: new ObjectId(id), status: "active" },
      { $set: { status: "revoked", revokedAt } },
    );

    if (result.matchedCount === 0) {
      response.status(404).json({ error: "Active demo restriction not found." });
      return;
    }

    response.json({ restriction: { id, status: "revoked", revokedAt } });
  } catch {
    response.status(500).json({ error: "Unable to revoke demo restriction." });
  }
});

// Short-lived in-memory admin sessions for the local demo only.
// Tokens are random, stored server-side, and sent as an HttpOnly cookie.
const ADMIN_COOKIE_NAME = "admin_session";
const ADMIN_SESSION_MINUTES = Math.max(1, Math.min(240, Number(process.env.ADMIN_SESSION_MINUTES) || 30));
const adminSessions = new Map<string, number>();

function getAdminCredentials(): { username: string; password: string } | null {
  const username = process.env.DEMO_ADMIN_USERNAME?.trim().toLowerCase();
  const password = process.env.DEMO_ADMIN_PASSWORD;
  if (!username || !password) {
    return null;
  }
  return { username, password };
}

function getSessionToken(request: express.Request): string | null {
  const header = request.headers.cookie;
  if (!header) {
    return null;
  }
  for (const part of header.split(";")) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }
    const name = part.slice(0, separatorIndex).trim();
    if (name === ADMIN_COOKIE_NAME) {
      return decodeURIComponent(part.slice(separatorIndex + 1).trim());
    }
  }
  return null;
}

function isAdminAuthenticated(request: express.Request): boolean {
  const token = getSessionToken(request);
  if (!token) {
    return false;
  }
  const expiresAt = adminSessions.get(token);
  if (expiresAt === undefined) {
    return false;
  }
  if (expiresAt <= Date.now()) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

function requireAdmin(request: express.Request, response: express.Response, next: express.NextFunction) {
  if (!isAdminAuthenticated(request)) {
    response.status(401).json({ error: "Admin authentication required.", adminRequired: true });
    return;
  }
  next();
}

function setAdminSessionCookie(response: express.Response, token: string) {
  response.setHeader(
    "Set-Cookie",
    `${ADMIN_COOKIE_NAME}=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${ADMIN_SESSION_MINUTES * 60}`,
  );
}

function clearAdminSessionCookie(response: express.Response) {
  response.setHeader("Set-Cookie", `${ADMIN_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

app.post("/api/admin/login", (request, response) => {
  const credentials = getAdminCredentials();
  if (!credentials) {
    response.status(503).json({ error: "Admin credentials are not configured on the server." });
    return;
  }

  const body: unknown = request.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    response.status(400).json({ error: "Request body must be a JSON object." });
    return;
  }
  const data = body as Record<string, unknown>;
  const username = typeof data.username === "string" ? data.username.trim().toLowerCase() : "";
  const password = typeof data.password === "string" ? data.password : "";

  const usernameMatches = username.length > 0 && passwordsMatch(username, credentials.username);
  const passwordMatches = password.length > 0 && passwordsMatch(password, credentials.password);
  if (!usernameMatches || !passwordMatches) {
    response.status(401).json({ error: "Invalid admin credentials.", authenticated: false });
    return;
  }

  const token = randomBytes(32).toString("hex");
  adminSessions.set(token, Date.now() + ADMIN_SESSION_MINUTES * 60 * 1000);
  setAdminSessionCookie(response, token);
  response.json({ authenticated: true, expiresInMinutes: ADMIN_SESSION_MINUTES });
});

app.post("/api/admin/logout", (request, response) => {
  const token = getSessionToken(request);
  if (token) {
    adminSessions.delete(token);
  }
  clearAdminSessionCookie(response);
  response.json({ authenticated: false });
});

app.get("/api/admin/session", (request, response) => {
  if (!isAdminAuthenticated(request)) {
    response.json({ authenticated: false });
    return;
  }
  response.json({ authenticated: true, expiresInMinutes: ADMIN_SESSION_MINUTES });
});

function getDemoCredentials(): { username: string; password: string } | null {
  const username = process.env.DEMO_LOGIN_USERNAME?.trim().toLowerCase();
  const password = process.env.DEMO_LOGIN_PASSWORD;
  if (!username || !password) {
    return null;
  }
  return { username, password };
}

function passwordsMatch(input: string, expected: string): boolean {
  const inputBuffer = Buffer.from(input, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return inputBuffer.length === expectedBuffer.length && timingSafeEqual(inputBuffer, expectedBuffer);
}

function buildIncidentHash(input: { ruleId: string; level: number; threshold: number; windowMinutes: number; triggeredAt: Date }): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        ruleId: input.ruleId,
        level: input.level,
        threshold: input.threshold,
        windowMinutes: input.windowMinutes,
        triggeredAt: input.triggeredAt.toISOString(),
      }),
    )
    .digest("hex");
}

async function expireLoginRestrictions(now: Date) {
  if (!loginRestrictionsCollection) return;
  await loginRestrictionsCollection.updateMany(
    { status: "active", expiresAt: { $lte: now } },
    { $set: { status: "expired" } },
  );
}

async function upsertFailedLoginAlert(ipAddress: string, attemptCount: number, level: number, observedAt: Date) {
  if (!alertsCollection) {
    throw new Error("Alert storage is unavailable.");
  }

  const filter = { ipAddress, ruleId: LOGIN_RESTRICTION_RULE_ID, status: "open" as const };
  const windowStartedAt = new Date(observedAt.getTime() - LOGIN_ATTEMPT_WINDOW_MS);
  const update = {
    $set: {
      attemptCount,
      restrictionLevel: level,
      windowStartedAt,
      lastObservedAt: observedAt,
      updatedAt: observedAt,
    },
    $setOnInsert: {
      ruleName: "Failed login burst",
      threshold: LOGIN_FAILED_ATTEMPT_THRESHOLD,
      windowMinutes: LOGIN_ATTEMPT_WINDOW_MINUTES,
      firstObservedAt: observedAt,
      createdAt: observedAt,
    },
  };

  try {
    await alertsCollection.updateOne(filter, update, { upsert: true });
  } catch (error) {
    if (!(error instanceof MongoServerError) || error.code !== 11000) {
      throw error;
    }

    await alertsCollection.updateOne(filter, { $set: update.$set });
  }
}

app.post("/api/login", async (request, response) => {
  if (!loginAttemptsCollection || !loginRestrictionsCollection || !alertsCollection) {
    response.status(503).json({ error: "Login security storage is unavailable." });
    return;
  }

  const credentials = getDemoCredentials();
  if (!credentials) {
    response.status(503).json({ error: "Demo login is not configured on this server." });
    return;
  }

  const body: unknown = request.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    response.status(400).json({ error: "Request body must be a JSON object." });
    return;
  }

  const data = body as Record<string, unknown>;
  if (typeof data.username !== "string" || data.username.trim().length === 0 || data.username.length > 64) {
    response.status(400).json({ error: "username must contain 1 to 64 characters." });
    return;
  }
  if (typeof data.password !== "string" || data.password.length === 0 || data.password.length > 256) {
    response.status(400).json({ error: "password must contain 1 to 256 characters." });
    return;
  }

  const username = data.username.trim().toLowerCase();
  const ipAddress = (request.ip ?? "unknown").toLowerCase();
  const now = new Date();

  try {
    await expireLoginRestrictions(now);

    const locked = await loginRestrictionsCollection.findOne({ username, level: 3, status: "locked" });
    if (locked) {
      response.status(403).json({
        allowed: false,
        authenticated: false,
        locked: true,
        reason: "This demo account is locked pending admin review. An admin can unlock it from the dashboard.",
        username,
        restriction: {
          level: 3,
          status: "locked",
          expiresAt: null,
          incidentHash: locked.incidentHash,
        },
      });
      return;
    }

    const activeRestriction = await loginRestrictionsCollection.findOne({
      username,
      ipAddress,
      status: "active",
      expiresAt: { $gt: now },
    });
    if (activeRestriction) {
      response.status(403).json({
        allowed: false,
        authenticated: false,
        restricted: true,
        reason: `Too many failed login attempts. This account is restricted from this address until the restriction expires.`,
        username,
        restriction: {
          level: activeRestriction.level,
          status: "active",
          durationMinutes: activeRestriction.durationMinutes,
          expiresAt: activeRestriction.expiresAt,
          incidentHash: activeRestriction.incidentHash,
        },
      });
      return;
    }

    const passwordMatches = username === credentials.username && passwordsMatch(data.password, credentials.password);
    if (passwordMatches) {
      await loginAttemptsCollection.insertOne({ username, ipAddress, attemptedAt: now, success: true });
      response.json({
        allowed: true,
        authenticated: true,
        username,
        reason: "Demo login successful. This protects only this local demo app's login flow.",
      });
      return;
    }

    await loginAttemptsCollection.insertOne({ username, ipAddress, attemptedAt: now, success: false });

    const windowStart = new Date(now.getTime() - LOGIN_ATTEMPT_WINDOW_MS);
    const failedCount = await loginAttemptsCollection.countDocuments({
      username,
      ipAddress,
      success: false,
      attemptedAt: { $gte: windowStart, $lte: now },
    });

    if (failedCount >= LOGIN_FAILED_ATTEMPT_THRESHOLD) {
      const priorEscalations = await loginRestrictionsCollection.countDocuments({
        username,
        ipAddress,
        status: "expired",
      });
      const level = Math.min(priorEscalations + 1, 3) as 1 | 2 | 3;
      const incidentHash = buildIncidentHash({
        ruleId: LOGIN_RESTRICTION_RULE_ID,
        level,
        threshold: LOGIN_FAILED_ATTEMPT_THRESHOLD,
        windowMinutes: LOGIN_ATTEMPT_WINDOW_MINUTES,
        triggeredAt: now,
      });

      if (level === 3) {
        await loginRestrictionsCollection.insertOne({
          username,
          ipAddress,
          level: 3,
          status: "locked",
          durationMinutes: 0,
          createdAt: now,
          expiresAt: null,
          incidentHash,
        } satisfies LoginRestriction);
        await upsertFailedLoginAlert(ipAddress, failedCount, level, now);

        response.status(403).json({
          allowed: false,
          authenticated: false,
          locked: true,
          reason: "Repeated restrictions for this account. It is now locked pending admin review.",
          username,
          attemptCount: failedCount,
          threshold: LOGIN_FAILED_ATTEMPT_THRESHOLD,
          windowMinutes: LOGIN_ATTEMPT_WINDOW_MINUTES,
          restriction: { level: 3, status: "locked", expiresAt: null, incidentHash },
        });
        return;
      }

      const durationMinutes = LOGIN_RESTRICTION_DURATIONS[level];
      const expiresAt = new Date(now.getTime() + durationMinutes * 60 * 1000);
      await loginRestrictionsCollection.insertOne({
        username,
        ipAddress,
        level,
        status: "active",
        durationMinutes,
        createdAt: now,
        expiresAt,
        incidentHash,
      } satisfies LoginRestriction);
      await upsertFailedLoginAlert(ipAddress, failedCount, level, now);

      response.status(403).json({
        allowed: false,
        authenticated: false,
        restricted: true,
        reason: `More than ${LOGIN_FAILED_ATTEMPT_THRESHOLD - 1} failed login attempts within ${LOGIN_ATTEMPT_WINDOW_MINUTES} minutes triggered an automatic level ${level} restriction.`,
        username,
        attemptCount: failedCount,
        threshold: LOGIN_FAILED_ATTEMPT_THRESHOLD,
        windowMinutes: LOGIN_ATTEMPT_WINDOW_MINUTES,
        restriction: {
          level,
          status: "active",
          durationMinutes,
          expiresAt,
          incidentHash,
        },
      });
      return;
    }

    response.status(401).json({
      allowed: true,
      authenticated: false,
      invalidCredentials: true,
      reason: "Invalid demo credentials.",
      username,
      attemptCount: failedCount,
      threshold: LOGIN_FAILED_ATTEMPT_THRESHOLD,
      windowMinutes: LOGIN_ATTEMPT_WINDOW_MINUTES,
    });
  } catch {
    response.status(500).json({ error: "Unable to evaluate login attempt." });
  }
});

app.get("/api/login-security", requireAdmin, async (_request, response) => {
  if (!loginAttemptsCollection || !loginRestrictionsCollection) {
    response.status(503).json({ error: "Login security storage is unavailable." });
    return;
  }

  try {
    const now = new Date();
    await expireLoginRestrictions(now);
    const [attempts, restrictions, totalFailedAttempts] = await Promise.all([
      loginAttemptsCollection.find({ success: false }).sort({ attemptedAt: -1, _id: -1 }).limit(50).toArray(),
      loginRestrictionsCollection
        .find({ $or: [{ status: "locked" }, { status: "active", expiresAt: { $gt: now } }] })
        .sort({ createdAt: -1, _id: -1 })
        .toArray(),
      loginAttemptsCollection.countDocuments({ success: false }),
    ]);
    response.json({ attempts, restrictions, totalFailedAttempts });
  } catch {
    response.status(500).json({ error: "Unable to retrieve login security data." });
  }
});

app.post("/api/login-security/unlock", requireAdmin, async (request, response) => {
  if (!loginRestrictionsCollection) {
    response.status(503).json({ error: "Login security storage is unavailable." });
    return;
  }

  const body: unknown = request.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    response.status(400).json({ error: "Request body must be a JSON object." });
    return;
  }

  const data = body as Record<string, unknown>;
  if (typeof data.username !== "string" || data.username.trim().length === 0 || data.username.length > 64) {
    response.status(400).json({ error: "username must contain 1 to 64 characters." });
    return;
  }

  try {
    const revokedAt = new Date();
    const result = await loginRestrictionsCollection.updateMany(
      { username: data.username.trim().toLowerCase(), status: { $in: ["locked", "active"] } },
      { $set: { status: "revoked", revokedAt } },
    );
    response.json({ unlocked: true, username: data.username.trim().toLowerCase(), revokedCount: result.modifiedCount });
  } catch {
    response.status(500).json({ error: "Unable to unlock demo account." });
  }
});

app.use((error: unknown, _request: express.Request, response: express.Response, next: express.NextFunction) => {
  if (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    error.type === "entity.parse.failed"
  ) {
    response.status(400).json({ error: "Request body must contain valid JSON." });
    return;
  }

  next(error);
});

async function startServer() {
  try {
    databaseConnection = await connectDatabase();
    reportsCollection = databaseConnection.db.collection<ThreatReport>("reports");
    alertsCollection = databaseConnection.db.collection<ThreatAlert>("alerts");
    demoRestrictionsCollection = databaseConnection.db.collection<DemoRestriction>("demo_restrictions");
    loginAttemptsCollection = databaseConnection.db.collection<LoginAttemptRecord>("login_attempts");
    loginRestrictionsCollection = databaseConnection.db.collection<LoginRestriction>("login_restrictions");
    await alertsCollection.createIndex(
      { ipAddress: 1, ruleId: 1 },
      {
        unique: true,
        partialFilterExpression: { status: "open" },
        name: "unique_open_alert_per_ip_rule",
      },
    );
    await demoRestrictionsCollection.createIndex({ ipAddress: 1, status: 1, expiresAt: 1 });
    await loginAttemptsCollection.createIndex({ username: 1, ipAddress: 1, attemptedAt: -1 });
    await loginRestrictionsCollection.createIndex({ username: 1, ipAddress: 1, status: 1 });
    await loginRestrictionsCollection.createIndex({ status: 1, expiresAt: 1 });
    console.log("MongoDB connection established.");

    app.listen(port, () => {
      console.log(`Backend server listening on port ${port}`);
    });
  } catch (error: unknown) {
    console.error(
      JSON.stringify({
        category: getConnectionFailureCategory(error),
        ...getSafeErrorDetails(error),
      }),
    );
    process.exitCode = 1;
  }
}

void startServer();
