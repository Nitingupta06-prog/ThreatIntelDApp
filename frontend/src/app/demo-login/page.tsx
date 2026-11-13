"use client";

import { useState, type FormEvent } from "react";

const LOGIN_API_URL = "http://localhost:3001/api/login";
const ADMIN_LOGIN_API_URL = "http://localhost:3001/api/admin/login";

type LoginResult = {
  allowed?: boolean;
  authenticated?: boolean;
  invalidCredentials?: boolean;
  locked?: boolean;
  restricted?: boolean;
  blockedByIntel?: boolean;
  reason?: string;
  username?: string;
  attemptCount?: number;
  threshold?: number;
  windowMinutes?: number;
  restriction?: {
    level?: number;
    status?: string;
    durationMinutes?: number;
    expiresAt?: string | null;
    incidentHash?: string;
  };
  error?: unknown;
};

function formatExpiry(value: string | null | undefined) {
  if (!value) return "No expiry — locked until admin unlock";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export default function DemoLoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LoginResult | null>(null);
  const [adminPanelOpen, setAdminPanelOpen] = useState(false);
  const [adminUsername, setAdminUsername] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [adminBusy, setAdminBusy] = useState(false);
  const [adminError, setAdminError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(LOGIN_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const payload = (await response.json()) as LoginResult;

      if (typeof payload.error === "string") {
        throw new Error(payload.error);
      }
      if (typeof payload.reason !== "string") {
        throw new Error("The login API returned an unexpected response.");
      }

      setResult(payload);
      if (payload.authenticated) {
        setPassword("");
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to connect to the login API.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleAdminSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAdminBusy(true);
    setAdminError(null);

    try {
      const response = await fetch(ADMIN_LOGIN_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username: adminUsername, password: adminPassword }),
      });
      const payload = (await response.json()) as { authenticated?: unknown; error?: unknown };
      if (!response.ok || payload.authenticated !== true) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Admin login failed.");
      }

      setAdminPassword("");
      window.location.assign("/#login-security");
    } catch (requestError) {
      setAdminError(requestError instanceof Error ? requestError.message : "Admin login failed.");
      setAdminBusy(false);
    }
  }

  const resultKind = result?.authenticated
    ? "allowed"
    : result?.locked || result?.restricted || result?.blockedByIntel
      ? "restricted"
      : result?.invalidCredentials
        ? "error"
        : "allowed";

  return (
    <main className="dashboard-shell">
      <aside className="sidebar demo-sidebar">
        <a className="brand" href="/" aria-label="ThreatIntelDApp overview">
          <span className="brand-mark"><span aria-hidden="true">◈</span></span>
          <span className="brand-name">ThreatIntel<span>DApp</span></span>
        </a>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          <a className="nav-item" href="/"><span className="demo-nav-symbol" aria-hidden="true">▦</span><span>Overview</span></a>
          <a className="nav-item" href="/#reports"><span className="demo-nav-symbol" aria-hidden="true">⌁</span><span>Threat reports</span></a>
          <a className="nav-item" href="/#alerts"><span className="demo-nav-symbol" aria-hidden="true">♧</span><span>Alerts</span></a>
          <a className="nav-item" href="/#restrictions"><span className="demo-nav-symbol" aria-hidden="true">◇</span><span>IP restrictions</span></a>
          <a className="nav-item active" href="/demo-login" aria-current="page"><span className="demo-nav-symbol" aria-hidden="true">↗</span><span>Demo login</span></a>
        </nav>

        <div className="sidebar-bottom">
          <div className="workspace-label">DEMO SCOPE</div>
          <div className="sidebar-note">
            <span className="note-dot" />
            <span><strong>Local demo only</strong><small>Protects this app's login flow</small></span>
          </div>
        </div>
      </aside>

      <section className="main-panel">
        <header className="topbar">
          <div className="breadcrumb"><a href="/">Workspace</a><span className="crumb-slash">/</span><strong>Demo login</strong></div>
          <div className="topbar-actions"><div className="system-status"><span className="status-dot" /> Local demo only</div></div>
        </header>

        <div className="content-wrap">
          <section className="page-heading">
            <div>
              <div className="eyebrow">LOCAL DEMO LOGIN · REAL CREDENTIAL CHECK</div>
              <h1>Demo login</h1>
              <p>Sign in with the demo credentials configured in the backend <code>.env</code>. Failed attempts are counted per account and source IP; crossing the threshold automatically applies an escalating restriction.</p>
            </div>
          </section>

          <section className="demo-login-card" aria-labelledby="demo-login-heading">
            <div className="section-kicker">LOCAL DEMO ONLY</div>
            <h2 id="demo-login-heading">Demo account sign-in</h2>
            <p className="modal-description">Every submit is a real login attempt against this demo app only. The backend records the server timestamp and the server-observed client IP (never a client-supplied IP). 4 failed attempts for the same account and IP within 10 minutes trigger a 30-minute restriction; a repeat after expiry triggers 48 hours; a third escalation locks the account until an admin unlocks it. Credentials are never logged or returned. This flow does not monitor or block any other site or network traffic.</p>

            <form className="demo-login-form" onSubmit={handleSubmit}>
              <label htmlFor="demo-username">Username</label>
              <input
                id="demo-username"
                name="username"
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                required
              />
              <label htmlFor="demo-password">Password</label>
              <input
                id="demo-password"
                name="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
              <button type="submit" className="submit-button" disabled={submitting}>
                {submitting ? "Signing in…" : "Sign in"}
              </button>
              <p className="demo-login-hint">Use the DEMO_LOGIN_USERNAME / DEMO_LOGIN_PASSWORD values from backend/.env.</p>
            </form>

            <div className="admin-entry">
              <button type="button" className="admin-entry-button" onClick={() => setAdminPanelOpen((open) => !open)} aria-expanded={adminPanelOpen}>
                {adminPanelOpen ? "Hide admin sign in" : "Admin sign in"}
              </button>
              {adminPanelOpen && (
                <div className="admin-login-card admin-inline-panel">
                  <div className="admin-login-heading">
                    <span className="section-kicker">ADMIN ACCESS</span>
                    <h3>Admin sign in</h3>
                    <p>Opens the Login security section on the overview with a short-lived admin session. Credentials are configured only in the backend <code>.env</code>.</p>
                  </div>
                  <form className="admin-login-form" onSubmit={(event) => void handleAdminSubmit(event)}>
                    <div className="admin-field">
                      <label htmlFor="admin-username-inline">Username</label>
                      <input id="admin-username-inline" name="admin-username" type="text" autoComplete="username" placeholder="Admin username" value={adminUsername} onChange={(event) => setAdminUsername(event.target.value)} required />
                    </div>
                    <div className="admin-field">
                      <label htmlFor="admin-password-inline">Password</label>
                      <input id="admin-password-inline" name="admin-password" type="password" autoComplete="current-password" placeholder="Admin password" value={adminPassword} onChange={(event) => setAdminPassword(event.target.value)} required />
                    </div>
                    {adminError && <div className="feedback-message feedback-error" role="alert">{adminError}</div>}
                    <div className="admin-inline-actions">
                      <button className="submit-button admin-login-button" type="submit" disabled={adminBusy}>
                        {adminBusy ? "Signing in…" : "Sign in as admin"}
                      </button>
                      <button className="cancel-button" type="button" onClick={() => { setAdminPanelOpen(false); setAdminError(null); setAdminPassword(""); }}>
                        Cancel
                      </button>
                    </div>
                  </form>
                </div>
              )}
            </div>

            {error && <div className="demo-login-result error" role="alert"><h2>Could not reach login API</h2><p>{error}</p></div>}
            {result && (
              <div className={`demo-login-result ${resultKind}`} role="status">
                <h2>
                  {result.authenticated
                    ? "Login successful"
                    : result.blockedByIntel
                      ? "Blocked by verified threat intel"
                      : result.locked
                        ? "Account locked"
                        : result.restricted
                          ? `Restriction level ${result.restriction?.level ?? ""} active`
                          : "Invalid credentials"}
                </h2>
                <p>{result.reason}</p>
                {typeof result.attemptCount === "number" && typeof result.threshold === "number" && typeof result.windowMinutes === "number" && (
                  <p className="attempt-count">
                    Failed attempts in the last {result.windowMinutes} min: <strong>{result.attemptCount}</strong> · threshold: {result.threshold}
                  </p>
                )}
                {result.invalidCredentials && typeof result.attemptCount === "number" && typeof result.threshold === "number" && (
                  <p className="attempt-count">Remaining attempts before restriction: <strong>{Math.max(result.threshold - result.attemptCount, 0)}</strong></p>
                )}
                {(result.restricted || result.locked) && result.restriction?.status === "active" && typeof result.restriction.durationMinutes === "number" && (
                  <p className="expiry-time">Restriction duration: {result.restriction.durationMinutes >= 60 ? `${result.restriction.durationMinutes / 60} hours` : `${result.restriction.durationMinutes} minutes`}</p>
                )}
                {(result.restricted || result.locked) && result.restriction?.expiresAt && (
                  <p className="expiry-time">Restriction expires: {formatExpiry(result.restriction.expiresAt)}</p>
                )}
                {(result.restricted || result.locked) && result.restriction?.incidentHash && (
                  <p className="attempt-count">Incident hash: <code>{result.restriction.incidentHash.slice(0, 16)}…</code> (non-sensitive; anchorable on-chain from the dashboard)</p>
                )}
              </div>
            )}
          </section>

          <p className="heuristic-note">Restrictions are created automatically when the failed-attempt threshold is crossed and can be unlocked by an admin from the dashboard. This page protects only this local demo app's login flow — it never inspects real credentials of other services, visitor IPs elsewhere, or network traffic.</p>
        </div>
      </section>
    </main>
  );
}
