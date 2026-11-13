"use client";

import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { BrowserProvider, Contract, keccak256, toUtf8Bytes, type EventLog, type Log } from "ethers";

const API_URL = "http://localhost:3001/api/reports";
const ALERTS_API_URL = "http://localhost:3001/api/alerts";
const RESTRICTIONS_API_URL = "http://localhost:3001/api/demo-restrictions";
const LOGIN_SECURITY_API_URL = "http://localhost:3001/api/login-security";
const LOGIN_UNLOCK_API_URL = "http://localhost:3001/api/login-security/unlock";
const ADMIN_SESSION_API_URL = "http://localhost:3001/api/admin/session";
const ADMIN_LOGIN_API_URL = "http://localhost:3001/api/admin/login";
const ADMIN_LOGOUT_API_URL = "http://localhost:3001/api/admin/logout";
const HARDHAT_CHAIN_ID = 31337;
const SEPOLIA_CHAIN_ID = 11155111;

type NetworkConfig = {
  name: string;
  chainIdHex: string;
  rpcUrls: string[];
  blockExplorerUrls?: string[];
  registryAddress: string;
  deploymentBlock: number;
};

const NETWORKS: Record<number, NetworkConfig> = {
  [HARDHAT_CHAIN_ID]: {
    name: "Hardhat Local",
    chainIdHex: "0x7a69",
    rpcUrls: ["http://127.0.0.1:8545"],
    registryAddress: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    deploymentBlock: 0,
  },
  [SEPOLIA_CHAIN_ID]: {
    name: "Sepolia",
    chainIdHex: "0xaa36a7",
    rpcUrls: ["https://ethereum-sepolia-rpc.publicnode.com"],
    blockExplorerUrls: ["https://sepolia.etherscan.io"],
    registryAddress: "0xEdAC7D121D5bacA455735CF8c7C309D243B9B1a8",
    deploymentBlock: 12069456,
  },
};

function getNetworkConfig(chainId: number | null): NetworkConfig | undefined {
  return chainId === null ? undefined : NETWORKS[chainId];
}

const EVENT_QUERY_CHUNK_SIZE = 9000;

async function queryReportSubmittedEvents(
  contract: Contract,
  config: NetworkConfig,
  provider: BrowserProvider,
  reportHash?: string
): Promise<Log[]> {
  const latestBlock = await provider.getBlockNumber();
  const filter = reportHash
    ? contract.filters.ReportSubmitted(null, reportHash, null)
    : contract.filters.ReportSubmitted();
  const events: Log[] = [];
  for (let fromBlock = config.deploymentBlock; fromBlock <= latestBlock; fromBlock += EVENT_QUERY_CHUNK_SIZE) {
    const toBlock = Math.min(fromBlock + EVENT_QUERY_CHUNK_SIZE - 1, latestBlock);
    const chunk = await contract.queryFilter(filter, fromBlock, toBlock);
    events.push(...chunk);
  }
  return events;
}
const REGISTRY_ABI = [
  "function reportCount() view returns (uint256)",
  "function admin() view returns (address)",
  "function submitReport(bytes32 reportHash)",
  "function updateAuditStatus(uint256 reportId, uint8 newStatus)",
  "function getReport(uint256 reportId) view returns (tuple(bytes32 reportHash, uint256 submittedAt, address submitter, uint8 auditStatus) report)",
  "event ReportSubmitted(uint256 indexed reportId, bytes32 indexed reportHash, address indexed submitter, uint256 submittedAt)",
] as const;
const AUDIT_STATUSES = ["Submitted", "UnderReview", "Verified", "Rejected"] as const;
const AUDIT_STATUS_LABELS: Record<number, string> = {
  0: "Submitted",
  1: "Under review",
  2: "Verified",
  3: "Rejected",
};

type EthereumProvider = {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
  on: (event: string, listener: (...args: unknown[]) => void) => void;
  removeListener: (event: string, listener: (...args: unknown[]) => void) => void;
};

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }
}
const THREAT_TYPES = [
  "Credential stuffing",
  "Authentication failures",
  "Port scanning",
  "Phishing infrastructure",
] as const;

type ThreatReport = {
  _id: string;
  ipAddress: string;
  threatType: (typeof THREAT_TYPES)[number];
  summary: string;
  evidence?: string;
  submittedAt: string;
  status: string;
};

type ReportPayload = {
  reports?: unknown;
  total?: unknown;
  error?: unknown;
};

type ThreatAlert = {
  _id: string;
  ipAddress: string;
  ruleId: string;
  ruleName: string;
  status: "open";
  reportCount?: number;
  attemptCount?: number;
  threshold: number;
  windowMinutes: number;
  lastObservedAt: string;
};

type AlertPayload = {
  alerts?: unknown;
  total?: unknown;
  error?: unknown;
};

type DemoRestriction = {
  _id: string;
  ipAddress: string;
  durationMinutes: 5 | 15 | 30;
  createdAt: string;
  expiresAt: string;
  status: "active";
  alertId?: string;
  source?: "automatic_login_attempt" | "manual";
};

type RestrictionPayload = {
  restrictions?: unknown;
  total?: unknown;
  error?: unknown;
};

type LoginAttemptRecord = {
  _id: string;
  username: string;
  ipAddress: string;
  attemptedAt: string;
  success: boolean;
};

type LoginRestriction = {
  _id: string;
  username: string;
  ipAddress: string;
  level: 1 | 2 | 3;
  status: "active" | "expired" | "revoked" | "locked";
  durationMinutes: number;
  createdAt: string;
  expiresAt: string | null;
  incidentHash: string;
};

type LoginSecurityPayload = {
  attempts?: unknown;
  restrictions?: unknown;
  totalFailedAttempts?: unknown;
  error?: unknown;
};

const navItems = [
  { icon: "grid", label: "Overview", href: "#overview", active: true },
  { icon: "activity", label: "Threat reports", href: "#reports" },
  { icon: "bell", label: "Alerts", href: "#alerts" },
  { icon: "shield", label: "IP restrictions", href: "#restrictions" },
  { icon: "activity", label: "Demo login", href: "/demo-login" },
];

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
    bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" /><path d="M10 21h4" /></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.7a8 8 0 0 1-1.6.9l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.6-.9l-1.7.7-1.4-2.4L7.5 15a8 8 0 0 1 0-1.9L6.1 12l1.4-2.4 1.7.7a8 8 0 0 1 1.6-.9l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.6.9l1.7-.7 1.4 2.4-1.4 1.1a8 8 0 0 1-.1 1.9Z" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    close: <path d="m18 6-12 12M6 6l12 12" />,
  };

  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
}

function formatReported(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function shortenAddress(address: string) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

function getEthereum(): EthereumProvider | undefined {
  return typeof window === "undefined" ? undefined : window.ethereum;
}

function reportHashFor(report: ThreatReport) {
  const payload = JSON.stringify({
    _id: report._id,
    ipAddress: report.ipAddress,
    threatType: report.threatType,
    summary: report.summary,
    evidence: report.evidence ?? "",
    submittedAt: report.submittedAt,
  });
  return keccak256(toUtf8Bytes(payload));
}

export default function Home() {
  const [reports, setReports] = useState<ThreatReport[]>([]);
  const [totalReports, setTotalReports] = useState<number | null>(null);
  const [reportsLoading, setReportsLoading] = useState(true);
  const [reportsError, setReportsError] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState<number | null>(null);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [restrictions, setRestrictions] = useState<DemoRestriction[]>([]);
  const [totalRestrictions, setTotalRestrictions] = useState<number | null>(null);
  const [restrictionsLoading, setRestrictionsLoading] = useState(true);
  const [restrictionsError, setRestrictionsError] = useState<string | null>(null);
  const [restrictionDurations, setRestrictionDurations] = useState<Record<string, 5 | 15 | 30>>({});
  const [restrictionBusyId, setRestrictionBusyId] = useState<string | null>(null);
  const [alertRestrictionFeedback, setAlertRestrictionFeedback] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const [restrictionFeedback, setRestrictionFeedback] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const [showSubmitForm, setShowSubmitForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState<string | null>(null);
  const [ipAddress, setIpAddress] = useState("");
  const [threatType, setThreatType] = useState<(typeof THREAT_TYPES)[number]>(THREAT_TYPES[0]);
  const [summary, setSummary] = useState("");
  const [evidence, setEvidence] = useState("");
  const [walletAccount, setWalletAccount] = useState<string | null>(null);
  const [walletChainId, setWalletChainId] = useState<number | null>(null);
  const [walletConnecting, setWalletConnecting] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);
  const [registryCount, setRegistryCount] = useState<string | null>(null);
  const [registryLoading, setRegistryLoading] = useState(false);
  const [registryError, setRegistryError] = useState<string | null>(null);
  const [anchorBusyId, setAnchorBusyId] = useState<string | null>(null);
  const [anchorFeedback, setAnchorFeedback] = useState<Record<string, { kind: "success" | "error"; message: string }>>({});
  const [anchoredReports, setAnchoredReports] = useState<Record<string, { reportId: string; txHash: string }>>({});
  const [auditStatusByReport, setAuditStatusByReport] = useState<Record<string, number>>({});
  const [auditLoading, setAuditLoading] = useState(false);
  const [contractAdmin, setContractAdmin] = useState<string | null>(null);
  const [auditSelection, setAuditSelection] = useState<Record<string, number>>({});
  const [auditBusyId, setAuditBusyId] = useState<string | null>(null);
  const [auditFeedback, setAuditFeedback] = useState<Record<string, { kind: "success" | "error"; message: string }>>({});
  const [loginAttempts, setLoginAttempts] = useState<LoginAttemptRecord[]>([]);
  const [loginRestrictions, setLoginRestrictions] = useState<LoginRestriction[]>([]);
  const [totalFailedAttempts, setTotalFailedAttempts] = useState<number | null>(null);
  const [loginSecurityLoading, setLoginSecurityLoading] = useState(true);
  const [loginSecurityError, setLoginSecurityError] = useState<string | null>(null);
  const [loginSecurityFeedback, setLoginSecurityFeedback] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const [unlockBusyUser, setUnlockBusyUser] = useState<string | null>(null);
  const [incidentAnchorBusyId, setIncidentAnchorBusyId] = useState<string | null>(null);
  const [incidentAnchorFeedback, setIncidentAnchorFeedback] = useState<Record<string, { kind: "success" | "error"; message: string }>>({});
  const [anchoredIncidents, setAnchoredIncidents] = useState<Record<string, { reportId: string; txHash: string }>>({});
  const [adminStatus, setAdminStatus] = useState<"checking" | "authenticated" | "unauthenticated">("checking");
  const [adminBusy, setAdminBusy] = useState(false);

  const loadReports = useCallback(async () => {
    setReportsLoading(true);
    setReportsError(null);

    try {
      const response = await fetch(API_URL);
      const payload = (await response.json()) as ReportPayload;

      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to load reports.");
      }
      if (!Array.isArray(payload.reports) || typeof payload.total !== "number") {
        throw new Error("The reports API returned an unexpected response.");
      }

      setReports(payload.reports as ThreatReport[]);
      setTotalReports(payload.total);
    } catch (error) {
      setReportsError(error instanceof Error ? error.message : "Unable to connect to the reports API.");
    } finally {
      setReportsLoading(false);
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    setAlertsLoading(true);
    setAlertsError(null);

    try {
      const response = await fetch(ALERTS_API_URL);
      const payload = (await response.json()) as AlertPayload;

      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to load alerts.");
      }
      if (!Array.isArray(payload.alerts) || typeof payload.total !== "number") {
        throw new Error("The alerts API returned an unexpected response.");
      }

      setAlerts(payload.alerts as ThreatAlert[]);
      setTotalAlerts(payload.total);
    } catch (error) {
      setAlertsError(error instanceof Error ? error.message : "Unable to connect to the alerts API.");
    } finally {
      setAlertsLoading(false);
    }
  }, []);

  const loadRestrictions = useCallback(async () => {
    setRestrictionsLoading(true);
    setRestrictionsError(null);

    try {
      const response = await fetch(RESTRICTIONS_API_URL);
      const payload = (await response.json()) as RestrictionPayload;
      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to load demo restrictions.");
      }
      if (!Array.isArray(payload.restrictions) || typeof payload.total !== "number") {
        throw new Error("The demo restrictions API returned an unexpected response.");
      }

      setRestrictions(payload.restrictions as DemoRestriction[]);
      setTotalRestrictions(payload.total);
    } catch (error) {
      setRestrictionsError(error instanceof Error ? error.message : "Unable to connect to demo restrictions.");
    } finally {
      setRestrictionsLoading(false);
    }
  }, []);

  const loadLoginSecurity = useCallback(async () => {
    setLoginSecurityLoading(true);
    setLoginSecurityError(null);

    try {
      const response = await fetch(LOGIN_SECURITY_API_URL, { credentials: "include" });
      if (response.status === 401) {
        setAdminStatus("unauthenticated");
        setLoginSecurityLoading(false);
        return;
      }
      const payload = (await response.json()) as LoginSecurityPayload;
      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to load login security data.");
      }
      if (!Array.isArray(payload.attempts) || !Array.isArray(payload.restrictions) || typeof payload.totalFailedAttempts !== "number") {
        throw new Error("The login security API returned an unexpected response.");
      }

      setLoginAttempts(payload.attempts as LoginAttemptRecord[]);
      setLoginRestrictions(payload.restrictions as LoginRestriction[]);
      setTotalFailedAttempts(payload.totalFailedAttempts);
    } catch (error) {
      setLoginSecurityError(error instanceof Error ? error.message : "Unable to connect to login security API.");
    } finally {
      setLoginSecurityLoading(false);
    }
  }, []);

  const checkAdminSession = useCallback(async () => {
    try {
      const response = await fetch(ADMIN_SESSION_API_URL, { credentials: "include" });
      const payload = (await response.json()) as { authenticated?: unknown };
      setAdminStatus(payload.authenticated === true ? "authenticated" : "unauthenticated");
    } catch {
      setAdminStatus("unauthenticated");
    }
  }, []);

  useEffect(() => {
    void loadReports();
    void loadAlerts();
    void loadRestrictions();
    void checkAdminSession();
  }, [checkAdminSession, loadAlerts, loadReports, loadRestrictions]);

  useEffect(() => {
    if (adminStatus === "authenticated") {
      void loadLoginSecurity();
    }
  }, [adminStatus, loadLoginSecurity]);

  const syncWalletState = useCallback(async (ethereum: EthereumProvider) => {
    try {
      const provider = new BrowserProvider(ethereum);
      const network = await provider.getNetwork();
      setWalletChainId(Number(network.chainId));
      const accounts = (await provider.send("eth_accounts", [])) as string[];
      setWalletAccount(accounts.length > 0 ? accounts[0] : null);
    } catch {
      setWalletAccount(null);
      setWalletChainId(null);
    }
  }, []);

  useEffect(() => {
    const ethereum = getEthereum();
    if (!ethereum) return;

    const handleAccountsChanged = (...args: unknown[]) => {
      const accounts = args[0] as string[] | undefined;
      setWalletAccount(accounts && accounts.length > 0 ? accounts[0] : null);
      if (!accounts || accounts.length === 0) setWalletChainId(null);
    };
    const handleChainChanged = (...args: unknown[]) => {
      const chainIdHex = args[0] as string | undefined;
      setWalletChainId(chainIdHex ? Number.parseInt(chainIdHex, 16) : null);
    };

    ethereum.on("accountsChanged", handleAccountsChanged);
    ethereum.on("chainChanged", handleChainChanged);
    void syncWalletState(ethereum);

    return () => {
      ethereum.removeListener("accountsChanged", handleAccountsChanged);
      ethereum.removeListener("chainChanged", handleChainChanged);
    };
  }, [syncWalletState]);

  async function switchToNetwork(chainId: number) {
    const ethereum = getEthereum();
    const config = getNetworkConfig(chainId);
    if (!ethereum || !config) return;

    setWalletError(null);
    try {
      try {
        await ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: config.chainIdHex }] });
      } catch (error) {
        if ((error as { code?: number }).code !== 4902) throw error;
        await ethereum.request({
          method: "wallet_addEthereumChain",
          params: [{
            chainId: config.chainIdHex,
            chainName: config.name,
            rpcUrls: config.rpcUrls,
            blockExplorerUrls: config.blockExplorerUrls,
            nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
          }],
        });
      }
      await syncWalletState(ethereum);
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : "Unable to switch network.");
    }
  }

  async function connectWallet() {
    const ethereum = getEthereum();
    if (!ethereum) {
      setWalletError("MetaMask is not installed. Install the MetaMask extension and try again.");
      return;
    }

    setWalletConnecting(true);
    setWalletError(null);
    try {
      await ethereum.request({ method: "eth_requestAccounts" });
      await syncWalletState(ethereum);
    } catch (error) {
      if ((error as { code?: number }).code === 4001) {
        setWalletError("Wallet connection was rejected.");
      } else {
        setWalletError(error instanceof Error ? error.message : "Unable to connect wallet.");
      }
    } finally {
      setWalletConnecting(false);
    }
  }

  const loadRegistryCount = useCallback(async () => {
    const ethereum = getEthereum();
    if (!ethereum || !walletAccount) {
      setRegistryCount(null);
      setRegistryError(null);
      return;
    }
    const network = getNetworkConfig(walletChainId);
    if (!network) {
      setRegistryCount(null);
      setRegistryError("Switch MetaMask to Hardhat Local or Sepolia to read the registry.");
      return;
    }

    setRegistryLoading(true);
    setRegistryError(null);
    try {
      const provider = new BrowserProvider(ethereum);
      const contract = new Contract(network.registryAddress, REGISTRY_ABI, provider);
      const count = (await contract.reportCount()) as bigint;
      setRegistryCount(count.toString());
    } catch (error) {
      setRegistryCount(null);
      setRegistryError(error instanceof Error ? error.message : "Unable to read reportCount() from the registry contract.");
    } finally {
      setRegistryLoading(false);
    }
  }, [walletAccount, walletChainId]);

  useEffect(() => {
    void loadRegistryCount();
  }, [loadRegistryCount]);

  const loadAnchoredReports = useCallback(async () => {
    const ethereum = getEthereum();
    if (!ethereum || !walletAccount || !getNetworkConfig(walletChainId) || reports.length === 0) {
      setAnchoredReports({});
      setAuditStatusByReport({});
      setContractAdmin(null);
      return;
    }

    setAuditLoading(true);
    try {
      const config = getNetworkConfig(walletChainId)!;
      const provider = new BrowserProvider(ethereum);
      const contract = new Contract(config.registryAddress, REGISTRY_ABI, provider);
      const events = await queryReportSubmittedEvents(contract, config, provider);
      const byHash = new Map<string, { reportId: string; txHash: string }>();
      for (const event of events) {
        const log = event as EventLog;
        const reportId = (log.args?.[0] as bigint | undefined)?.toString();
        const reportHash = log.args?.[1] as string | undefined;
        if (reportId && reportHash && log.transactionHash) {
          byHash.set(reportHash.toLowerCase(), { reportId, txHash: log.transactionHash });
        }
      }

      const matched: Record<string, { reportId: string; txHash: string }> = {};
      for (const report of reports) {
        const info = byHash.get(reportHashFor(report).toLowerCase());
        if (info) matched[report._id] = info;
      }
      setAnchoredReports(matched);

      try {
        const adminAddress = (await contract.admin()) as string;
        setContractAdmin(adminAddress.toLowerCase());
      } catch {
        setContractAdmin(null);
      }

      const statuses: Record<string, number> = {};
      await Promise.all(
        Object.entries(matched).map(async ([reportKey, info]) => {
          try {
            const onChainReport = (await contract.getReport(BigInt(info.reportId))) as { auditStatus: bigint | number };
            statuses[reportKey] = Number(onChainReport.auditStatus);
          } catch {
            // Leave the status blank for this report if the read fails.
          }
        })
      );
      setAuditStatusByReport(statuses);
    } catch {
      setAnchoredReports({});
      setAuditStatusByReport({});
      setContractAdmin(null);
    } finally {
      setAuditLoading(false);
    }
  }, [reports, walletAccount, walletChainId]);

  useEffect(() => {
    void loadAnchoredReports();
  }, [loadAnchoredReports]);

  async function anchorReport(report: ThreatReport) {
    const ethereum = getEthereum();
    if (!ethereum || !walletAccount) {
      setAnchorFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: "Connect your MetaMask wallet first." } }));
      return;
    }
    if (!getNetworkConfig(walletChainId)) {
      setAnchorFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: "Switch MetaMask to Hardhat Local or Sepolia first." } }));
      return;
    }

    setAnchorBusyId(report._id);
    setAnchorFeedback((current) => {
      const next = { ...current };
      delete next[report._id];
      return next;
    });
    try {
      const config = getNetworkConfig(walletChainId)!;
      const provider = new BrowserProvider(ethereum);
      const signer = await provider.getSigner();
      const contract = new Contract(config.registryAddress, REGISTRY_ABI, signer);
      const reportHash = reportHashFor(report);

      let existing: Log[];
      try {
        existing = await queryReportSubmittedEvents(contract, config, provider, reportHash);
      } catch (error) {
        setAnchorFeedback((current) => ({
          ...current,
          [report._id]: { kind: "error", message: `Could not verify whether this report is already anchored: ${error instanceof Error ? error.message : "event query failed"}` },
        }));
        return;
      }
      if (existing.length > 0) {
        const existingLog = existing[0] as EventLog;
        const reportId = (existingLog.args?.[0] as bigint | undefined)?.toString() ?? "unknown";
        if (existingLog.transactionHash) {
          setAnchoredReports((current) => ({ ...current, [report._id]: { reportId, txHash: existingLog.transactionHash as string } }));
        }
        setAnchorFeedback((current) => ({ ...current, [report._id]: { kind: "success", message: `Already anchored on-chain as report #${reportId}.` } }));
        return;
      }

      const tx = await contract.submitReport(reportHash);
      const receipt = await tx.wait();
      const submitted = receipt?.logs
        .map((log: Log) => {
          try {
            return contract.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((parsed: { name?: string } | null) => parsed?.name === "ReportSubmitted");
      const reportId = (submitted?.args?.[0] as bigint | undefined)?.toString() ?? "unknown";

      setAnchorFeedback((current) => ({
        ...current,
        [report._id]: { kind: "success", message: `Anchored on-chain as report #${reportId} · tx ${tx.hash.slice(0, 10)}…${tx.hash.slice(-6)}` },
      }));
      if (reportId !== "unknown") {
        setAnchoredReports((current) => ({ ...current, [report._id]: { reportId, txHash: tx.hash } }));
      }
      void loadRegistryCount();
    } catch (error) {
      if ((error as { code?: number }).code === 4001) {
        setAnchorFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: "Transaction rejected in MetaMask." } }));
      } else {
        setAnchorFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: error instanceof Error ? error.message : "Unable to anchor report hash." } }));
      }
    } finally {
      setAnchorBusyId(null);
    }
  }

  const activeNetwork = getNetworkConfig(walletChainId);
  const isRegistryAdmin = Boolean(contractAdmin && walletAccount && contractAdmin === walletAccount.toLowerCase());

  async function updateReportAuditStatus(report: ThreatReport) {
    const anchored = anchoredReports[report._id];
    const ethereum = getEthereum();
    const network = getNetworkConfig(walletChainId);
    if (!anchored || !ethereum || !walletAccount || !network) return;
    if (!isRegistryAdmin) {
      setAuditFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: "Only the connected admin wallet can update audit status." } }));
      return;
    }

    const currentStatus = auditStatusByReport[report._id];
    const newStatus = auditSelection[report._id] ?? currentStatus;
    if (newStatus === undefined || newStatus === currentStatus) return;

    setAuditBusyId(report._id);
    setAuditFeedback((current) => {
      const next = { ...current };
      delete next[report._id];
      return next;
    });
    try {
      const provider = new BrowserProvider(ethereum);
      const signer = await provider.getSigner();
      const contract = new Contract(network.registryAddress, REGISTRY_ABI, signer);
      const tx = await contract.updateAuditStatus(BigInt(anchored.reportId), newStatus);
      await tx.wait();
      setAuditFeedback((current) => ({
        ...current,
        [report._id]: { kind: "success", message: `On-chain audit status updated to ${AUDIT_STATUS_LABELS[newStatus] ?? AUDIT_STATUSES[newStatus]}.` },
      }));
      await loadAnchoredReports();
    } catch (error) {
      if ((error as { code?: number }).code === 4001) {
        setAuditFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: "Transaction rejected in MetaMask." } }));
      } else {
        setAuditFeedback((current) => ({ ...current, [report._id]: { kind: "error", message: error instanceof Error ? error.message : "Unable to update audit status." } }));
      }
    } finally {
      setAuditBusyId(null);
    }
  }

  async function applyRestriction(alert: ThreatAlert) {
    setRestrictionBusyId(alert._id);
    setAlertRestrictionFeedback(null);
    try {
      const response = await fetch(RESTRICTIONS_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ipAddress: alert.ipAddress,
          durationMinutes: restrictionDurations[alert._id] ?? 5,
          alertId: alert._id,
        }),
      });
      const payload = (await response.json()) as { error?: unknown };
      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to apply demo restriction.");
      }

      setAlertRestrictionFeedback({ kind: "success", message: `Temporary demo restriction applied to ${alert.ipAddress}.` });
      await loadRestrictions();
    } catch (error) {
      setAlertRestrictionFeedback({ kind: "error", message: error instanceof Error ? error.message : "Unable to apply demo restriction." });
    } finally {
      setRestrictionBusyId(null);
    }
  }

  async function revokeRestriction(restriction: DemoRestriction) {
    setRestrictionBusyId(restriction._id);
    setRestrictionFeedback(null);
    try {
      const response = await fetch(`${RESTRICTIONS_API_URL}/${restriction._id}/revoke`, { method: "POST" });
      const payload = (await response.json()) as { error?: unknown };
      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to revoke demo restriction.");
      }

      setRestrictionFeedback({ kind: "success", message: `Demo restriction for ${restriction.ipAddress} was revoked.` });
      await loadRestrictions();
    } catch (error) {
      setRestrictionFeedback({ kind: "error", message: error instanceof Error ? error.message : "Unable to revoke demo restriction." });
    } finally {
      setRestrictionBusyId(null);
    }
  }

  async function anchorIncident(restriction: LoginRestriction) {
    const ethereum = getEthereum();
    if (!ethereum || !walletAccount) {
      setIncidentAnchorFeedback((current) => ({ ...current, [restriction._id]: { kind: "error", message: "Connect your MetaMask wallet first." } }));
      return;
    }
    if (!getNetworkConfig(walletChainId)) {
      setIncidentAnchorFeedback((current) => ({ ...current, [restriction._id]: { kind: "error", message: "Switch MetaMask to Hardhat Local or Sepolia first." } }));
      return;
    }

    const incidentHash = `0x${restriction.incidentHash}`;
    setIncidentAnchorBusyId(restriction._id);
    setIncidentAnchorFeedback((current) => {
      const next = { ...current };
      delete next[restriction._id];
      return next;
    });
    try {
      const config = getNetworkConfig(walletChainId)!;
      const provider = new BrowserProvider(ethereum);
      const signer = await provider.getSigner();
      const contract = new Contract(config.registryAddress, REGISTRY_ABI, signer);

      let existing: Log[];
      try {
        existing = await queryReportSubmittedEvents(contract, config, provider, incidentHash);
      } catch (error) {
        setIncidentAnchorFeedback((current) => ({
          ...current,
          [restriction._id]: { kind: "error", message: `Could not verify whether this incident is already anchored: ${error instanceof Error ? error.message : "event query failed"}` },
        }));
        return;
      }
      if (existing.length > 0) {
        const existingLog = existing[0] as EventLog;
        const reportId = (existingLog.args?.[0] as bigint | undefined)?.toString() ?? "unknown";
        if (existingLog.transactionHash) {
          setAnchoredIncidents((current) => ({ ...current, [restriction._id]: { reportId, txHash: existingLog.transactionHash as string } }));
        }
        setIncidentAnchorFeedback((current) => ({ ...current, [restriction._id]: { kind: "success", message: `Already anchored on-chain as report #${reportId}.` } }));
        return;
      }

      const tx = await contract.submitReport(incidentHash);
      const receipt = await tx.wait();
      const submitted = receipt?.logs
        .map((log: Log) => {
          try {
            return contract.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((parsed: { name?: string } | null) => parsed?.name === "ReportSubmitted");
      const reportId = (submitted?.args?.[0] as bigint | undefined)?.toString() ?? "unknown";

      setIncidentAnchorFeedback((current) => ({
        ...current,
        [restriction._id]: { kind: "success", message: `Incident hash anchored on-chain as report #${reportId} · tx ${tx.hash.slice(0, 10)}…${tx.hash.slice(-6)}` },
      }));
      if (reportId !== "unknown") {
        setAnchoredIncidents((current) => ({ ...current, [restriction._id]: { reportId, txHash: tx.hash } }));
      }
      void loadRegistryCount();
    } catch (error) {
      if ((error as { code?: number }).code === 4001) {
        setIncidentAnchorFeedback((current) => ({ ...current, [restriction._id]: { kind: "error", message: "Transaction rejected in MetaMask." } }));
      } else {
        setIncidentAnchorFeedback((current) => ({ ...current, [restriction._id]: { kind: "error", message: error instanceof Error ? error.message : "Unable to anchor incident hash." } }));
      }
    } finally {
      setIncidentAnchorBusyId(null);
    }
  }

  async function unlockAccount(username: string) {
    setUnlockBusyUser(username);
    setLoginSecurityFeedback(null);
    try {
      const response = await fetch(LOGIN_UNLOCK_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username }),
      });
      const payload = (await response.json()) as { error?: unknown };
      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to unlock demo account.");
      }

      setLoginSecurityFeedback({ kind: "success", message: `Demo account "${username}" unlocked (admin demo control).` });
      await loadLoginSecurity();
    } catch (error) {
      setLoginSecurityFeedback({ kind: "error", message: error instanceof Error ? error.message : "Unable to unlock demo account." });
    } finally {
      setUnlockBusyUser(null);
    }
  }

  async function handleAdminLogout() {
    setAdminBusy(true);
    try {
      await fetch(ADMIN_LOGOUT_API_URL, { method: "POST", credentials: "include" });
    } finally {
      setAdminStatus("unauthenticated");
      setAdminBusy(false);
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(null);

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ipAddress,
          threatType,
          summary,
          ...(evidence ? { evidence } : {}),
        }),
      });
      const payload = (await response.json()) as { error?: unknown };

      if (!response.ok) {
        throw new Error(typeof payload.error === "string" ? payload.error : "Unable to submit report.");
      }

      setShowSubmitForm(false);
      setIpAddress("");
      setThreatType(THREAT_TYPES[0]);
      setSummary("");
      setEvidence("");
      setSubmitSuccess("Threat report submitted for review.");
      await loadReports();
      await loadAlerts();
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Unable to submit report.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="dashboard-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" aria-label="ThreatIntelDApp overview">
          <span className="brand-mark"><Icon name="shield" size={21} /></span>
          <span className="brand-name">ThreatIntel<span>DApp</span></span>
        </a>

        <div className="workspace-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          {navItems.map((item) => (
            <a className={`nav-item${item.active ? " active" : ""}`} href={item.href} key={item.label}>
              <Icon name={item.icon} />
              <span>{item.label}</span>
            </a>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="workspace-label">PREFERENCES</div>
          <a className="nav-item" href="#settings"><Icon name="settings" /><span>Settings</span></a>
          <div className="sidebar-note">
            <span className="note-dot" />
            <span><strong>Demo environment</strong><small>Reports API · local demo</small></span>
          </div>
          <div className="profile-row">
            <div className="avatar">SA</div>
            <div className="profile-copy"><strong>Security Analyst</strong><small>Demo workspace</small></div>
            <button className="icon-button profile-more" aria-label="Profile options"><span>···</span></button>
          </div>
        </div>
      </aside>

      <section className="main-panel" id="overview">
        <header className="topbar">
          <div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><strong>Overview</strong></div>
          <div className="topbar-actions">
            <div className={`system-status${reportsError ? " system-status-error" : ""}`}>
              <span className="status-dot" />
              {reportsLoading ? "Connecting to reports API" : reportsError ? "Reports API unavailable" : "Reports API connected"}
            </div>
            <div className="wallet-area">
              {walletAccount ? (
                <div className={`wallet-status${activeNetwork ? " wallet-status-ok" : " wallet-status-warn"}`}>
                  <span className="status-dot" />
                  <span className="wallet-address">{shortenAddress(walletAccount)}</span>
                  <span className="wallet-network">{activeNetwork ? activeNetwork.name : walletChainId === null ? "Unknown network" : `Chain ${walletChainId}`}</span>
                </div>
              ) : (
                <button className="wallet-button" onClick={() => void connectWallet()} disabled={walletConnecting}>
                  {walletConnecting ? "Connecting…" : "Connect Wallet"}
                </button>
              )}
              {walletError && <div className="wallet-error" role="alert">{walletError}</div>}
            </div>
            <button className="icon-button search-button" aria-label="Search"><Icon name="search" /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Icon name="bell" /></button>
            <div className="top-avatar">SA</div>
          </div>
        </header>

        <div className="content-wrap">
          <section className="page-heading">
            <div>
              <div className="eyebrow">DECENTRALIZED THREAT INTELLIGENCE DAPP</div>
              <h1>Threat intelligence overview</h1>
              <p>Review off-chain submissions in this local demo dashboard.</p>
            </div>
            <button className="submit-button" onClick={() => { setShowSubmitForm(true); setSubmitError(null); setSubmitSuccess(null); }}>
              <span className="plus">+</span> Submit Report
            </button>
          </section>

          {submitSuccess && <div className="feedback-message feedback-success" role="status">{submitSuccess}</div>}

          <section className="metrics-grid" aria-label="Threat summary">
            <article className="metric-card">
              <div className="metric-top"><span>Total reports</span><span className="metric-icon"><Icon name="activity" /></span></div>
              <div className="metric-value">{reportsLoading && totalReports === null ? "…" : totalReports ?? "—"}</div>
              <div className="metric-foot">{reportsError && totalReports === null ? "Reports API unavailable" : "Count from reports API"}</div>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>Open alerts</span><span className="metric-icon"><Icon name="bell" /></span></div>
              <div className="metric-value">{alertsLoading && totalAlerts === null ? "…" : totalAlerts ?? "—"}</div>
              <div className="metric-foot">{alertsError && totalAlerts === null ? "Alerts API unavailable" : "Reports & demo-login heuristics"}</div>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>Demo IP restrictions</span><span className="metric-icon"><Icon name="shield" /></span></div>
              <div className="metric-value">{restrictionsLoading && totalRestrictions === null ? "…" : totalRestrictions ?? "—"}</div>
              <div className="metric-foot">Active in local demo login only</div>
            </article>
          </section>

          <section className="registry-section" aria-labelledby="registry-heading">
            <div className="section-heading">
              <div>
                <div className="section-kicker">{activeNetwork ? `ON-CHAIN REGISTRY · ${activeNetwork.name.toUpperCase()} · CHAIN ${walletChainId}` : "ON-CHAIN REGISTRY · UNSUPPORTED NETWORK"}</div>
                <h2 id="registry-heading">On-chain registry</h2>
              </div>
              <div className="registry-header-actions">
                <div className="network-switch" role="group" aria-label="Choose registry network">
                  {Object.entries(NETWORKS).map(([chainId, network]) => (
                    <button
                      key={chainId}
                      className={`network-switch-button${walletChainId === Number(chainId) ? " network-switch-active" : ""}`}
                      onClick={() => void switchToNetwork(Number(chainId))}
                      disabled={!walletAccount}
                    >
                      {network.name}
                    </button>
                  ))}
                </div>
                <button className="filter-button" onClick={() => void loadRegistryCount()} disabled={registryLoading || !walletAccount || !activeNetwork}>
                  Refresh <span className="refresh-mark">↻</span>
                </button>
              </div>
            </div>
            <div className="registry-card">
              {!walletAccount && <div className="alerts-state">Connect your MetaMask wallet to read the on-chain registry.</div>}
              {walletAccount && !activeNetwork && (
                <div className="alerts-state alerts-error" role="alert">
                  <span>Connected to unsupported network{walletChainId !== null ? ` (chain ${walletChainId})` : ""}. Supported registries: Hardhat Local (31337) and Sepolia (11155111).</span>
                </div>
              )}
              {walletAccount && activeNetwork && registryLoading && <div className="alerts-state">Reading reportCount()…</div>}
              {walletAccount && activeNetwork && !registryLoading && registryError && (
                <div className="alerts-state alerts-error" role="alert">
                  <span>{registryError}</span>
                  <button className="retry-button" onClick={() => void loadRegistryCount()}>Try again</button>
                </div>
              )}
              {walletAccount && activeNetwork && !registryLoading && !registryError && registryCount !== null && (
                <div className="registry-count-row">
                  <span className="registry-count-value">{registryCount}</span>
                  <span className="registry-count-label">reports recorded on-chain</span>
                  <code className="registry-address">{activeNetwork.registryAddress}</code>
                </div>
              )}
            </div>
            <p className="heuristic-note">Read-only view of ThreatReportRegistry on {activeNetwork ? activeNetwork.name : "a supported network"}. No transactions are sent from this dashboard.</p>
          </section>

          <section className="alerts-section" id="alerts" aria-labelledby="alerts-heading">
            <div className="section-heading">
              <div>
                <div className="section-kicker">LOCAL SIMULATION HEURISTIC · NOT LIVE MONITORING</div>
                <h2 id="alerts-heading">Recent open alerts</h2>
              </div>
              <span className="report-limit">{alertsLoading ? "Loading" : `${alerts.length} shown · ${totalAlerts ?? "—"} open`}</span>
            </div>
            <div className="alerts-card">
              {alertsLoading && <div className="alerts-state">Loading open alerts…</div>}
              {!alertsLoading && alertsError && (
                <div className="alerts-state alerts-error" role="alert">
                  <span>{alertsError}</span>
                  <button className="retry-button" onClick={() => void loadAlerts()}>Try again</button>
                </div>
              )}
              {!alertsLoading && !alertsError && alerts.length === 0 && (
                <div className="alerts-state">No open alerts from reports or demo login attempts.</div>
              )}
              {!alertsLoading && !alertsError && alerts.length > 0 && (
                <>
                  <div className="alerts-list-heading"><span>IP ADDRESS</span><span>RULE</span><span>COUNT</span><span>STATUS</span><span>ACTION</span></div>
                  <ul className="alerts-list">
                    {alerts.slice(0, 5).map((alert) => (
                      <li className="alert-row" key={alert._id}>
                        <code>{alert.ipAddress}</code>
                        <span className="alert-rule">{alert.ruleName}</span>
                        <span className="alert-count">{alert.attemptCount ?? alert.reportCount ?? "—"}</span>
                        <span className="alert-open-status"><i /> Open</span>
                        <div className="alert-action">
                          <span className="demo-scope-tag">Manual · optional</span>
                          <select
                            aria-label={`Restriction duration for ${alert.ipAddress}`}
                            value={restrictionDurations[alert._id] ?? 5}
                            onChange={(event) => setRestrictionDurations((current) => ({ ...current, [alert._id]: Number(event.target.value) as 5 | 15 | 30 }))}
                            disabled={restrictionBusyId === alert._id}
                          >
                            <option value={5}>5 min</option><option value={15}>15 min</option><option value={30}>30 min</option>
                          </select>
                          <button className="mini-action-button" onClick={() => void applyRestriction(alert)} disabled={restrictionBusyId === alert._id}>
                            {restrictionBusyId === alert._id ? "Applying…" : "Restrict demo"}
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
            {alertRestrictionFeedback && <div className={`feedback-message feedback-${alertRestrictionFeedback.kind}`} role={alertRestrictionFeedback.kind === "error" ? "alert" : "status"}>{alertRestrictionFeedback.message}</div>}
            <p className="heuristic-note">Alerts are generated locally from submitted-report bursts and failed demo login bursts. They do not represent live network monitoring.</p>
            <p className="heuristic-note">Failed demo logins are counted per account and server-observed IP in a rolling 10-minute window; 4 failures trigger a level 1 restriction (30 min), a repeat after expiry triggers level 2 (48 hours), and a third escalation locks the account until admin unlock. The duration selector and “Restrict demo” button are an optional manual demo control. Local demo only — no real credentials of other services, visitor IPs elsewhere, or network traffic are inspected or blocked.</p>
          </section>

          <section className="restrictions-section" id="login-security" aria-labelledby="login-security-heading">
            <div className="section-heading">
              <div><div className="section-kicker">LOCAL DEMO LOGIN ONLY · AUTOMATIC</div><h2 id="login-security-heading">Login security</h2></div>
              <span className="report-limit">{loginSecurityLoading ? "Loading" : `${totalFailedAttempts ?? "—"} failed attempts`}</span>
            </div>
            {adminStatus !== "authenticated" ? (
              <div className="admin-login-card">
                <div className="admin-login-heading">
                  <span className="section-kicker">ADMIN ACCESS</span>
                  <h3>Sign in required</h3>
                  <p>Failed-attempt data and account unlock require a short-lived admin session. Use the admin sign-in on the demo login page — credentials are configured only in the backend <code>.env</code>.</p>
                </div>
                <a className="submit-button admin-login-button" href="/demo-login" style={{ textDecoration: "none", display: "inline-flex" }}>
                  Go to admin sign in
                </a>
              </div>
            ) : (
              <>
                <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
                  <button className="revoke-button" onClick={() => void handleAdminLogout()} disabled={adminBusy}>Sign out admin</button>
                </div>
                {loginSecurityFeedback && <div className={`feedback-message feedback-${loginSecurityFeedback.kind}`} role={loginSecurityFeedback.kind === "error" ? "alert" : "status"}>{loginSecurityFeedback.message}</div>}
                {loginSecurityError && <div className="alerts-state alerts-error" role="alert"><span>{loginSecurityError}</span><button className="retry-button" onClick={() => void loadLoginSecurity()}>Try again</button></div>}
                {loginSecurityLoading && <div className="alerts-state">Loading login security data…</div>}
                {!loginSecurityError && !loginSecurityLoading && (
              <>
                <div className="table-card restrictions-table-card">
                  <div className="table-scroll">
                    <table className="restrictions-table">
                      <thead><tr><th>ACCOUNT</th><th>SOURCE IP</th><th>LEVEL</th><th>STATUS</th><th>EXPIRES</th><th>INCIDENT HASH</th><th>ACTION</th></tr></thead>
                      <tbody>
                        {loginRestrictions.map((restriction) => (
                          <tr key={restriction._id}>
                            <td><code>{restriction.username}</code></td>
                            <td><code>{restriction.ipAddress}</code></td>
                            <td><span className="demo-scope-tag">Level {restriction.level}</span></td>
                            <td>{restriction.status === "locked" ? "Locked" : restriction.status === "active" ? "Active" : restriction.status}</td>
                            <td>{restriction.expiresAt ? formatReported(restriction.expiresAt) : "Until admin unlock"}</td>
                            <td><code title={restriction.incidentHash}>{restriction.incidentHash.slice(0, 10)}…</code></td>
                            <td>
                              <div className="alert-action">
                                <button className="mini-action-button" onClick={() => void anchorIncident(restriction)} disabled={incidentAnchorBusyId === restriction._id || Boolean(anchoredIncidents[restriction._id])}>
                                  {incidentAnchorBusyId === restriction._id ? "Anchoring…" : anchoredIncidents[restriction._id] ? "Anchored" : "Anchor hash"}
                                </button>
                                {(restriction.status === "locked" || restriction.status === "active") && (
                                  <button className="revoke-button" onClick={() => void unlockAccount(restriction.username)} disabled={unlockBusyUser === restriction.username}>
                                    {unlockBusyUser === restriction.username ? "Unlocking…" : "Unlock · admin"}
                                  </button>
                                )}
                              </div>
                              {incidentAnchorFeedback[restriction._id] && <div className={`feedback-message feedback-${incidentAnchorFeedback[restriction._id].kind}`}>{incidentAnchorFeedback[restriction._id].message}</div>}
                            </td>
                          </tr>
                        ))}
                        {loginRestrictions.length === 0 && (
                          <tr><td colSpan={7}><div className="alerts-state">No active or locked login restrictions.</div></td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="table-card restrictions-table-card" style={{ marginTop: 16 }}>
                  <div className="table-scroll">
                    <table className="restrictions-table">
                      <thead><tr><th>TIME</th><th>ACCOUNT</th><th>SOURCE IP</th><th>RESULT</th></tr></thead>
                      <tbody>
                        {loginAttempts.slice(0, 10).map((attempt) => (
                          <tr key={attempt._id}>
                            <td>{formatReported(attempt.attemptedAt)}</td>
                            <td><code>{attempt.username}</code></td>
                            <td><code>{attempt.ipAddress}</code></td>
                            <td><span className="demo-scope-tag">{attempt.success ? "Success" : "Failed"}</span></td>
                          </tr>
                        ))}
                        {loginAttempts.length === 0 && (
                          <tr><td colSpan={4}><div className="alerts-state">No failed login attempts recorded yet.</div></td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
                )}
              </>
            )}
            <p className="heuristic-note">Only the non-sensitive incident hash (rule, level, threshold, window, timestamp — never username, password, or IP) is anchored on-chain. “Unlock · admin” is a manual demo control for locked accounts and requires an admin session. This section reflects only this local demo app's login flow — it does not monitor or block other sites or network traffic.</p>
          </section>

          <section className="restrictions-section" id="restrictions" aria-labelledby="restrictions-heading">
            <div className="section-heading">
              <div><div className="section-kicker">LOCAL DEMO LOGIN ONLY</div><h2 id="restrictions-heading">Active demo restrictions</h2></div>
              <span className="report-limit">{restrictionsLoading ? "Loading" : `${restrictions.length} active`}</span>
            </div>
            {restrictionFeedback && <div className={`feedback-message feedback-${restrictionFeedback.kind}`} role={restrictionFeedback.kind === "error" ? "alert" : "status"}>{restrictionFeedback.message}</div>}
            {restrictionsError && <div className="alerts-state alerts-error" role="alert"><span>{restrictionsError}</span><button className="retry-button" onClick={() => void loadRestrictions()}>Try again</button></div>}
            {!restrictionsError && restrictionsLoading && <div className="alerts-state">Loading active demo restrictions…</div>}
            {!restrictionsError && !restrictionsLoading && restrictions.length === 0 && <div className="alerts-state restriction-empty">No active demo restrictions.</div>}
            {!restrictionsError && !restrictionsLoading && restrictions.length > 0 && (
              <div className="table-card restrictions-table-card">
                <div className="table-scroll">
                  <table className="restrictions-table">
                    <thead><tr><th>IP ADDRESS</th><th>DURATION</th><th>EXPIRES</th><th>SCOPE</th><th>ACTION</th></tr></thead>
                    <tbody>
                      {restrictions.map((restriction) => (
                        <tr key={restriction._id}>
                          <td><code>{restriction.ipAddress}</code></td>
                          <td>{restriction.durationMinutes} min</td>
                          <td>{formatReported(restriction.expiresAt)}</td>
                          <td><span className="demo-scope-tag">Demo login only{restriction.source === "automatic_login_attempt" ? " · auto" : ""}</span></td>
                          <td><button className="revoke-button" onClick={() => void revokeRestriction(restriction)} disabled={restrictionBusyId === restriction._id}>{restrictionBusyId === restriction._id ? "Revoking…" : "Revoke"}</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>

          <section className="reports-section">
            <div className="section-heading">
              <div><div className="section-kicker">OFF-CHAIN REPORTS</div><h2>Recent threat reports</h2></div>
              <span className="report-limit">Newest 50</span>
            </div>
            <div className="table-card" id="reports">
              <div className="table-toolbar">
                <div className="feed-label"><span className="feed-live-dot" /> Reports API <span className="feed-divider">·</span> <span>{reportsLoading ? "Loading" : `${reports.length} loaded`}</span></div>
                <button className="filter-button" onClick={() => void loadReports()} disabled={reportsLoading}>
                  Refresh <span className="refresh-mark">↻</span>
                </button>
              </div>
              {reportsError && (
                <div className="report-state report-error" role="alert">
                  <strong>Could not load reports</strong><span>{reportsError}</span>
                  <button className="retry-button" onClick={() => void loadReports()}>Try again</button>
                </div>
              )}
              {!reportsError && reportsLoading && <div className="report-state">Loading reports…</div>}
              {!reportsError && !reportsLoading && reports.length === 0 && <div className="report-state">No threat reports yet. Submit the first report to get started.</div>}
              {!reportsError && !reportsLoading && reports.length > 0 && (
                <div className="table-scroll">
                  <table>
                    <thead><tr><th>REPORT</th><th>INDICATOR</th><th>STATUS</th><th>SUBMITTED</th><th>ANCHOR</th><th>ON-CHAIN AUDIT</th></tr></thead>
                    <tbody>
                      {reports.map((report) => (
                        <tr key={report._id}>
                          <td><div className="report-title">{report.threatType}</div><div className="report-meta">{report.summary}</div></td>
                          <td><code>{report.ipAddress}</code></td>
                          <td><span className="review-status"><i />{report.status.replaceAll("_", " ")}</span></td>
                          <td><span className="reported-time"><Icon name="clock" size={14} />{formatReported(report.submittedAt)}</span></td>
                          <td>
                            {anchoredReports[report._id] ? (
                              <div className="anchor-anchored">
                                <div>Anchored · #{anchoredReports[report._id].reportId}</div>
                                <div className="anchor-tx">tx {anchoredReports[report._id].txHash.slice(0, 10)}…{anchoredReports[report._id].txHash.slice(-6)}</div>
                              </div>
                            ) : (
                              <button
                                className="anchor-button"
                                onClick={() => void anchorReport(report)}
                                disabled={anchorBusyId === report._id || !walletAccount || !activeNetwork}
                              >
                                {anchorBusyId === report._id ? "Anchoring…" : "Anchor hash"}
                              </button>
                            )}
                            {anchorFeedback[report._id] && (
                              <div className={`anchor-feedback anchor-feedback-${anchorFeedback[report._id].kind}`} role={anchorFeedback[report._id].kind === "error" ? "alert" : "status"}>
                                {anchorFeedback[report._id].message}
                              </div>
                            )}
                          </td>
                          <td>
                            {!anchoredReports[report._id] && <span className="audit-empty">—</span>}
                            {anchoredReports[report._id] && auditLoading && <span className="audit-empty">Loading…</span>}
                            {anchoredReports[report._id] && !auditLoading && auditStatusByReport[report._id] === undefined && <span className="audit-empty">Unavailable</span>}
                            {anchoredReports[report._id] && !auditLoading && auditStatusByReport[report._id] !== undefined && (
                              <>
                                <span className="audit-status-value">{AUDIT_STATUS_LABELS[auditStatusByReport[report._id]] ?? AUDIT_STATUSES[auditStatusByReport[report._id]]}</span>
                                {isRegistryAdmin ? (
                                  <div className="alert-action audit-action">
                                    <select
                                      aria-label={`On-chain audit status for report ${report._id}`}
                                      value={auditSelection[report._id] ?? auditStatusByReport[report._id]}
                                      onChange={(event) => setAuditSelection((current) => ({ ...current, [report._id]: Number(event.target.value) }))}
                                      disabled={auditBusyId === report._id}
                                    >
                                      {AUDIT_STATUSES.map((status, index) => (
                                        <option key={status} value={index}>{AUDIT_STATUS_LABELS[index]}</option>
                                      ))}
                                    </select>
                                    <button
                                      className="mini-action-button"
                                      onClick={() => void updateReportAuditStatus(report)}
                                      disabled={auditBusyId === report._id || (auditSelection[report._id] ?? auditStatusByReport[report._id]) === auditStatusByReport[report._id]}
                                    >
                                      {auditBusyId === report._id ? "Updating…" : "Update status"}
                                    </button>
                                  </div>
                                ) : (
                                  <div className="audit-readonly">Read-only · admin wallet {contractAdmin ? shortenAddress(contractAdmin) : ""} required</div>
                                )}
                                {auditFeedback[report._id] && (
                                  <div className={`anchor-feedback anchor-feedback-${auditFeedback[report._id].kind}`} role={auditFeedback[report._id].kind === "error" ? "alert" : "status"}>
                                    {auditFeedback[report._id].message}
                                  </div>
                                )}
                              </>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="table-footer">
                <span>Showing <strong>{reports.length}</strong> of <strong>{totalReports ?? "—"}</strong> reports</span>
                <span>All report details and evidence are stored off-chain</span>
              </div>
            </div>
          </section>
          <footer className="page-footer"><span>ThreatIntelDApp <span className="footer-separator">·</span> Local demo dashboard</span><span>Local simulation only — real logins and traffic are never affected</span></footer>
        </div>
      </section>

      {showSubmitForm && (
        <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setShowSubmitForm(false); }}>
          <section className="report-modal" role="dialog" aria-modal="true" aria-labelledby="report-form-title">
            <div className="modal-heading">
              <div><div className="section-kicker">OFF-CHAIN SUBMISSION</div><h2 id="report-form-title">Submit a threat report</h2></div>
              <button className="icon-button modal-close" aria-label="Close form" onClick={() => setShowSubmitForm(false)}><Icon name="close" /></button>
            </div>
            <p className="modal-description">Reports are stored in the demo database for review. No detection or restriction action is triggered.</p>
            <form className="report-form" onSubmit={handleSubmit}>
              <label htmlFor="ipAddress">IP address <span>IPv4 or IPv6</span></label>
              <input id="ipAddress" name="ipAddress" value={ipAddress} onChange={(event) => setIpAddress(event.target.value)} placeholder="e.g. 192.0.2.10" required autoComplete="off" />

              <label htmlFor="threatType">Threat type</label>
              <select id="threatType" name="threatType" value={threatType} onChange={(event) => setThreatType(event.target.value as (typeof THREAT_TYPES)[number])}>
                {THREAT_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>

              <label htmlFor="summary">Short summary <span>{summary.length}/280</span></label>
              <textarea id="summary" name="summary" value={summary} onChange={(event) => setSummary(event.target.value)} maxLength={280} rows={3} required placeholder="Briefly describe the reported activity" />

              <label htmlFor="evidence">Evidence <span>Optional · up to 10,000 characters</span></label>
              <textarea id="evidence" name="evidence" value={evidence} onChange={(event) => setEvidence(event.target.value)} maxLength={10_000} rows={4} placeholder="Add supporting text, if available" />

              {submitError && <div className="feedback-message feedback-error" role="alert">{submitError}</div>}
              <div className="form-actions">
                <button type="button" className="cancel-button" onClick={() => setShowSubmitForm(false)} disabled={submitting}>Cancel</button>
                <button type="submit" className="submit-button" disabled={submitting}>{submitting ? "Submitting…" : "Submit for review"}</button>
              </div>
            </form>
          </section>
        </div>
      )}
    </main>
  );
}
