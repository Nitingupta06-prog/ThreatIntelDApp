# ThreatIntelDApp

A beginner-friendly decentralized threat-intelligence demo. Analysts submit threat reports off-chain; the dashboard can anchor a deterministic hash of each report on an Ethereum smart contract and track an on-chain audit status.

## What the app does (and its demo boundaries)

- **Off-chain reports** — the backend stores threat reports (IP address, threat type, summary, optional evidence) in MongoDB. Reports stay `pending_review`.
- **Alerts are a heuristic, not live monitoring** — alerts are generated locally from two rules: submitted-report bursts (3+ reports for the same IP within 10 minutes) and failed demo login bursts (4+ failed logins for the same account and server-observed IP within 10 minutes). No real network traffic is analyzed.
- **Demo login is a real credential check for this app only** — `POST /api/login` verifies username/password against `DEMO_LOGIN_USERNAME`/`DEMO_LOGIN_PASSWORD` in `backend/.env` (never hardcoded, logged, or returned). Failed attempts are recorded with server timestamp and server-observed client IP (proxy headers only when `TRUST_PROXY` is set). 4 failures in 10 minutes → 30-minute restriction; repeat after expiry → 48 hours; third escalation → account locked until admin unlock. Successful logins are not counted as failures.
- **IP restrictions are demo-only and mostly automatic** — login restrictions only affect this app's `/api/login` endpoint — they do not block real logins or network traffic elsewhere. Only a non-sensitive incident hash (rule, level, threshold, window, timestamp — never username, password, or IP) can be anchored on-chain. Manual restrictions remain as an optional demo control.
- **Login security admin access is a local demo control** — `GET /api/login-security` and `POST /api/login-security/unlock` require a short-lived admin session. Admin credentials come only from `DEMO_ADMIN_USERNAME`/`DEMO_ADMIN_PASSWORD` in `backend/.env`; `POST /api/admin/login` issues a random token in an HttpOnly, SameSite=Lax cookie (lifetime set by `ADMIN_SESSION_MINUTES`, default 30). No admin password or permanent secret exists in frontend code — the dashboard only holds the session cookie.
- **On-chain registry** — `ThreatReportRegistry` stores the `bytes32` report hash, the submission timestamp, the submitter wallet address, and an audit status (`Submitted`, `UnderReview`, `Verified`, `Rejected`) for each report. No report text, IPs, or evidence go on-chain. The contract admin can update audit statuses; everyone can read them.

## Architecture

| Layer | Tech | Role |
| --- | --- | --- |
| `frontend/` | Next.js 16 + React 19 + ethers v6 | Dashboard UI, MetaMask wallet connection, on-chain reads and transactions |
| `backend/` | Express 5 + MongoDB (Node/tsx) | REST API for reports, alerts, demo restrictions, demo login |
| `blockchain/` | Hardhat 3 + Solidity 0.8.34 + Ignition | `ThreatReportRegistry` contract storing report hash, submission timestamp, submitter wallet address, and audit status; report text, IP address, and evidence stay off-chain |

The frontend talks to the backend at `http://localhost:3001` and to the chain through the user's MetaMask wallet (it never holds a private key).

## Prerequisites

- Node.js 22.13+ and npm
- MongoDB — a local instance or a MongoDB Atlas cluster
- [MetaMask](https://metamask.io/) browser extension
- For Sepolia work: a Sepolia testnet wallet with test ETH (see below)

## Install dependencies

Run each command in its own PowerShell terminal, or sequentially:

```powershell
cd backend;   npm install
cd ..\frontend; npm install
cd ..\blockchain; npm install
```

## Configure the backend

Copy the example env file and fill in your MongoDB connection string:

```powershell
cd backend
copy .env.example .env
```

`.env` should contain (values are yours — never commit them):

```dotenv
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB_NAME=threatintel_demo
DEMO_LOGIN_USERNAME=demo_analyst
DEMO_LOGIN_PASSWORD=choose-a-local-demo-password
DEMO_ADMIN_USERNAME=demo_admin
DEMO_ADMIN_PASSWORD=choose-a-local-admin-password
# ADMIN_SESSION_MINUTES=30   # optional — admin session lifetime (default 30)
# TRUST_PROXY=   # optional — only set when behind a trusted proxy
```

For Atlas, use your cluster's connection string instead. The database name defaults to `threatintel_demo`.

## Run the app locally

You need the Hardhat node running in one terminal at all times. A second terminal is used once for the deploy command and can then be reused for the backend. The frontend runs in a third terminal.

**Terminal 1 — Hardhat local node** (chain ID `31337`, RPC `http://127.0.0.1:8545`):

```powershell
cd blockchain
npx hardhat node
```

Leave it running — this is the persistent local node at `http://127.0.0.1:8545`. In a second terminal, deploy the registry to it, passing the existing admin parameter file:

```powershell
cd blockchain
npx hardhat ignition deploy ignition/modules/ThreatReportRegistry.ts --network localhost --parameters ignition/params/31337.json
```

This deploys to the running localhost node and uses `ignition/params/31337.json`, which transfers admin to the configured `adminAddress`. Once the deploy finishes, keep this same terminal open — you will reuse it for the backend below. The current local registry address is:

```
0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
```

(An older local deployment exists at `0x5FbDB2315678afecb367f032d93F642f64180aa3` — use the address above, which matches the frontend config.)

**Terminal 2 — Deploy, then Backend (reuse the same terminal):**

First run the deploy command shown above in this terminal. After it completes, start the backend in the same terminal:

```powershell
cd ..\backend
npm run dev
```

Listens on `http://localhost:3001`. Health check: `http://localhost:3001/health`.

**Terminal 3 — Frontend:**

```powershell
cd frontend
npm run dev
```

Open `http://localhost:3000`.

## Using the dashboard

1. Submit threat reports with **Submit Report** (stored off-chain in MongoDB).
2. Click **Connect Wallet** in the top bar and approve the MetaMask connection.
3. In the **On-chain registry** section, pick **Hardhat Local** or **Sepolia**. If MetaMask is on the wrong network, use the switcher — the app will ask MetaMask to switch or add the network.
4. The card shows `reportCount()` for the connected registry.
5. In the reports table, click **Anchor hash** on a report. The app computes a deterministic `keccak256` hash of the report, checks `ReportSubmitted` events for duplicates (in 9,000-block chunks to respect RPC limits), and sends `submitReport` via MetaMask. Anchored reports show `Anchored · #id` plus a truncated tx hash, and the status persists after refresh.
6. If your wallet is the contract admin, an audit-status dropdown appears for anchored reports; choosing a status sends `updateAuditStatus`. Non-admin wallets see the status read-only.

## Sepolia testnet

- **Chain ID:** `11155111`
- **RPC used by the frontend:** `https://ethereum-sepolia-rpc.publicnode.com`
- **Registry address:** `0xEdAC7D121D5bacA455735CF8c7C309D243B9B1a8`
- **Deployment block:** `12069456` (the frontend only queries events from this block onward)
- **Explorer:** `https://sepolia.etherscan.io`

### Get test ETH

Use a Sepolia faucet (e.g. Google "Sepolia faucet" — Alchemy, Infura, or sepoliafaucet.com) and paste your MetaMask account address.

### Deploying to Sepolia

`hardhat.config.ts` reads two **configuration variables** for the `sepolia` network:

- `SEPOLIA_RPC_URL` — your Sepolia RPC endpoint
- `SEPOLIA_PRIVATE_KEY` — the deployer wallet's private key

These are stored in Hardhat's **encrypted keystore**, not in `.env` files. Set them interactively (Hardhat prompts for the value and encrypts it at rest):

```powershell
cd blockchain
npx hardhat keystore set SEPOLIA_RPC_URL
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
```

The Ignition module `ThreatReportRegistryAdminModule` requires an `adminAddress` parameter (the wallet that will control audit statuses — typically your MetaMask account). Create `blockchain/ignition/params/11155111.json`:

```json
{
  "ThreatReportRegistryAdminModule": {
    "adminAddress": "0xYourMetaMaskAddress"
  }
}
```

Then deploy, passing the parameters file you just created:

```powershell
npx hardhat ignition deploy ignition/modules/ThreatReportRegistry.ts --network sepolia --parameters ignition/params/11155111.json
```

### Verifying on Sepolia without exposing keys

- The contract address and all reads are public — check `reportCount()`, `admin()`, and `getReport(id)` on `https://sepolia.etherscan.io/address/0xEdAC7D121D5bacA455735CF8c7C309D243B9B1a8`.
- Without an explorer API key, you can still inspect the public contract details, transactions, and events on `https://sepolia.etherscan.io/address/0xEdAC7D121D5bacA455735CF8c7C309D243B9B1a8` — but source-code verification requires a separately configured verification method (for example, a block-explorer API key set up for Hardhat, or manual verification through the explorer's UI). `SEPOLIA_PRIVATE_KEY` is a deployment key, not a verification key, and must not be used for verification.

- Never paste your private key into chat, tickets, or committed files. If a key is ever exposed, move funds and generate a new wallet immediately.

## What must stay private vs. what is safe to share

**Keep private (never commit or share):**

- `backend/.env` — especially `MONGODB_URI` (may contain DB credentials)
- `SEPOLIA_PRIVATE_KEY` keystore entry and any raw private key or seed phrase
- `SEPOLIA_RPC_URL` if your provider URL embeds an API key
- The Hardhat keystore files themselves

**Safe to share:**

- Contract addresses, chain IDs, RPC endpoints without embedded keys, deployment block numbers
- `ignition/params/*.json` `adminAddress` values (public wallet addresses)
- `backend/.env.example`, `package.json` files, and all source code
- Transaction hashes and on-chain report IDs

## Project layout

```
backend/     Express API + MongoDB (reports, alerts, demo restrictions, demo login)
frontend/    Next.js dashboard + MetaMask/ethers on-chain integration
blockchain/  Hardhat project: contracts/, ignition/ modules + params + deployments
```
