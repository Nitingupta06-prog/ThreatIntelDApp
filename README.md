# ThreatIntelDApp

A classroom prototype for decentralized threat-intelligence reporting and community review.

## Class-demo scope

The working demonstration is **local**: the report content is uploaded to the presenter’s IPFS node, and its CID plus reviewer decision are recorded on a local Hardhat blockchain. Three configured reviewer wallets vote; two matching votes make a report `Verified` or `Rejected`.

This prototype does **not** monitor live network traffic, determine maliciousness automatically, or block IP addresses on other websites. The only enforcement is inside this demo app's own `POST /api/login` flow: if the server-observed client IP exactly matches the `ipAddress` of a **Verified** V2 report, that login attempt is denied with `blockedByIntel: true`. Rejected reports never block anything, and no other site, service, or network traffic is affected. A separate service would be needed to act on verified reports anywhere else. Use synthetic data only: IPFS report content is public to anyone who can retrieve its CID.

## Architecture

| Part | Role in the demo |
| --- | --- |
| Next.js frontend | Submit a report and show IPFS and on-chain results |
| Express backend | Sends the report JSON to the local Kubo IPFS node, returns its CID, serves the verified-intel feed, and checks it during demo login |
| IPFS Desktop / Kubo | Stores and serves the report content by CID |
| Hardhat + `ThreatReportRegistryV2` | Records each CID and its submitter, timestamp, and 2-of-3 review status |
| MetaMask | Signs local-chain submission and reviewer-vote transactions |

The V2 contract address used by the current local demo is `0x5FbDB2315678afecb367f032d93F642f64180aa3` on chain `31337`.

## Start the classroom demo

Before class, confirm IPFS Desktop is open and shows **Connected to IPFS**. The backend also needs the already-configured `backend/.env` and a reachable MongoDB connection to start; keep that private file out of screenshots and Git.

Open four PowerShell terminals. In each terminal, first activate the project’s Node version:

```powershell
fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression
fnm use 26
```

**Terminal 1 — local blockchain:**

```powershell
cd C:\Users\gupta\OneDrive\Documents\ThreatIntelDApp\blockchain
npx hardhat node
```

Leave it running. It prints local test accounts and private keys. Never use these generated test keys on Sepolia or Mainnet; never share them.

**Terminal 2 — deploy V2 to that running node:**

```powershell
cd C:\Users\gupta\OneDrive\Documents\ThreatIntelDApp\blockchain
npx hardhat ignition deploy ignition/modules/ThreatReportRegistryV2.ts --network localhost --parameters ignition/params/31337-v2.json
```

Keep the node running. Restarting it resets the local chain state and demo transactions; redeploy V2 before presenting again.

**Terminal 3 — backend:**

```powershell
cd C:\Users\gupta\OneDrive\Documents\ThreatIntelDApp\backend
$env:TRUST_PROXY="loopback"
npm run dev
```

`TRUST_PROXY=loopback` lets the backend read the client IP from `X-Forwarded-For` only when the request comes from the local loopback proxy — needed for the login-blocking demo below. Do **not** use `true` (that trusts every proxy and is unsafe). If `backend/.env` already sets `TRUST_PROXY`, keep that value instead.

Wait for `MongoDB connection established.` and `Backend server listening on port 3001`.

**Terminal 4 — frontend:**

```powershell
cd C:\Users\gupta\OneDrive\Documents\ThreatIntelDApp\frontend
npm run dev
```

Open `http://localhost:3000`.

## Demo sequence

1. In MetaMask, select **Hardhat Local** (RPC `http://127.0.0.1:8545`, chain ID `31337`). Connect the non-reviewer submitter wallet. It needs local test ETH for gas.
2. Open **Submit Report** and enter synthetic data, for example:

   - IP: `192.0.2.10` (documentation-only test IP)
   - Threat type: `Port scanning`
   - Summary: `Synthetic class demonstration report`

3. Choose **Decentralized submit (IPFS + local chain)** and confirm the MetaMask transaction. Explain: the report JSON goes to IPFS; the contract receives only its CID.
4. Scroll to **Decentralized reports**. Show the report details loaded back from IPFS and its on-chain `Submitted` status.
5. Switch MetaMask to reviewer A, connect that account to the dashboard, and click **Approve**. Show `1 approve`.
6. Switch to a different reviewer account and approve the same report. Show the status change to **Verified**.
7. Refresh the page and show that **Verified** remains. This was manually demonstrated on the local chain.

## Demo sequence — verified intel blocks demo login

8. Confirm the feed returns the verified report (PowerShell):

   ```powershell
   Invoke-RestMethod -Uri "http://localhost:3001/api/intel/verified" -Method Get
   ```

9. Simulate a login from the reported IP `192.0.2.10` (the backend trusts `X-Forwarded-For` only from loopback because of `TRUST_PROXY=loopback`):

   ```powershell
   Invoke-RestMethod -Uri "http://localhost:3001/api/login" -Method Post -ContentType "application/json" -Headers @{"X-Forwarded-For"="192.0.2.10"} -Body '{"username":"demo","password":"test"}'
   ```

   Expected: `403` with `blockedByIntel: true` — login denied before any password check, and **no** failed-attempt counter or restriction is created.
10. Repeat with a different IP to show normal behavior is unchanged:

    ```powershell
    Invoke-RestMethod -Uri "http://localhost:3001/api/login" -Method Post -ContentType "application/json" -Headers @{"X-Forwarded-For"="198.51.100.7"} -Body '{"username":"demo","password":"test"}'
    ```

    Expected: `401 invalidCredentials` (or `200` with correct credentials) — the intel feed does not interfere.
11. On `http://localhost:3000/demo-login`, the same block appears in the UI as **“Blocked by verified threat intel”** when the request IP matches.
12. If the Hardhat node, Kubo gateway, or chain is unavailable, `/api/login` returns `503` instead of guessing — mention this as a deliberate fail-closed demo choice.

This blocking applies **only** to this demo app's login endpoint. It does not monitor live traffic, inspect other websites, or block any IP anywhere else.

The local reviewers are the three addresses in `blockchain/ignition/params/31337-v2.json`. For this local-only demo, their private keys are printed by the Hardhat node and can be imported into MetaMask on the presenter’s computer. Do not paste those keys into this README, chat, slides, or use them on a public network. The report submitter must be a different wallet from the reviewers.

## Short presentation script

**English:** “ThreatIntelDApp is a prototype for sharing and reviewing threat reports. Report details are stored on IPFS, while the blockchain stores the content identifier and the review result. Three designated reviewers vote, and two matching votes are required to mark a report verified or rejected. This local demo does not monitor live traffic or block other systems; it demonstrates how applications could share and verify threat intelligence.”

**Hinglish:** “ThreatIntelDApp threat reports ko share aur review karne ka prototype hai. Report ki details IPFS par rehti hain, aur blockchain par uska CID aur review result record hota hai. Teen reviewers mein se do same decision dein tab report Verified ya Rejected hoti hai. Yeh local demo live traffic monitor ya kisi doosri app ko block nahi karta—yeh dikhata hai ki apps verified threat intelligence kaise share kar sakti hain.”

## Common questions

- **Why use IPFS?** It stores the report outside the contract and gives the content a CID. The CID lets the app retrieve the same content; it is not encryption or a privacy guarantee.
- **Why use a blockchain?** It provides a shared, tamper-evident record of submitted CIDs and reviewer decisions.
- **Who decides a report is verified?** The contract’s three configured reviewer wallets; two approve votes verify, and two reject votes reject.
- **Does it detect or block attackers by itself?** No. Reports are submitted by people in this prototype. The demo login endpoint does compare the server-observed IP against Verified report IPs and denies matching logins — but only inside this app, and only for exact IP matches.
- **Is this already a public DApp?** The demonstrated version uses a local blockchain and the presenter’s IPFS node. Other people cannot rely on it being available over the public internet yet.

## Older prototype features

The dashboard also contains earlier MongoDB, demo-login, alert, restriction, and V1 registry features. They are separate legacy/demo flows and are not the source of truth for the V2 decentralized report-review demonstration. For the class presentation, focus on **V2 registry** and **Decentralized reports**.

## Project folders

```text
frontend/    Next.js dashboard and MetaMask integration
backend/     Express API, MongoDB-backed legacy demo routes, and local IPFS upload endpoint
blockchain/  Hardhat contracts, including ThreatReportRegistryV2
```
