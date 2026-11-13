# ThreatIntelDApp

A classroom prototype for decentralized threat-intelligence reporting and community review.

## Class-demo scope

The working demonstration is **local**: the report content is uploaded to the presenter’s IPFS node, and its CID plus reviewer decision are recorded on a local Hardhat blockchain. Three configured reviewer wallets vote; two matching votes make a report `Verified` or `Rejected`.

This prototype does **not** monitor live network traffic, determine maliciousness automatically, or block IP addresses on other websites. A separate service would need to read the verified reports and decide what action to take. Use synthetic data only: IPFS report content is public to anyone who can retrieve its CID.

## Architecture

| Part | Role in the demo |
| --- | --- |
| Next.js frontend | Submit a report and show IPFS and on-chain results |
| Express backend | Sends the report JSON to the local Kubo IPFS node and returns its CID |
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
npm run dev
```

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

The local reviewers are the three addresses in `blockchain/ignition/params/31337-v2.json`. For this local-only demo, their private keys are printed by the Hardhat node and can be imported into MetaMask on the presenter’s computer. Do not paste those keys into this README, chat, slides, or use them on a public network. The report submitter must be a different wallet from the reviewers.

## Short presentation script

**English:** “ThreatIntelDApp is a prototype for sharing and reviewing threat reports. Report details are stored on IPFS, while the blockchain stores the content identifier and the review result. Three designated reviewers vote, and two matching votes are required to mark a report verified or rejected. This local demo does not monitor live traffic or block other systems; it demonstrates how applications could share and verify threat intelligence.”

**Hinglish:** “ThreatIntelDApp threat reports ko share aur review karne ka prototype hai. Report ki details IPFS par rehti hain, aur blockchain par uska CID aur review result record hota hai. Teen reviewers mein se do same decision dein tab report Verified ya Rejected hoti hai. Yeh local demo live traffic monitor ya kisi doosri app ko block nahi karta—yeh dikhata hai ki apps verified threat intelligence kaise share kar sakti hain.”

## Common questions

- **Why use IPFS?** It stores the report outside the contract and gives the content a CID. The CID lets the app retrieve the same content; it is not encryption or a privacy guarantee.
- **Why use a blockchain?** It provides a shared, tamper-evident record of submitted CIDs and reviewer decisions.
- **Who decides a report is verified?** The contract’s three configured reviewer wallets; two approve votes verify, and two reject votes reject.
- **Does it detect or block attackers by itself?** No. Reports are submitted by people in this prototype. A separate consuming login service could read verified intelligence and apply its own rules.
- **Is this already a public DApp?** The demonstrated version uses a local blockchain and the presenter’s IPFS node. Other people cannot rely on it being available over the public internet yet.

## Older prototype features

The dashboard also contains earlier MongoDB, demo-login, alert, restriction, and V1 registry features. They are separate legacy/demo flows and are not the source of truth for the V2 decentralized report-review demonstration. For the class presentation, focus on **V2 registry** and **Decentralized reports**.

## Project folders

```text
frontend/    Next.js dashboard and MetaMask integration
backend/     Express API, MongoDB-backed legacy demo routes, and local IPFS upload endpoint
blockchain/  Hardhat contracts, including ThreatReportRegistryV2
```
