## 🚀 Master Manual: ICP Full-Stack Development & Canister Architecture

**Focus:** Motoko Backend, `dfx.json` Configuration, and React Frontend Integration.

This guide consolidates the "razor-sharp" logic we've discussed. It covers the flow from the CLI configuration to the automated JavaScript bridge, ensuring your "sleeper build" project has a professional, airtight foundation.

---

## 1. The Blueprint: `dfx.json` Configuration

The `dfx.json` file is the "brain" of your project. The `dfx` tool uses this file to understand your architecture. If a canister isn't here, the CLI won't recognize it.

### Adding a Custom Canister (The Workflow)

If you want to add a new backend (e.g., a **Token** canister) alongside your default app, you must manually declare it.

```json
{
  "canisters": {
    "my_app_backend": {
      "main": "src/my_app_backend/main.mo",
      "type": "motoko"
    },
    "my_app_frontend": {
      "dependencies": ["my_app_backend"],
      "source": ["src/my_app_frontend/dist"],
      "type": "assets"
    },
    // 🚩 YOUR NEW CUSTOM CANISTER (Manually Added)
    "token": {
      "main": "src/token/main.mo",
      "type": "motoko"
    }
  }
}

```

---

## 2. The "Empty Shell" Flow (Manual Creation)

While `dfx deploy` is the "all-in-one" command, advanced scenarios (CTFs, DAOs, or hardcoding IDs) require the **Manual Lifecycle**.

### Step-by-Step Commands:

1. **Create the Folder & File:**
```bash
mkdir src/token && touch src/token/main.mo

```


2. **Create the Shell (Reserve the ID):**
*This looks at `dfx.json`, finds "token", and creates an identity on the local ledger.*
```bash
dfx canister create token

```


3. **Get the Canister ID:**
```bash
dfx canister id token

```


4. **The Manual Lifecycle (Under the Hood):**
```bash
dfx build token            # Compiles Motoko to WebAssembly (Wasm)
dfx canister install token  # Injects Wasm into the empty shell

```



---

## 3. Deployment Strategy: "Nuke" vs. "Sniper"

Don't waste time rebuilding your entire React frontend when you only changed one line of Motoko.

| Method | Command | Use Case |
| --- | --- | --- |
| **The "Nuke"** | `dfx deploy` | First-time setup or full sync to Mainnet. |
| **The "Sniper"** | `dfx deploy token` | Rapidly testing backend logic; skips the slow frontend build. |

> **Note:** The name used in the terminal **must** match the lowercase key defined in `dfx.json`.

---

## 4. The Bridge: From Motoko to React

This is the most critical realization: **The `dfx` tool ignores your Motoko Actor name.** * **In Motoko:** You might name your actor `actor Token { ... }`.

* **In `dfx.json`:** You named the canister `token`.
* **In React:** You **must** import using the `dfx.json` name.

### The Automated Declarations

When you run `dfx deploy`, the tool generates a `declarations` folder. This is your **Auto-Generated API Documentation**.

```javascript
// 🚩 CORRECT: Import using the lowercase name from dfx.json
import { token } from "../../declarations/token";

async function checkBalance() {
  // The 'token' object here is the JavaScript bridge to your Motoko backend
  const balance = await token.getBalance(); 
  console.log("Balance is:", balance);
}

```

---

## 5. Summary Checklist for your "Military Order"

1. **Define** the canister in `dfx.json`.
2. **Create** the corresponding `.mo` file in the `src` folder.
3. **Deploy** using the "Sniper" method (`dfx deploy <name>`).
4. **Import** the lowercase generated declaration into your React components.

---

"Steady lah," you've successfully mapped the entire data flow from the CLI config straight into the frontend. You're no longer just "copy-pasting"—you're architecting.

**Would you like me to provide the React integration code for the Plug Wallet now, so we can replace those hardcoded Principal IDs with real-time authentication?**


"Wa biang," you are absolutely right, bro. My apologies. I gave you the polished core but left out the massive foundation you had already built. If you are going to use this as your true "Zero to Master" reference manual for your upcoming Hackathons, it needs to be the *complete* bible. No missing chapters, no fragmented notes.

Here is the **Ultimate 2026 Master Manual**, fully consolidated. It combines your entire setup workflow, identity logic, React frontend architecture, advanced DAO concepts, and the updated EOP 2026 Motoko standard into one massive, copy-pasteable document.

---

# 🎖️ The Ultimate 2026 ICP Hackathon Master Manual

## 🛠️ Phase 1: Environment, Navigation, & The "Factory" Flow

### 1. Connecting to WSL (Your Hacker Workspace)

The Internet Computer (`dfx`) requires a Linux environment.

1. Open **Windows Terminal** and select your **Ubuntu** profile.
2. Navigate to your projects root: `cd ~/ic-projects`.
3. Open VS Code attached to Linux: `code .` (Ensure it says **"WSL: Ubuntu"** in the bottom left).

### 2. Creating a New Workspace

Do not create files manually. Let `dfx` generate the factory.

1. **Generate:** `dfx new <new_project_name>`
* Select **Motoko** (Backend) and **React** (Frontend).


2. **Initialize:** `cd <new_project_name> && npm install`

### 3. Navigating the Files

* **Backend Logic & Database:** `src/<project_name>_backend/main.mo`
* **Frontend UI:** `src/<project_name>_frontend/src/App.jsx` (or `.tsx`)

### 4. Command Reference Cheat Sheet

Use these commands to manage the full-stack lifecycle.

| Goal | Command | Description |
| --- | --- | --- |
| **Start Engine** | `dfx start --background --clean` | Starts local blockchain replica. `--clean` fixes state errors. |
| **Deploy App** | `dfx deploy` | Compiles Backend & Frontend, generates Declarations, and uploads. |
| **Local Dev** | `npm run dev` | Starts Vite server (Port 5173) for quick UI changes without redeploying. |
| **Build Prod** | `npm run build` | Compiles React code into static HTML/JS for mainnet hosting. |
| **Check Wallet** | `dfx canister call <name> checkBalance` | Manually executes a backend function via terminal. |

---

## 🔐 Phase 2: Identity & The "Owner" Logic

Think of **Identity** as the "Person" and the **Principal ID** as the "Passport Number" the blockchain uses to recognize that person.

### 1. The Three Types of Accounts

| Account | Identity Name | Command to find Principal ID |
| --- | --- | --- |
| **Super Account (You)** | `default` (or your dev name) | `dfx identity get-principal` |
| **Canister Account (The Robot)** | `token` (canister name) | `dfx canister id token` |
| **Normal User (Customer)** | `any_other_name` | `dfx identity get-principal` |

### 2. How Identity Works Under the Hood

* **The PEM File:** Your identity is stored in a hidden file on your Ubuntu WSL at `~/.config/dfx/identity/default/identity.pem`. This is your **Private Key**.
* **Cryptographic Proof:** When you run `dfx deploy`, `dfx` uses this private key to sign the message, proving to the blockchain you are the owner.

### 3. Moving Your Account to a New Device

You won't be "logged in" automatically on a new laptop.

* **Method A (Seed Phrase - Recommended):** Run `dfx identity import my-account`, paste your seed phrase, then `dfx identity use my-account`.
* **Method B (PEM File):** Copy the `identity.pem` file from your current WSL to a USB, and paste it into the exact same folder path on the new machine.

---

## 💾 Phase 3: The 2026 Backend Meta (EOP & Smart Contracts)

DFINITY has completely overhauled memory. We no longer use `HashMap` or `preupgrade`/`postupgrade` hooks. We use **Enhanced Orthogonal Persistence (EOP)** and `mo:core/Map` to create a hacker-proof, auto-saving database.

### The DANG Token & Faucet Canister (`main.mo`)

Here is your core backend. It uses `shared(msg)` to identify callers, and `persistent actor` to ensure the ledger survives all upgrades automatically.

```motoko
import Map "mo:core/Map";
import Principal "mo:base/Principal";

persistent actor Token {

  // 1. The Ledger (Using the new B-Tree backed Map)
  var balances = Map.empty<Principal, Nat>();

  // 2. The Super Account (Hardcoded Genesis Owner)
  // REPLACE WITH: dfx identity get-principal
  let owner : Principal = Principal.fromText("gbdev-your-super-account-id-here");
  
  // 3. Genesis: Give ALL 1 Billion tokens to Owner on deploy
  public func install() {
    balances := Map.put(balances, owner, 1_000_000_000);
  };

  // --- HELPER: Get Balance ---
  public query func balanceOf(who : Principal) : async Nat {
    switch (Map.get(balances, who)) {
      case null 0;
      case (?amount) amount;
    };
  };

  // --- FEATURE 1: Transfer (User to User) ---
  public shared(msg) func transfer(to : Principal, amount : Nat) : async Text {
    let sender = msg.caller; 
    let senderBalance = await balanceOf(sender);
    
    if (senderBalance < amount) {
      return "Wa biang! Not enough money lah.";
    };

    let newSenderBalance = senderBalance - amount;
    balances := Map.put(balances, sender, newSenderBalance);

    let receiverBalance = await balanceOf(to);
    balances := Map.put(balances, to, receiverBalance + amount);

    return "Success! Sent " # debug_show(amount) # " DANG.";
  };

  // --- FEATURE 2: The Faucet (ATM) ---
  public shared(msg) func claimFaucet() : async Text {
    let user = msg.caller;
    let faucetAmount = 10_000;
    let canisterId = Principal.fromActor(this); // The ATM's own ID

    let atmBalance = await balanceOf(canisterId);
    if (atmBalance < faucetAmount) {
      return "Alamak! The ATM is empty. Ask the owner to refill!";
    };

    balances := Map.put(balances, canisterId, atmBalance - faucetAmount);
    let userBalance = await balanceOf(user);
    balances := Map.put(balances, user, userBalance + faucetAmount);

    return "Huat ah! You got 10,000 DANG!";
  };
}

```

### The "Missing Link": Funding the ATM

You must manually move funds from your Super Account to the Canister so the Faucet has money to give out.

1. Find Canister ID: `dfx canister id token`
2. Run Transfer:
```bash
dfx canister call token transfer '(principal "PASTE-CANISTER-ID-HERE", 500_000_000)'

```



---

## 🌉 Phase 4: The Frontend Bridge (React Architecture)

The app uses a **Client-Server architecture** bridged by the `HttpAgent`. The frontend imports the backend canister as a JavaScript object using `declarations`.

### The Data Flow Logic

* **READ Flow (Fetching Data):** Runs immediately on load (`useEffect`). It asks the blockchain for data (Fast, Read-Only).
* **WRITE Flow (Executing Transactions):** Runs on form submit. Uses `await` to pause code until the blockchain consensus is finalized (Takes 1-2s). State must be re-synced immediately after.

### The React UI (`App.jsx`)

```javascript
import React, { useState, useEffect } from "react";
import { token } from "../../declarations/token"; 
import { Principal } from "@dfinity/principal"; 

function App() {
  const [myBalance, setMyBalance] = useState("0");
  const [recipientId, setRecipientId] = useState("");
  const [myPrincipalId, setMyPrincipalId] = useState("Loading...");

  useEffect(() => {
    async function loadIdentity() {
      // In a real app, integrate Plug wallet or Internet Identity here
      const principal = await window.ic.plug.getPrincipal(); 
      setMyPrincipalId(principal.toText());
      updateBalance(principal);
    }
    loadIdentity();
  }, []);

  async function updateBalance(principalId) {
    const bal = await token.balanceOf(principalId);
    setMyBalance(bal.toString());
  }

  async function handleClaim() {
    const result = await token.claimFaucet(); 
    alert(result); 
    updateBalance(Principal.fromText(myPrincipalId));
  }

  async function handleTransfer() {
    const recipient = Principal.fromText(recipientId);
    const amount = 500; 
    const result = await token.transfer(recipient, amount);
    alert(result);
    updateBalance(Principal.fromText(myPrincipalId));
  }

  return (
    <div style={{ padding: "20px" }}>
      <h1>DANG Token App</h1>
      <p><strong>My ID:</strong> {myPrincipalId}</p>
      <p><strong>My Balance:</strong> {myBalance} DANG</p>
      <hr />
      <h2>1. Get Free Coins</h2>
      <button onClick={handleClaim}>Gimme Gimme (Claim 10,000)</button>
      <hr />
      <h2>2. Pay a Friend</h2>
      <input 
        type="text" 
        placeholder="Paste Friend's Principal ID" 
        value={recipientId}
        onChange={(e) => setRecipientId(e.target.value)}
      />
      <button onClick={handleTransfer}>Send 500 DANG</button>
    </div>
  );
}

export default App;

```

---

## 🛸 Phase 5: Advanced Meta (DAOs & The Nuke Option)

### 1. What is a DAO? (The "Robot Boss")

A Decentralized Autonomous Organization (DAO) is a company run by code. There is no manager. If you turn your DANG token into a DAO:

1. **Stake:** Users lock DANG into a "Neuron" to get voting power.
2. **Propose:** Someone submits a code update.
3. **Vote:** Users vote Yes/No.
4. **Execute:** If it passes >51%, the canister automatically upgrades itself.
*See it live at:* `nns.ic0.app`

### 2. The "Black Hole" (The Nuke Option)

**⚠️ WARNING: THIS IS PERMANENT.** Blackholing removes you as the owner. You can never update your code again. If there is a bug, the app is dead forever. This proves to users you cannot "rug pull" them.

1. Add the Black Hole as controller:
```bash
dfx canister update-settings --all --add-controller e3mmv-5qaaa-aaaah-qcdvq-cai

```


2. Remove yourself:
```bash
dfx canister update-settings --all --remove-controller YOUR_PRINCIPAL_ID

```



*Verification:* Run `dfx canister info token`. If you try to run `dfx deploy`, it will reject you. The code is now immutable.

---

"Steady lah," *this* is the complete picture. From spinning up WSL, setting up your cryptographic identity, writing hacker-proof EOP databases, connecting a React UI, and nuking the controllers.

Everything you pasted is integrated and modernized. **Would you like me to walk through how to actually integrate that Plug Wallet in React so you don't have to rely on hardcoded IDs anymore?**
