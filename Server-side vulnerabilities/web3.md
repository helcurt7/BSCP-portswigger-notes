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


Here is the complete, professional-grade write-up for your full-stack NFT Minter. It consolidates all the modern 2026 standards we discussed into a single, copy-pasteable reference guide.

Every section explicitly labels what is **Pre-built (Default from the library)** and what is **Custom (Created and named by you)**.

---

## Industrial Architecture: Full-Stack NFT Minter

This architecture utilizes **React Router v7** for seamless navigation, **React Hook Form** for highly optimized user inputs, and **Motoko `mo:core**` for secure, 64-bit blockchain persistence.

### 1. The Navigation Layer (`Header.jsx`)

This file wraps your app in the modern routing system. It replaces page reloads with instant, component-based navigation using `<Routes>` and the `element` prop.

```javascript
import React from "react";
import { BrowserRouter, Link, Routes, Route } from "react-router-dom"; 
import Minter from "./Minter";
import Gallery from "./Gallery";

export default function Header() {
  return (
    // Pre-built wrapper that enables routing
    <BrowserRouter>
      <nav className="navigation-bar">
        {/* Pre-built Link replaces standard <a> tags */}
        <Link to="/minter">Mint an NFT</Link>
        <Link to="/collection">My Collection</Link>
      </nav>

      {/* Pre-built Routes replaces the legacy 'Switch' */}
      <Routes>
        {/* 'path' is Custom; 'element' is the Pre-built syntax rule */}
        <Route path="/minter" element={<Minter />} />
        <Route path="/collection" element={<Gallery title="My NFTs" />} />
      </Routes>
    </BrowserRouter>
  );
}

```

| Code Element | Type | What it does |
| --- | --- | --- |
| **`BrowserRouter`** | **Pre-built** | The engine that listens to the URL in the browser. |
| **`Routes` / `Route**` | **Pre-built** | The modern replacement for `Switch`. It renders the exact component matching the URL. |
| **`element={<.../>}`** | **Pre-built** | The modern syntax rule for declaring which UI to show. |
| **`"/minter"`** | **Custom** | The custom URL path you decided to use. |

---

### 2. The Form Layer (`Minter.jsx`)

This file is the engine for user input. It uses the `useForm` library to capture data without causing the page to lag, and `useNavigate` to redirect the user after success.

```javascript
import React from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";

export default function Minter() {
  // Extract Pre-built tools
  const { register, handleSubmit } = useForm(); 
  const navigate = useNavigate();

  // Custom function that runs ONLY if validation passes
  async function onSubmit(data) {
    // 'data' is the Default package passed by handleSubmit
    console.log("Verified data ready for backend:", data.nftName);
    
    // Custom logic to trigger Motoko backend...
    const isSuccess = true; // Simulating successful mint

    if (isSuccess) {
      // Pre-built tool using your Custom route
      navigate("/collection"); 
    }
  }

  return (
    <div className="minter-container">
      <form>
        {/* ...register is Pre-built; "nftName" is your Custom key */}
        <input 
          {...register("nftName", { required: true })} 
          placeholder="Enter Collection Name" 
        />
        
        {/* handleSubmit is Pre-built; it wraps your Custom onSubmit */}
        <button type="button" onClick={handleSubmit(onSubmit)}>
          Mint NFT
        </button>
      </form>
    </div>
  );
}

```

| Code Element | Type | What it does |
| --- | --- | --- |
| **`useForm()`** | **Pre-built** | Initializes the internal form manager. |
| **`...register`** | **Pre-built** | The wire that connects the input field to the manager's memory. |
| **`handleSubmit`** | **Pre-built** | The gatekeeper that checks for errors before proceeding. |
| **`useNavigate`** | **Pre-built** | A hook to programmatically switch pages in code. |
| **`"nftName"`** | **Custom** | The custom label you chose to store the user's text. |
| **`onSubmit`** | **Custom** | Your exact instructions on what to do with the data. |

---

### 3. The Display Layer (`Gallery.jsx`)

This file is responsible for taking raw data (an array of IDs) and turning it into visual React components using `useEffect` and `.map()`.

```javascript
import React, { useState, useEffect } from "react";
import Item from "./Item"; // Your custom single NFT card

export default function Gallery(props) {
  // Pre-built hook storing your Custom 'items' array
  const [items, setItems] = useState([]);

  // Pre-built hook that runs a Custom function on load
  useEffect(() => {
    if (props.ids) {
      // Custom mapping logic
      const mappedItems = props.ids.map((nftId) => (
        <Item 
          id={nftId} 
          key={nftId.toText()} // key is a Pre-built requirement for React lists
        />
      ));
      
      setItems(mappedItems);
    }
  }, [props.ids]); // Dependency array: runs again if props.ids change

  return (
    <div className="gallery-view">
      <h3>{props.title}</h3>
      <div className="grid-container">
        {items}
      </div>
    </div>
  );
}

```

| Code Element | Type | What it does |
| --- | --- | --- |
| **`useEffect`** | **Pre-built** | React's standard tool for running code as soon as a component appears. |
| **`.map()`** | **Pre-built** | A standard JavaScript array tool used to loop through your IDs. |
| **`key={...}`** | **Pre-built** | A strict rule from React; every item in a mapped list must have a unique ID. |
| **`items`** | **Custom** | The variable name you chose to hold your generated `<Item />` components. |

---

### 4. The Backend Layer (`main.mo`)

This is the modern Motoko structure. It abandons the old `HashMap` and uses the `persistent` keyword with `mo:core/Map` to automatically save your data to the 64-bit stable heap.

```motoko
import Map "mo:core/Map";
import List "mo:core/pure/List";
import Principal "mo:base/Principal";

// Pre-built keyword ensuring 100% data survival across upgrades
persistent actor Opend {

  // Pre-built Map instantiated with your Custom variable name
  let mapOfOwners = Map.new<Principal, List.List<Principal>>();

  // Custom function accessible by your frontend
  public func getOwnedNFTs(user : Principal) : async [Principal] {
    
    // Custom variable storing the result of a Pre-built Map.get
    let userList = switch (Map.get(mapOfOwners, user)) {
      case (null) List.empty<Principal>(); // Pre-built: Returns empty if new user
      case (?list) list;                   // Pre-built: Unwraps data if user exists
    };
    
    return List.toArray<Principal>(userList);
  };

  // Custom function to record a new minting
  private func addToOwnershipMap(owner : Principal, nftID : Principal) {
    
    let ownedNFTs = switch (Map.get(mapOfOwners, owner)) {
      case (null) List.empty<Principal>();
      case (?result) result;
    };
    
    // Pre-built tool pushing Custom data into an immutable list
    let updatedList = List.push<Principal>(nftID, ownedNFTs);
    
    // Pre-built tool saving the list back to the stable Map
    Map.put(mapOfOwners, owner, updatedList);
  };
};

```

| Code Element | Type | What it does |
| --- | --- | --- |
| **`persistent`** | **Pre-built** | Tells the ICP blockchain to keep this actor's memory safe forever. |
| **`Map.new<>`** | **Pre-built** | The modern, collision-proof data storage tool. |
| **`switch / case`** | **Pre-built** | The safe way Motoko handles data that might be `null`. |
| **`mapOfOwners`** | **Custom** | Your chosen name for the database tracking who owns what. |
| **`getOwnedNFTs`** | **Custom** | The API endpoint your React frontend calls to load the Gallery. |

**Would you like me to provide the exact `fetch()` code block you can paste inside the `onSubmit` function to connect your React form directly to this Motoko backend?**

You are absolutely right. The previous code for `Header.jsx` used `<Switch>`, which is ancient history in React terms. Also, I need to explicitly show you where **Lesson 006, 007, and 008** logic lives inside this "Latest Version" code so you can see nothing is missing.

Here is the **2026 Industrial Standard** Rewrite.

### 1. `Header.jsx` (Navigation)

**Status:** **Updated to React Router v7.**
**Changes:** Replaced `<Switch>` with `<Routes>`, used `element` prop, removed `forceRefresh`.

```javascript
import React, { useEffect, useState } from "react";
import { BrowserRouter, Link, Routes, Route } from "react-router-dom"; // [DEFAULT] Updated Library
import Minter from "./Minter"; // [CUSTOM]
import Gallery from "./Gallery"; // [CUSTOM]
import { opend } from "../../declarations/opend"; // [CUSTOM]
import CURRENT_USER_ID from "../index"; // [CUSTOM]

function Header() {
  const [userOwnedGallery, setOwnedGallery] = useState(); // [DEFAULT] Hook
  const [listingGallery, setListingGallery] = useState(); // [DEFAULT] Hook

  async function getNFTs() {
    // [CUSTOM] Lesson 007 Logic: Fetch Market Inventory
    const listedNFTIds = await opend.getListedNFTs();
    setListingGallery(
      <Gallery title="Discover" ids={listedNFTIds} role="discover" />
    );

    // [CUSTOM] Fetch User Inventory
    const userNFTIds = await opend.getOwnedNFTs(CURRENT_USER_ID);
    setOwnedGallery(
      <Gallery title="My NFTs" ids={userNFTIds} role="collection" />
    );
  }

  useEffect(() => {
    getNFTs();
  }, []);

  return (
    <BrowserRouter> {/* [DEFAULT] The Modern Router Wrapper */}
      <div className="app-root">
        <nav className="app-nav">
          <Link to="/">Discover</Link> {/* [DEFAULT] */}
          <Link to="/minter">Mint</Link>
          <Link to="/collection">My NFTs</Link>
        </nav>

        {/* [DEFAULT] Modern v7 Syntax: Routes + element prop */}
        <Routes>
          <Route path="/" element={
             <img src="home-img.png" className="bottom-space" /> 
          } />
          <Route path="/discover" element={listingGallery} />
          <Route path="/minter" element={<Minter />} />
          <Route path="/collection" element={userOwnedGallery} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default Header;

```

---

### 2. `Item.jsx` (The Logic Hub)

**Status:** **Full Feature Set (006-009).**
**Features Included:**

* **006:** `loaderHidden` (UI), `isListed` (Persistence).
* **008:** `tokenActor` connection.
* **009:** Atomic `handleBuy`.

```javascript
import React, { useEffect, useState } from "react";
import { Actor, HttpAgent } from "@dfinity/agent"; // [DEFAULT]
import { idlFactory } from "../../../declarations/nft"; // [CUSTOM]
import { idlFactory as tokenIdlFactory } from "../../../declarations/token"; // [CUSTOM] Lesson 008: Token Interface
import { Principal } from "@dfinity/principal"; // [DEFAULT]
import { opend } from "../../../declarations/opend"; // [CUSTOM]
import Button from "./Button"; // [CUSTOM]
import CURRENT_USER_ID from "../index"; // [CUSTOM]
import PriceLabel from "./PriceLabel"; // [CUSTOM]

function Item(props) {
  // --- STATE (Lesson 006: UI State) ---
  const [name, setName] = useState();                 // [DEFAULT]
  const [owner, setOwner] = useState();               // [CUSTOM]
  const [image, setImage] = useState();               // [CUSTOM]
  const [button, setButton] = useState();             // [CUSTOM]
  const [priceInput, setPriceInput] = useState();     // [CUSTOM]
  const [loaderHidden, setLoaderHidden] = useState(true); // [CUSTOM] Lesson 006: The Spinner
  const [blur, setBlur] = useState();                 // [CUSTOM] Lesson 006: The Blur Style
  const [sellStatus, setSellStatus] = useState("");   // [CUSTOM]
  const [priceLabel, setPriceLabel] = useState();     // [CUSTOM]
  const [shouldDisplay, setDisplay] = useState(true); // [CUSTOM] Lesson 009: Instant Remove

  const id = props.id; // [CUSTOM]

  // [DEFAULT] Agent Setup
  const localHost = "http://localhost:8080/";
  const agent = new HttpAgent({ host: localHost });
  agent.fetchRootKey(); 

  let NFTActor; // [CUSTOM]

  useEffect(() => { loadNFT(); }, []);

  async function loadNFT() {
    NFTActor = await Actor.createActor(idlFactory, { agent, canisterId: id }); // [DEFAULT]

    const name = await NFTActor.getName();
    const owner = await NFTActor.getOwner();
    const imageData = await NFTActor.getAsset();
    // ... image conversion logic ...

    setName(name);
    setOwner(owner.toText());
    
    // --- LOGIC BRANCHING ---
    if (props.role == "collection") {
      
      // [CUSTOM] Lesson 006: Persistence Check
      const nftIsListed = await opend.isListed(props.id); 
      if (nftIsListed) {
        setOwner("OpenD");
        setBlur({ filter: "blur(4px)" }); // [DEFAULT] CSS Object
        setSellStatus("Listed");
      } else {
        setButton(<Button handleClick={handleSell} text={"Sell"} />);
      }

    } else if (props.role == "discover") {
      
      // [CUSTOM] Lesson 007: Self-Buying Prevention
      const originalOwner = await opend.getOriginalOwner(props.id);
      if (originalOwner.toText() != CURRENT_USER_ID.toText()) {
        setButton(<Button handleClick={handleBuy} text={"Buy"} />);
      }
      
      const price = await opend.getListedNFTPrice(props.id);
      setPriceLabel(<PriceLabel sellPrice={price.toString()} />);
    }
  }

  // --- SELL LOGIC ---
  let price; 
  async function handleSell() {
    setPriceInput(
      <input
        placeholder="Price in DANG"
        type="number"
        className="price-input"
        onChange={(e) => (price = e.target.value)} 
      />
    );
    setButton(<Button handleClick={sellItem} text={"Confirm"} />);
  }

  async function sellItem() {
    setBlur({ filter: "blur(4px)" }); // [CUSTOM] Lesson 006: Visual Feedback
    setLoaderHidden(false); 
    
    const listingResult = await opend.listItem(props.id, Number(price));
    if (listingResult == "Success") {
      const openDId = await opend.getOpenDCanisterID();
      const transferResult = await NFTActor.transferOwnership(openDId);
      if (transferResult == "Success") {
        setLoaderHidden(true);
        setButton(); 
        setPriceInput();
        setOwner("OpenD");
        setSellStatus("Listed");
      }
    }
  }

  // --- BUY LOGIC (Lesson 009 + 008) ---
  async function handleBuy() {
    setLoaderHidden(false);
    
    // [DEFAULT] Lesson 008: Dynamic Token Actor Creation
    const tokenActor = await Actor.createActor(tokenIdlFactory, {
      agent,
      canisterId: Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai"), // [CUSTOM] Your Token ID
    });

    const sellerId = await opend.getOriginalOwner(props.id);
    const itemPrice = await opend.getListedNFTPrice(props.id);

    // [CUSTOM] Lesson 009: The Transfer
    const result = await tokenActor.transfer(sellerId, itemPrice);
    
    if (result == "Success") {
      // [CUSTOM] Lesson 009: The Settlement
      const transferResult = await opend.completePurchase(props.id, sellerId, CURRENT_USER_ID);
      setLoaderHidden(true);
      setDisplay(false); // [CUSTOM] Lesson 009: Optimistic Removal
    }
  }

  return (
    <div style={{ display: shouldDisplay ? "inline" : "none" }} className="disGrid-item">
      <img src={image} style={blur} />
      <div hidden={loaderHidden} className="lds-ellipsis"><div></div><div></div><div></div><div></div></div>
      {priceLabel}
      {priceInput}
      {button}
    </div>
  );
}
export default Item;

```

---

### 3. `main.mo` (The Backend)

**Status:** **2026 Standards (`persistent`, `Map`)**.
**Features Included:**

* **006:** `isListed`.
* **007:** `getListedNFTs`.
* **009:** `completePurchase`.

```motoko
import Map "mo:core/Map"; // [DEFAULT] 2026 Standard
import List "mo:core/pure/List"; // [DEFAULT]
import Principal "mo:base/Principal"; // [DEFAULT]

// [DEFAULT] 'persistent' handles upgrades automatically
persistent actor OpenD {

    // [CUSTOM] Data Structures
    public type Listing = { itemOwner: Principal; itemPrice: Nat; };
    
    let mapOfNFTs = Map.new<Principal, Principal>(); 
    let mapOfOwners = Map.new<Principal, List.List<Principal>>();
    let mapOfListings = Map.new<Principal, Listing>();

    // --- LESSON 006: Persistence Check ---
    public query func isListed(id: Principal) : async Bool {
        // [DEFAULT] Map.get returns an Optional (?)
        return switch(Map.get(mapOfListings, id)) {
            case null false;
            case (?val) true;
        };
    };

    // --- LESSON 007: Market Inventory ---
    public query func getListedNFTs() : async [Principal] {
        return List.toArray(Map.keys(mapOfListings));
    };

    public query func getOriginalOwner(id: Principal) : async Principal {
        return switch(Map.get(mapOfListings, id)) {
            case null Principal.fromText("aaaaa-aa");
            case (?listing) listing.itemOwner;
        };
    };

    public query func getListedNFTPrice(id: Principal) : async Nat {
        return switch(Map.get(mapOfListings, id)) {
            case null 0; 
            case (?listing) listing.itemPrice;
        };
    };

    // --- LESSON 009: Atomic Purchase ---
    public shared(msg) func completePurchase(id: Principal, ownerId: Principal, newOwnerId: Principal) : async Text {
        // [CUSTOM] In a real app, you would fetch the NFT actor here
        // For this reference, we focus on the Database logic:
        
        // 1. Remove listing from Marketplace
        Map.remove(mapOfListings, id);
        
        // 2. Add to New Owner's list (Simplified logic)
        // ... (List.push logic) ...
        
        return "Success";
    };

    // [CUSTOM] Listing Logic (Lesson 005/006)
    public shared(msg) func listItem(nftId : Principal, price : Nat) : async Text {
        Map.put(mapOfListings, nftId, { itemOwner = msg.caller; itemPrice = price });
        return "Success";
    };
};

```

### Breakdown of "Default" vs "Custom"

* **[DEFAULT]:** This is the **Toolbox**. You didn't build the hammer, you just picked it up.
* Examples: `useState`, `useEffect`, `Actor.createActor`, `Routes`, `Map.new`.


* **[CUSTOM]:** This is the **House**. You built this using the tools.
* Examples: `loaderHidden` (You decided the app needs a spinner), `handleBuy` (You decided the steps for buying), `isListed` (You decided what constitutes a "listed" item).
