
---

## 🎖️ The Master Manual: Setup, Navigation, and Identity (2026)

### 1. How Identity Works (The "Owner" Logic)

When you ran `dfx deploy`, the terminal told you it was creating a "default" identity.

* **The Principal ID:** Your "account" is actually a long string of characters called a **Principal ID**.
* **The PEM File:** Your identity is stored in a hidden file on your Ubuntu WSL at `~/.config/dfx/identity/default/identity.pem`. This file contains your **Private Key**.
* **Cryptographic Proof:** When you run a command, `dfx` uses that private key to "sign" the message. The blockchain checks the signature and says, "Yep, this matches the owner of this canister."

### 2. Moving Your Account to Another Device

Since your identity is tied to that local `.pem` file, you won't be "logged in" automatically on a new laptop. You have two ways to "login" elsewhere:

#### **Method A: The Seed Phrase (Recommended)**

When you first created your identity, `dfx` gave you a **Seed Phrase** (e.g., *weird leader agent...*).

1. On the **new device**, install `dfx`.
2. Run: `dfx identity import my-account`
3. Paste your seed phrase when prompted.
4. Run: `dfx identity use my-account`

#### **Method B: Copying the PEM File**

1. Copy the `identity.pem` file from your current Ubuntu WSL to a USB drive.
2. Paste it into the same folder (`~/.config/dfx/identity/default/`) on the new machine.

---

### 🚀 3. Creating a New Workspace (The "Factory" Flow)

You don't need to reinstall anything to start a new project. Just use the "Generator":

1. **Open VS Code** and ensure you are connected to **WSL: Ubuntu**.
2. **Navigate to your project root:** `cd ~/ic-projects`.
3. **Generate:** `dfx new <new_project_name>`.
* Select **Motoko** (Backend) and **React** (Frontend).


4. **Initialize:** `cd <new_project_name> && npm install`.

---

### 📂 4. Navigating and Editing Files

To find your code in the Linux file system:

1. In VS Code, go to **File > Open Folder**.
2. Type: `/home/helcurt/ic-projects/<project_name>`.
3. **Target Files:**
* **Backend:** `src/<project_name>_backend/main.mo` (Logic and Database).
* **Frontend:** `src/<project_name>_frontend/src/App.tsx` (React UI).



---

### 🛡️ 5. The "Persistent Counter" Logic

In `main.mo`, use the `stable` keyword to ensure your data survives code updates:

```motoko
actor {
  stable var count : Nat = 0; // Stays on the blockchain forever!

  public func greet(name : Text) : async Text {
    count += 1;
    return "Yo " # name # "! Visitor count: " # debug_show(count);
  };
}

```

---

### 🚢 6. The Deployment Pipeline

1. **Local (Testing):** `dfx deploy` (Runs on 127.0.0.1:4943).
2. **Public (Mainnet):** `dfx deploy --network ic`. This makes your app **publicly hosted** on the global internet, accessible by anyone via a `.icp0.io` URL.

---
