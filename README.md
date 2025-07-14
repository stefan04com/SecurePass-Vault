# 🔐 SecurePass Vault: A Modern Password Manager

## Safeguarding Your Digital Life with Robust Cryptography

SecurePass Vault is a desktop password manager meticulously crafted in Python, designed to provide a secure and intuitive solution for managing your ever-growing collection of digital credentials. Built with a strong emphasis on modern cryptographic practices, it offers both a user-friendly Graphical User Interface (GUI) and a versatile Command-Line Interface (CLI) to ensure your sensitive data remains confidential and uncompromised.

---

## ✨ Core Functionalities & Features

SecurePass Vault offers a comprehensive suite of features to empower users with secure password management:

* **🔒 Secure Profile Initialization:**
    * **Functionality:** Upon the very first launch, the application guides you through a secure setup process to establish your master profile. You define a single, strong master password that acts as the ultimate key to your vault.
    * **Security Insight:** Your master password is never stored directly. Instead, it's used as input for a Cryptographically Secure Key Derivation Function (KDF) to generate a robust encryption key. This design ensures that even if your `profile.json` file were compromised, your master password remains safe from direct exposure.

* **🔑 Robust User Authentication:**
    * **Functionality:** Subsequent logins require successful authentication against your master password.
    * **Security Insight:** To thwart brute-force attacks, the system incorporates a strict limit on consecutive failed login attempts, automatically exiting the application after too many incorrect tries.

* **🛡️ State-of-the-Art Encryption (AES-256 GCM):**
    * **Functionality:** Every password you store within the vault is meticulously encrypted before being written to disk.
    * **Security Insight:** We employ AES-256 in Galois/Counter Mode (GCM), a leading authenticated encryption algorithm. AES-GCM not only ensures the confidentiality of your passwords but also guarantees their integrity and authenticity, preventing any unauthorized tampering or accidental corruption of your data.

* **🌀 Cryptographically Secure Key Derivation (PBKDF2-HMAC-SHA256):**
    * **Functionality:** The master encryption key is derived from your master password using PBKDF2.
    * **Security Insight:** By leveraging PBKDF2-HMAC-SHA256 with a high iteration count (600,000 iterations) and a unique, randomly generated salt for each profile, we dramatically increase the computational cost for attackers attempting to brute-force your master password. This makes precomputation attacks like rainbow tables virtually ineffective.

* **🎲 Dynamic Initialization Vectors (IVs) & Authentication Tags:**
    * **Functionality:** Each individual password encryption operation utilizes a distinct, cryptographically random Initialization Vector (IV).
    * **Security Insight:** The use of unique IVs prevents identical plaintext passwords from yielding identical ciphertexts, adding a crucial layer of security. The authentication tag (an inherent part of GCM) ensures that the encrypted data has not been modified since it was encrypted, providing integrity verification.

* **🗃️ Dual Storage Solutions:**
    * **GUI Version (SQLite):**
        * **Functionality:** The GUI application stores encrypted password entries in a structured SQLite database (`data/vault.db`).
        * **Security Insight:** All interactions with the database are performed using **parameterized queries**. This is a fundamental security practice that completely prevents SQL injection vulnerabilities, a common and dangerous attack vector.
    * **CLI Version (JSON File):**
        * **Functionality:** The Command-Line Interface version provides a lightweight alternative, storing encrypted passwords in a JSON file (`data/passwords.json`).
        * **Important Note:** It's crucial to understand that the GUI and CLI versions utilize *separate* data vaults (`vault.db` vs. `passwords.json`) and do not share password entries. This provides flexibility but means passwords added via one interface will not be immediately visible in the other.

* **✨ Integrated Strong Password Generator (GUI):**
    * **Functionality:** Don't struggle to invent complex passwords! The GUI includes a utility to instantly generate cryptographically strong, random passwords that meet modern security standards.
    * **Security Insight:** These passwords are created using Python's `secrets` module, ensuring true randomness and avoiding predictable patterns, a critical component for strong security.

* **📋 Ephemeral Clipboard Management (GUI):**
    * **Functionality:** When you copy a password to your clipboard, it's automatically cleared after a brief 30-second delay.
    * **Security Insight:** This thoughtful feature minimizes the time sensitive data lingers in your system's clipboard memory, reducing the risk of accidental exposure or malicious access by other applications.

* **⏳ Inactivity Auto-Lock (GUI):**
    * **Functionality:** The GUI application will automatically lock itself and require re-authentication after a predefined period of user inactivity (5 minutes).
    * **Security Insight:** This prevents unauthorized access to your password vault if you step away from your computer while the application is open, adding a crucial layer of physical security.

* **📊 Comprehensive Activity Logging:**
    * **Functionality:** All significant user actions and system events (e.g., login attempts, password additions, deletions) are timestamped and logged to `data/logs.txt`.
    * **Security Insight:** This provides an auditable trail of activity, useful for monitoring usage and detecting any suspicious behavior.

---

## 🔒 Security Deep Dive

The cornerstone of SecurePass Vault's reliability lies in its uncompromising approach to security:

* **Master Key Never Stored:** Your master password is the foundation, but its direct value is never persisted. Instead, a computationally expensive key derivation process produces a cryptographic key, only a hash of which is stored alongside a unique salt. This means even if the `profile.json` file is compromised, an attacker would face the monumental task of brute-forcing a heavily salted and stretched hash.
* **Authentication and Confidentiality Combined:** By choosing AES-GCM, we address not only the secrecy of your passwords but also their integrity. The authentication tag ensures that the encrypted data has not been altered since it was last encrypted, providing a critical defense against tampering.
* **Robust Password Input:** Sensitive inputs like passwords are handled using `getpass` in the CLI and masked input fields in the GUI, preventing them from being displayed on screen or logged in terminal history.

---

## 🚀 Getting Started

Follow these steps to get SecurePass Vault up and running on your local machine.

### Prerequisites

* **Python 3.x:** Ensure you have a compatible version of Python installed.
    ```bash
    python --version
    ```

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/stefan04com/SecurePass-Vault.git](https://github.com/stefan04com/SecurePass-Vault.git)
    cd SecurePass-Vault
    ```
2.  **Install dependencies:** All required Python packages are listed in `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```