## Encrypted File Structure

```
+------------+---------+--------+--------+-------------------+
| MAGIC (8B) | VER (1) | SALT   | IV     | ENCRYPTED DATA    |
+------------+---------+--------+--------+-------------------+
```

### Header Fields

* **MAGIC (8 bytes)**: `AESGCM01` – identifies valid encrypted files
* **VER (1 byte)**: format version (currently `1`)
* **SALT (16 bytes)**: random salt for PBKDF2 key derivation
* **IV (12 bytes)**: random initialization vector for AES-GCM

### Encrypted Payload

* **ENCRYPTED DATA**: file content encrypted using AES-256-GCM
* Includes a **128-bit authentication tag** (GCM) for integrity & authenticity

---

## Cryptography Used

* **Key Derivation**: PBKDF2WithHmacSHA256

  * Salt: 16 bytes
  * Iterations: 100,000
  * Key size: 256-bit

* **Encryption Algorithm**: AES-256

* **Mode**: GCM (Authenticated Encryption)

* **Padding**: NoPadding (handled by GCM)

---

## How It Works (Short)

1. Generate random SALT and IV
2. Derive AES-256 key from password using PBKDF2
3. Write header (MAGIC + VER + SALT + IV)
4. Encrypt file data in streaming mode
5. GCM tag verifies password correctness and detects tampering
