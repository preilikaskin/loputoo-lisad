# A04:2025 Cryptographic Failures — Agent Instructions

## Category
OWASP Top 10:2025 A04 — Cryptographic Failures (formerly A02:2021)
Covers weak cryptography, missing encryption, hardcoded keys, insecure hash algorithms.

## CWE List
- CWE-261: Weak Encoding for Password
- CWE-296: Improper Following of a Certificate's Chain of Trust
- CWE-310: Cryptographic Issues
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-322: Key Exchange without Entity Authentication
- CWE-323: Reusing a Nonce, Key Pair in Encryption
- CWE-324: Use of a Key Past its Expiration Date
- CWE-325: Missing Cryptographic Step
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-328: Use of Weak Hash
- CWE-329: Generation of Predictable IV with CBC Mode
- CWE-330: Use of Insufficiently Random Values
- CWE-331: Insufficient Entropy
- CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator
- CWE-336: Same Seed in Pseudo-Random Number Generator
- CWE-337: Predictable Seed in Pseudo-Random Number Generator
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
- CWE-340: Generation of Predictable Numbers or Identifiers
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-523: Unprotected Transport of Credentials
- CWE-720: OWASP Top Ten 2007 Category A9
- CWE-757: Selection of Less-Secure Algorithm During Negotiation
- CWE-759: Use of a One-Way Hash without a Salt
- CWE-760: Use of a One-Way Hash with a Predictable Salt
- CWE-780: Use of RSA Algorithm without OAEP
- CWE-818: Insufficient Transport Layer Protection
- CWE-916: Use of Password Hash With Insufficient Computational Effort

## Search Patterns (grep)
### Group 1: Weak algorithms (CWE-326, 327, 328, 916)
- `md5|MD5|sha1|SHA1|SHA-1|des|DES|rc4|RC4`
- `createHash|createCipher|createDecipher`
- `bcrypt|scrypt|argon2|pbkdf2|PBKDF2` (verify presence — if found, mark as Info; if absent where password hashing occurs, mark as TP)

### Group 2: Hardcoded keys/secrets (CWE-321, 330, 338)
- `secret.*=.*['"]|key.*=.*['"]|password.*=.*['"]`
- `Math\.random` (CWE-338 — weak PRNG; note: `crypto.randomBytes` and `uuid` v4 are secure alternatives, do not flag those as vulnerabilities)
- `iv.*=.*['"]|nonce.*=.*['"]|salt.*=.*['"]`

### Group 3: Transport/storage (CWE-319, 523, 818)
- `http://|HTTP` (cleartext transport — high false-positive rate; only flag when sensitive data is actually transmitted, ignore documentation URLs, comments, and non-sensitive API references)
- `cleartext|plain.*text|unencrypted`
- `localStorage|sessionStorage` (sensitive data in browser)

## Output Format
Return a table:
```
| # | File | Line | CWE | Vulnerability description | Severity | TP/FP/Info |
|---|------|------|-----|--------------------------|----------|------------|
| 1 | lib/insecurity.ts | 23 | CWE-328 | MD5 hash used for password hashing | High | TP |
```

At the end of the summary, include:
- Total findings: X
- TP: X, FP: X, Info: X  
- High: X, Medium: X, Low: X, Info: X
