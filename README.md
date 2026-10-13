# Java ATM (Console + Swing GUI)

Java 8+. Both front ends share one core (`Bank.java`) that holds every business and security rule.

## Build & run (PowerShell)

```powershell
javac -encoding UTF-8 -d out src\*.java
java -cp out ATM        # console
java -cp out ATMGUI     # GUI
```

Tests (security controls):

```powershell
javac -encoding UTF-8 -d out src\*.java test\BankTest.java
java -cp out BankTest
```

## First run

There are **no default accounts or PINs**. On first start an administrator (card `0000`) is created with a
random temporary PIN that is printed **once**. You must change it at first login.
Admin creates customers; customers must change the admin-set PIN at first login.
Lost admin PIN: delete the data folder (this wipes all accounts).

## Where data lives

`%USERPROFILE%\.java-atm\` (override with env var `ATM_DATA_DIR`): `accounts.dat`, `atm.key`, `audit.log`.
Console and GUI now share the same accounts. Never commit this folder (see `.gitignore`).
Optional: set `ATM_HMAC_KEY` to keep the integrity key out of the data folder.

## Security controls

| Area | What is implemented |
|---|---|
| Authentication | PINs hashed with PBKDF2-HMAC-SHA256 (120k iterations, per-PIN salt), constant-time compare, PIN policy (4 digits, no repeated/sequential, not the card's last digits), current PIN required to change PIN, temporary PINs force a change, 2-minute idle session timeout, masked PIN input |
| Rate limiting | 3 failed PINs lock the card for 30s, doubling each time up to 15 min; lock state is saved to disk (restart does not reset it); unknown card numbers are throttled the same way and return the same generic error (no card enumeration); daily outgoing limit (withdraw + transfer) of 5,000.00; per-operation max of 1,000,000.00 |
| Authorization (RLS-style) | There is no SQL database, so "row-level security" is enforced in code: customer operations take a `Session` and only ever touch the session's own account (no card number parameter to tamper with); admin operations re-check the admin role on every call; admins cannot move money or read PINs; transfers to admin accounts are refused; deleted accounts' sessions die immediately; the console no longer allows anonymous account creation |
| Secrets | No credentials in source or data files; no Java deserialization (custom text format); data file is HMAC-protected and the app refuses to start if it was modified; owner-only file permissions (best effort on Windows); audit log never contains PINs and masks card numbers; money stored as integer cents (no floating point) |

## Known limits (be honest in your report)

- Someone with full access to your user profile (data folder **and** key file) can still rebuild a valid data
  file. The HMAC detects accidental/casual tampering, not a determined local attacker. Use `ATM_HMAC_KEY` for more.
- 4-digit PINs are only 10,000 combinations; the lockout is what protects them.
- Lockout means an attacker who knows a card number can lock that card temporarily (and the admin card `0000`).
- Old `accounts.dat` / `gui_accounts.dat` from the previous version stored PINs in plain text and are not
  compatible. Delete them, and if they were ever pushed to GitHub, treat those PINs as burned.
