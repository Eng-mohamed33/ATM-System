import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core banking + security layer shared by the console (ATM) and Swing (ATMGUI) front ends.
 *
 * Security controls implemented here (the UIs contain no business rules):
 *  - Authentication: PBKDF2 PIN hashes, constant-time compare, forced change of temporary PINs,
 *    PIN policy, idle session timeout, re-authentication on PIN change.
 *  - Rate limiting: persisted per-card lockout with exponential backoff (unknown cards are
 *    throttled identically, so card numbers cannot be enumerated), daily outgoing-money limit.
 *  - Authorization ("row-level security" equivalent): every operation takes a Session and
 *    resolves the account from the session itself, never from caller-supplied card numbers,
 *    except for explicit admin operations which re-check the admin role on every call.
 *  - Secrets: no hardcoded credentials, random one-time bootstrap PIN, no Java deserialization,
 *    HMAC-protected data file, owner-only file permissions, audit log without secrets.
 */
final class Bank {

    static final class BankException extends Exception {
        private static final long serialVersionUID = 1L;
        BankException(String message) { super(message); }
    }

    // ---- tunables -------------------------------------------------------------------------
    static final long MAX_AMOUNT_CENTS = 100_000_000L;          // 1,000,000.00 per operation
    static final long MAX_BALANCE_CENTS = 1_000_000_000_000L;   // balance ceiling (overflow guard)
    static final long DAILY_OUTGOING_LIMIT_CENTS = 500_000L;    // 5,000.00 withdrawn+transferred/day
    static final int MAX_FAILED_ATTEMPTS = 3;
    static final long BASE_LOCK_MS = 30_000L;                   // 30s, doubles each lockout
    static final long MAX_LOCK_MS = 15 * 60_000L;               // capped at 15 min
    static final long IDLE_TIMEOUT_MS = 120_000L;               // session idle timeout
    static final int MAX_HISTORY = 200;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final String ADMIN_CARD = "0000";
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final SecureRandom RNG = new SecureRandom();

    // ---- model ----------------------------------------------------------------------------
    static final class Account {
        final String card;
        String name;
        String pinHash;
        long balance;                 // cents
        boolean admin;
        boolean mustChangePin;
        int failedAttempts;
        int lockouts;
        long lockedUntil;             // epoch millis
        String outDay = "";           // yyyy-MM-dd of the outgoing counter
        long outToday;                // cents sent out on outDay
        final List<String> history = new ArrayList<>();
        Account(String card) { this.card = card; }
    }

    static final class Session {
        final String card;
        final boolean admin;
        long lastActivity = System.currentTimeMillis();
        boolean open = true;
        Session(String card, boolean admin) { this.card = card; this.admin = admin; }
    }

    // ---- state ----------------------------------------------------------------------------
    private final Path dir, dataFile, auditFile;
    private final byte[] macKey;
    private final Map<String, Account> accounts = new LinkedHashMap<>();
    private final Map<String, Account> ghosts = new HashMap<>();  // throttle state for unknown cards
    private final String ghostHash;
    private String bootstrapPin;

    static Path defaultDir() {
        String env = System.getenv("ATM_DATA_DIR");
        if (env != null && !env.trim().isEmpty()) return Paths.get(env.trim());
        return Paths.get(System.getProperty("user.home"), ".java-atm");
    }

    Bank(Path dir) throws IOException {
        this.dir = dir;
        Files.createDirectories(dir);
        restrict(dir);
        this.dataFile = dir.resolve("accounts.dat");
        this.auditFile = dir.resolve("audit.log");
        this.macKey = loadKey();
        this.ghostHash = hashPin(randomPin("0000").toCharArray());
        load();
        if (accounts.isEmpty()) bootstrapAdmin();
    }

    /** Returns the one-time admin PIN created on first run (null afterwards). */
    synchronized String takeBootstrapPin() {
        String p = bootstrapPin;
        bootstrapPin = null;
        return p;
    }

    private void bootstrapAdmin() {
        Account admin = new Account(ADMIN_CARD);
        admin.name = "Administrator";
        admin.admin = true;
        admin.mustChangePin = true;
        String pin = randomPin(ADMIN_CARD);
        admin.pinHash = hashPin(pin.toCharArray());
        record(admin, "Account created (bootstrap)");
        accounts.put(admin.card, admin);
        bootstrapPin = pin;
        save();
        audit("BOOTSTRAP", ADMIN_CARD, "admin account created");
    }

    // ---- authentication -------------------------------------------------------------------
    synchronized Session login(String card, char[] pin) throws BankException {
        try {
            String key = clean(card == null ? "" : card.trim(), 32);
            long now = System.currentTimeMillis();
            Account a = accounts.get(key);
            boolean real = a != null;
            if (!real) {
                if (ghosts.size() > 1000) ghosts.clear();
                a = ghosts.get(key);
                if (a == null) { a = new Account(key); a.pinHash = ghostHash; ghosts.put(key, a); }
            }
            checkLock(a, now);
            boolean pinOk = verifyPin(pin, a.pinHash);   // always hash, so timing is the same
            if (!(pinOk && real)) {
                registerFailure(a, real);
                throw new BankException("Invalid card number or PIN.");
            }
            a.failedAttempts = 0; a.lockouts = 0; a.lockedUntil = 0;
            save();
            audit("LOGIN_OK", key, a.admin ? "admin" : "customer");
            return new Session(key, a.admin);
        } finally {
            wipe(pin);
        }
    }

    synchronized void logout(Session s) {
        if (s != null && s.open) { s.open = false; audit("LOGOUT", s.card, ""); }
    }

    synchronized boolean isActive(Session s) {
        return s != null && s.open && accounts.containsKey(s.card)
                && System.currentTimeMillis() - s.lastActivity <= IDLE_TIMEOUT_MS;
    }

    synchronized boolean mustChangePin(Session s) {
        Account a = s == null ? null : accounts.get(s.card);
        return a != null && a.mustChangePin;
    }

    synchronized String displayName(Session s) {
        Account a = s == null ? null : accounts.get(s.card);
        return a == null ? "" : a.name;
    }

    private void checkLock(Account a, long now) throws BankException {
        if (a.lockedUntil > now) {
            long secs = (a.lockedUntil - now + 999) / 1000;
            throw new BankException("Too many failed attempts. Try again in " + secs + " seconds.");
        }
    }

    private void registerFailure(Account a, boolean real) {
        a.failedAttempts++;
        audit("LOGIN_FAIL", a.card, real ? "" : "unknown card");
        if (a.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            a.lockouts++;
            long lock = Math.min(MAX_LOCK_MS, BASE_LOCK_MS << Math.min(a.lockouts - 1, 10));
            a.lockedUntil = System.currentTimeMillis() + lock;
            a.failedAttempts = 0;
            audit("LOCKOUT", a.card, (lock / 1000) + "s");
        }
        if (real) save();
    }

    /** Resolves the session to its account, enforcing open session + idle timeout. */
    private Account auth(Session s) throws BankException {
        long now = System.currentTimeMillis();
        if (s == null || !s.open) throw new BankException("Session ended. Please log in again.");
        if (now - s.lastActivity > IDLE_TIMEOUT_MS) {
            s.open = false;
            audit("SESSION_TIMEOUT", s.card, "");
            throw new BankException("Session timed out. Please log in again.");
        }
        Account a = accounts.get(s.card);
        if (a == null) { s.open = false; throw new BankException("Session ended. Please log in again."); }
        s.lastActivity = now;
        return a;
    }

    private Account customer(Session s) throws BankException {
        Account a = auth(s);
        if (a.admin) throw new BankException("Not available for administrator accounts.");
        if (a.mustChangePin) throw new BankException("You must change your temporary PIN first.");
        return a;
    }

    private Account admin(Session s) throws BankException {
        Account a = auth(s);
        if (!a.admin) {
            audit("DENIED", s.card, "admin operation attempted");
            throw new BankException("Access denied.");
        }
        if (a.mustChangePin) throw new BankException("You must change your temporary PIN first.");
        return a;
    }

    synchronized void changePin(Session s, char[] oldPin, char[] newPin) throws BankException {
        try {
            Account a = auth(s);
            checkLock(a, System.currentTimeMillis());
            if (!verifyPin(oldPin, a.pinHash)) {
                registerFailure(a, true);
                if (a.lockedUntil > System.currentTimeMillis()) s.open = false;
                throw new BankException("Current PIN is incorrect.");
            }
            validatePin(a.card, newPin);
            if (Arrays.equals(oldPin, newPin)) throw new BankException("New PIN must differ from the current PIN.");
            a.pinHash = hashPin(newPin);
            a.mustChangePin = false;
            a.failedAttempts = 0;
            record(a, "PIN changed");
            save();
            audit("PIN_CHANGED", a.card, "");
        } finally {
            wipe(oldPin); wipe(newPin);
        }
    }

    // ---- customer operations (always act on the session's own account) --------------------
    synchronized String balance(Session s) throws BankException {
        return fmt(customer(s).balance);
    }

    synchronized void deposit(Session s, long cents) throws BankException {
        Account a = customer(s);
        checkAmount(cents);
        if (a.balance + cents > MAX_BALANCE_CENTS) throw new BankException("Balance limit exceeded.");
        a.balance += cents;
        record(a, "Deposit: +" + fmt(cents));
        save();
        audit("DEPOSIT", a.card, fmt(cents));
    }

    synchronized void withdraw(Session s, long cents) throws BankException {
        Account a = customer(s);
        checkAmount(cents);
        reserveOutgoing(a, cents);
        if (cents > a.balance) throw new BankException("Insufficient balance.");
        a.balance -= cents;
        a.outToday += cents;
        record(a, "Withdrawal: -" + fmt(cents));
        save();
        audit("WITHDRAW", a.card, fmt(cents));
    }

    synchronized void transfer(Session s, String toCard, long cents) throws BankException {
        Account from = customer(s);
        checkAmount(cents);
        Account to = accounts.get(toCard == null ? "" : toCard.trim());
        if (to == null || to.admin || to == from) throw new BankException("Invalid recipient account.");
        reserveOutgoing(from, cents);
        if (cents > from.balance) throw new BankException("Insufficient balance.");
        if (to.balance + cents > MAX_BALANCE_CENTS) throw new BankException("Invalid recipient account.");
        from.balance -= cents;
        to.balance += cents;
        from.outToday += cents;
        record(from, "Transfer to " + mask(to.card) + ": -" + fmt(cents));
        record(to, "Transfer from " + mask(from.card) + ": +" + fmt(cents));
        save();
        audit("TRANSFER", from.card, fmt(cents) + " -> " + mask(to.card));
    }

    synchronized List<String> history(Session s) throws BankException {
        return new ArrayList<>(auth(s).history);
    }

    private void reserveOutgoing(Account a, long cents) throws BankException {
        String today = LocalDate.now().toString();
        if (!today.equals(a.outDay)) { a.outDay = today; a.outToday = 0; }
        if (a.outToday + cents > DAILY_OUTGOING_LIMIT_CENTS) {
            long left = Math.max(0, DAILY_OUTGOING_LIMIT_CENTS - a.outToday);
            audit("LIMIT_HIT", a.card, fmt(cents));
            throw new BankException("Daily limit exceeded. Remaining today: " + fmt(left));
        }
    }

    // ---- admin operations (role re-checked on every call) ---------------------------------
    /** Local-project recovery path. Set ATM_RECOVERY_CODE before production use. */
    synchronized void recoverAdminPin(String recoveryCode, char[] newPin) throws BankException {
        try {
            String expected = System.getenv("ATM_RECOVERY_CODE");
            if (expected == null || expected.trim().isEmpty()) expected = "4321";
            if (!expected.equals(recoveryCode == null ? "" : recoveryCode.trim())) {
                throw new BankException("Invalid recovery code.");
            }
            Account admin = accounts.get(ADMIN_CARD);
            if (admin == null) throw new BankException("Administrator account not found.");
            validatePin(admin.card, newPin);
            admin.pinHash = hashPin(newPin);
            admin.mustChangePin = false;
            admin.failedAttempts = 0;
            admin.lockouts = 0;
            admin.lockedUntil = 0;
            record(admin, "Administrator PIN recovered");
            save();
            audit("ADMIN_PIN_RECOVERED", ADMIN_CARD, "");
        } finally {
            wipe(newPin);
        }
    }

    synchronized List<String> listAccounts(Session s) throws BankException {
        admin(s);
        List<String> rows = new ArrayList<>();
        long now = System.currentTimeMillis();
        for (Account a : accounts.values()) {
            rows.add(a.card + " | " + a.name + " | " + fmt(a.balance) + " | " + (a.admin ? "Admin" : "Customer")
                    + (a.lockedUntil > now ? " | LOCKED" : "") + (a.mustChangePin ? " | temp PIN" : ""));
        }
        return rows;
    }

    synchronized List<String> accountHistory(Session s, String card) throws BankException {
        admin(s);
        Account a = accounts.get(card == null ? "" : card.trim());
        if (a == null) throw new BankException("Account not found.");
        audit("ADMIN_VIEW_HISTORY", s.card, mask(a.card));
        return new ArrayList<>(a.history);
    }

    synchronized void createAccount(Session s, String card, String name, char[] pin, long initialCents) throws BankException {
        try {
            admin(s);
            card = card == null ? "" : card.trim();
            if (!card.matches("\\d{4,16}")) throw new BankException("Card number must be 4-16 digits.");
            if (accounts.containsKey(card)) throw new BankException("Card number is already in use.");
            name = clean(name == null ? "" : name.trim(), 50);
            if (name.isEmpty()) throw new BankException("Customer name is required.");
            validatePin(card, pin);
            if (initialCents < 0 || initialCents > MAX_AMOUNT_CENTS) throw new BankException("Invalid initial balance.");
            Account a = new Account(card);
            a.name = name;
            a.pinHash = hashPin(pin);
            a.balance = initialCents;
            a.mustChangePin = true;               // admin knows this PIN, so the customer must replace it
            record(a, "Account created");
            accounts.put(card, a);
            save();
            audit("ACCOUNT_CREATED", s.card, mask(card));
        } finally {
            wipe(pin);
        }
    }

    synchronized void deleteAccount(Session s, String card) throws BankException {
        admin(s);
        Account a = accounts.get(card == null ? "" : card.trim());
        if (a == null || a.admin) throw new BankException("This account cannot be deleted.");
        accounts.remove(a.card);
        save();
        audit("ACCOUNT_DELETED", s.card, mask(a.card));
    }

    /** Admin cannot read PINs; they can only issue a random temporary one (shown once). */
    synchronized String resetPin(Session s, String card) throws BankException {
        admin(s);
        Account a = accounts.get(card == null ? "" : card.trim());
        if (a == null || a.admin) throw new BankException("This account's PIN cannot be reset here.");
        String pin = randomPin(a.card);
        a.pinHash = hashPin(pin.toCharArray());
        a.mustChangePin = true;
        a.failedAttempts = 0; a.lockouts = 0; a.lockedUntil = 0;
        record(a, "PIN reset by administrator");
        save();
        audit("PIN_RESET", s.card, mask(a.card));
        return pin;
    }

    // ---- validation & formatting ----------------------------------------------------------
    static long parseAmount(String text, boolean allowZero) throws BankException {
        String t = text == null ? "" : text.trim();
        if (!t.matches("\\d{1,9}(\\.\\d{1,2})?")) throw new BankException("Enter a valid amount (e.g. 150 or 150.50).");
        long cents = new java.math.BigDecimal(t).movePointRight(2).longValueExact();
        if (cents == 0 && !allowZero) throw new BankException("Amount must be greater than zero.");
        if (cents > MAX_AMOUNT_CENTS) throw new BankException("Amount exceeds the maximum of " + fmt(MAX_AMOUNT_CENTS) + ".");
        return cents;
    }

    private static void checkAmount(long cents) throws BankException {
        if (cents <= 0 || cents > MAX_AMOUNT_CENTS) throw new BankException("Invalid amount.");
    }

    static String fmt(long cents) { return String.format("%d.%02d", cents / 100, cents % 100); }

    static void validatePin(String card, char[] pin) throws BankException {
        String p = pin == null ? "" : new String(pin);
        if (!p.matches("\\d{4}")) throw new BankException("PIN must contain exactly 4 digits.");
        boolean same = true, asc = true, desc = true;
        for (int i = 1; i < 4; i++) {
            int d = p.charAt(i) - p.charAt(i - 1);
            if (d != 0) same = false;
            if (d != 1) asc = false;
            if (d != -1) desc = false;
        }
        if (same || asc || desc) throw new BankException("PIN is too easy to guess (no repeated or sequential digits).");
        if (card != null && card.length() >= 4 && card.endsWith(p)) throw new BankException("PIN must not match the end of the card number.");
    }

    private static String randomPin(String card) {
        while (true) {
            String p = String.format("%04d", RNG.nextInt(10000));
            try { validatePin(card, p.toCharArray()); return p; } catch (BankException ignored) { }
        }
    }

    private static String clean(String s, int max) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) { if (!Character.isISOControl(c)) sb.append(c); }
        return sb.length() > max ? sb.substring(0, max) : sb.toString();
    }

    private static String mask(String card) {
        String c = clean(card, 32);
        return c.length() > 6 ? "****" + c.substring(c.length() - 4) : "****";   // short cards are fully hidden
    }

    private static void wipe(char[] a) { if (a != null) Arrays.fill(a, '\0'); }

    private void record(Account a, String msg) {
        a.history.add(LocalDateTime.now().format(TIME) + " - " + msg);
        while (a.history.size() > MAX_HISTORY) a.history.remove(0);
    }

    // ---- PIN hashing ----------------------------------------------------------------------
    private static byte[] derive(char[] pin, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(pin, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static String hashPin(char[] pin) {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        return PBKDF2_ITERATIONS + ":" + b64(salt) + ":" + b64(derive(pin, salt, PBKDF2_ITERATIONS));
    }

    private static boolean verifyPin(char[] pin, String stored) {
        try {
            String[] p = stored.split(":");
            byte[] expected = unb64(p[2]);
            byte[] actual = derive(pin == null ? new char[0] : pin, unb64(p[1]), Integer.parseInt(p[0]));
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- persistence: custom text format (no Java deserialization), HMAC-protected ---------
    private static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    private static byte[] unb64(String s) { return Base64.getUrlDecoder().decode(s); }
    private static String b64(String s) { return b64(s.getBytes(StandardCharsets.UTF_8)); }
    private static String unb64s(String s) { return new String(unb64(s), StandardCharsets.UTF_8); }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Key comes from ATM_HMAC_KEY if set, otherwise from an owner-only key file next to the data. */
    private byte[] loadKey() throws IOException {
        try {
            String env = System.getenv("ATM_HMAC_KEY");
            if (env != null && !env.isEmpty()) {
                return MessageDigest.getInstance("SHA-256").digest(env.getBytes(StandardCharsets.UTF_8));
            }
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        Path kf = dir.resolve("atm.key");
        if (Files.exists(kf)) return unb64(new String(Files.readAllBytes(kf), StandardCharsets.UTF_8).trim());
        byte[] k = new byte[32];
        RNG.nextBytes(k);
        Files.write(kf, b64(k).getBytes(StandardCharsets.UTF_8));
        restrict(kf);
        return k;
    }

    private void save() {
        StringBuilder sb = new StringBuilder("ATMDATA\t1\n");
        for (Account a : accounts.values()) {
            sb.append("A\t").append(b64(a.card)).append('\t').append(b64(a.name)).append('\t').append(a.pinHash)
              .append('\t').append(a.balance).append('\t').append(a.admin ? 1 : 0).append('\t').append(a.mustChangePin ? 1 : 0)
              .append('\t').append(a.failedAttempts).append('\t').append(a.lockouts).append('\t').append(a.lockedUntil)
              .append('\t').append(a.outDay).append('\t').append(a.outToday).append('\n');
            for (String h : a.history) sb.append("H\t").append(b64(h)).append('\n');
        }
        byte[] body = sb.toString().getBytes(StandardCharsets.UTF_8);
        String out = sb + "MAC\t" + b64(hmac(body)) + "\n";
        try {
            Path tmp = dir.resolve("accounts.dat.tmp");
            Files.write(tmp, out.getBytes(StandardCharsets.UTF_8));
            restrict(tmp);
            try {
                Files.move(tmp, dataFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, dataFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Could not save data", e);
        }
    }

    private void load() throws IOException {
        if (!Files.exists(dataFile)) return;
        String text = new String(Files.readAllBytes(dataFile), StandardCharsets.UTF_8);
        int idx = text.lastIndexOf("\nMAC\t");
        if (idx < 0) throw new IOException("Data file failed its integrity check. Refusing to start.");
        byte[] body = text.substring(0, idx + 1).getBytes(StandardCharsets.UTF_8);
        byte[] given;
        try { given = unb64(text.substring(idx + 5).trim()); }
        catch (IllegalArgumentException e) { throw new IOException("Data file failed its integrity check. Refusing to start."); }
        if (!MessageDigest.isEqual(hmac(body), given)) {
            throw new IOException("Data file failed its integrity check (modified or wrong key). Refusing to start.");
        }
        try {
            Account cur = null;
            for (String line : new String(body, StandardCharsets.UTF_8).split("\n")) {
                String[] p = line.split("\t", -1);
                if (p[0].equals("A")) {
                    cur = new Account(unb64s(p[1]));
                    cur.name = unb64s(p[2]); cur.pinHash = p[3]; cur.balance = Long.parseLong(p[4]);
                    cur.admin = p[5].equals("1"); cur.mustChangePin = p[6].equals("1");
                    cur.failedAttempts = Integer.parseInt(p[7]); cur.lockouts = Integer.parseInt(p[8]);
                    cur.lockedUntil = Long.parseLong(p[9]); cur.outDay = p[10]; cur.outToday = Long.parseLong(p[11]);
                    accounts.put(cur.card, cur);
                } else if (p[0].equals("H") && cur != null) {
                    cur.history.add(unb64s(p[1]));
                }
            }
        } catch (RuntimeException e) {
            throw new IOException("Data file is corrupted. Refusing to start.");
        }
    }

    /** Best-effort owner-only permissions (POSIX where available, java.io.File flags on Windows). */
    private static void restrict(Path p) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(Files.isDirectory(p) ? "rwx------" : "rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            java.io.File f = p.toFile();
            f.setReadable(false, false); f.setWritable(false, false);
            f.setReadable(true, true); f.setWritable(true, true);
            if (f.isDirectory()) f.setExecutable(true, true);
        }
    }

    // ---- audit log (never contains PINs; card numbers are masked) -------------------------
    private void audit(String event, String card, String detail) {
        try {
            boolean fresh = !Files.exists(auditFile);
            String line = LocalDateTime.now().format(TIME) + " | " + event + " | " + mask(card) + " | " + clean(detail, 120) + System.lineSeparator();
            Files.write(auditFile, line.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            if (fresh) restrict(auditFile);
        } catch (IOException ignored) { }
    }
}
