import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/** Self-contained checks for the security controls. Run: java -cp out BankTest (see README). */
public class BankTest {
    static int passed = 0, failed = 0;

    static void check(String name, boolean ok) {
        if (ok) { passed++; System.out.println("  PASS  " + name); }
        else { failed++; System.out.println("  FAIL  " + name); }
    }

    interface Op { void run() throws Exception; }

    static String fails(Op op) {
        try { op.run(); return null; } catch (Exception e) { return e.getMessage(); }
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("atm-test");
        Bank bank = new Bank(dir);
        String adminPin = bank.takeBootstrapPin();

        System.out.println("Secrets / bootstrap");
        check("bootstrap PIN issued once", adminPin != null && adminPin.matches("\\d{4}") && bank.takeBootstrapPin() == null);
        String data = new String(Files.readAllBytes(dir.resolve("accounts.dat")), StandardCharsets.UTF_8);
        check("PIN stored as PBKDF2 hash, not plaintext", data.contains("\t120000:") && !data.contains("\t" + adminPin + "\t"));
        check("data file has HMAC trailer", data.contains("\nMAC\t"));

        System.out.println("Authentication");
        check("wrong PIN gives generic message", "Invalid card number or PIN.".equals(fails(() -> bank.login("0000", "9999".toCharArray()))));
        check("unknown card gives same message", "Invalid card number or PIN.".equals(fails(() -> bank.login("7777", "1357".toCharArray()))));
        Bank.Session admin = bank.login("0000", adminPin.toCharArray());
        check("temp PIN must be changed before admin ops", fails(() -> bank.listAccounts(admin)) != null);
        check("weak PIN rejected (sequential)", fails(() -> bank.changePin(admin, adminPin.toCharArray(), "1234".toCharArray())) != null);
        check("weak PIN rejected (repeated)", fails(() -> bank.changePin(admin, adminPin.toCharArray(), "1111".toCharArray())) != null);
        check("PIN change needs correct current PIN", fails(() -> bank.changePin(admin, "0001".toCharArray(), "2468".toCharArray())) != null);
        bank.changePin(admin, adminPin.toCharArray(), "2846".toCharArray());
        check("admin ops allowed after PIN change", fails(() -> bank.listAccounts(admin)) == null);

        System.out.println("Authorization");
        bank.createAccount(admin, "1111", "Ahmed", "7391".toCharArray(), 500000);
        bank.createAccount(admin, "2222", "Sara", "8264".toCharArray(), 100000);
        Bank.Session ahmed = bank.login("1111", "7391".toCharArray());
        check("new customer must change admin-set PIN first", fails(() -> bank.balance(ahmed)) != null);
        bank.changePin(ahmed, "7391".toCharArray(), "5827".toCharArray());
        check("customer can read own balance", "5000.00".equals(bank.balance(ahmed)));
        check("customer cannot list accounts", fails(() -> bank.listAccounts(ahmed)) != null);
        check("customer cannot create accounts", fails(() -> bank.createAccount(ahmed, "3333", "X", "9182".toCharArray(), 999999)) != null);
        check("customer cannot delete accounts", fails(() -> bank.deleteAccount(ahmed, "2222")) != null);
        check("customer cannot read others' history", fails(() -> bank.accountHistory(ahmed, "2222")) != null);
        check("customer cannot reset others' PIN", fails(() -> bank.resetPin(ahmed, "2222")) != null);
        check("admin cannot withdraw", fails(() -> bank.withdraw(admin, 100)) != null);
        check("transfer to admin account refused", fails(() -> bank.transfer(ahmed, "0000", 100)) != null);
        check("transfer to self refused", fails(() -> bank.transfer(ahmed, "1111", 100)) != null);
        check("transfer to unknown card refused", fails(() -> bank.transfer(ahmed, "9999", 100)) != null);
        check("admin account cannot be deleted", fails(() -> bank.deleteAccount(admin, "0000")) != null);

        System.out.println("Money handling");
        for (String bad : new String[] {"Infinity", "NaN", "-5", "1e3", "0", "10.999", "abc", "", "9999999999", "1000001"})
            check("amount rejected: '" + bad + "'", fails(() -> Bank.parseAmount(bad, false)) != null);
        check("amount accepted: 150.5 -> 15050 cents", Bank.parseAmount("150.5", false) == 15050);
        bank.deposit(ahmed, 2550);
        check("exact cents arithmetic", "5025.50".equals(bank.balance(ahmed)));
        check("overdraft refused", fails(() -> bank.withdraw(ahmed, 10_000_000)) != null);
        bank.transfer(ahmed, "2222", 2000);
        Bank.Session sara = bank.login("2222", "8264".toCharArray());
        bank.changePin(sara, "8264".toCharArray(), "6413".toCharArray());
        check("transfer credited recipient", "1020.00".equals(bank.balance(sara)));

        System.out.println("Rate limiting");
        bank.withdraw(ahmed, 300_000);       // 3000 + 20 transferred = 3020 outgoing
        check("daily limit enforced", fails(() -> bank.withdraw(ahmed, 250_000)) != null);
        for (int i = 0; i < 3; i++) fails(() -> bank.login("2222", "0000".toCharArray()));
        String locked = fails(() -> bank.login("2222", "6413".toCharArray()));
        check("3 failures lock the card (even with correct PIN)", locked != null && locked.startsWith("Too many failed attempts"));
        check("lockout survives restart", fails(() -> new Bank(dir).login("2222", "6413".toCharArray())).startsWith("Too many"));
        for (int i = 0; i < 3; i++) fails(() -> bank.login("7777", "0000".toCharArray()));
        String ghost = fails(() -> bank.login("7777", "1357".toCharArray()));
        check("unknown cards throttled identically (no enumeration)", ghost != null && ghost.startsWith("Too many"));
        check("admin sees LOCKED flag", bank.listAccounts(admin).toString().contains("LOCKED"));
        String temp = bank.resetPin(admin, "2222");
        check("admin reset clears lock and forces PIN change", fails(() -> bank.login("2222", temp.toCharArray())) == null);

        System.out.println("Sessions");
        Bank.Session s2 = bank.login("1111", "5827".toCharArray());
        s2.lastActivity -= Bank.IDLE_TIMEOUT_MS + 1000;
        check("idle session times out", fails(() -> bank.balance(s2)) != null && !bank.isActive(s2));
        Bank.Session s3 = bank.login("1111", "5827".toCharArray());
        bank.logout(s3);
        check("logged-out session unusable", fails(() -> bank.balance(s3)) != null);
        Bank.Session s4 = bank.login("1111", "5827".toCharArray());
        bank.deleteAccount(admin, "1111");
        check("deleted account's session is dead", fails(() -> bank.balance(s4)) != null);

        System.out.println("Integrity & audit");
        String audit = new String(Files.readAllBytes(dir.resolve("audit.log")), StandardCharsets.UTF_8);
        check("audit log records lockout + admin actions", audit.contains("LOCKOUT") && audit.contains("ACCOUNT_DELETED"));
        check("audit log has no PINs and masks cards", !audit.contains("5827") && !audit.contains("6413") && !audit.contains("1111 |"));
        Path f = dir.resolve("accounts.dat");
        String text = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
        Files.write(f, text.replaceFirst("\t0\t0\t0\t", "\t1\t0\t0\t").getBytes(StandardCharsets.UTF_8));
        Files.write(f, (text.replace("ATMDATA\t1", "ATMDATA\t2")).getBytes(StandardCharsets.UTF_8));
        check("tampered data file refused at startup", fails(() -> new Bank(dir)) != null);
        try {
            check("data dir not group/world accessible",
                    Files.getPosixFilePermissions(dir).stream().noneMatch(p -> p.name().startsWith("GROUP") || p.name().startsWith("OTHERS")));
        } catch (UnsupportedOperationException e) { System.out.println("  SKIP  POSIX perms (non-POSIX FS)"); }

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
