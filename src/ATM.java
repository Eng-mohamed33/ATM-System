import java.io.Console;
import java.util.List;
import java.util.Scanner;

/** Console front end. All rules and security checks live in {@link Bank}. */
public class ATM {
    private static final Scanner scanner = new Scanner(System.in);
    private static boolean warnedVisiblePin = false;
    private static Bank bank;

    public static void main(String[] args) {
        try {
            bank = new Bank(Bank.defaultDir());
        } catch (Exception e) {
            System.out.println("Cannot start: " + e.getMessage());
            return;
        }
        System.out.println("=================================");
        System.out.println("        JAVA CONSOLE ATM          ");
        System.out.println("=================================");

        String first = bank.takeBootstrapPin();
        if (first != null) {
            System.out.println("\nFIRST RUN - administrator account created.");
            System.out.println("Card: 0000   Temporary PIN: " + first);
            System.out.println("This PIN is shown ONCE and must be changed at first login.");
        }

        while (true) {
            System.out.println("\n1. Login\n2. Exit");
            int choice = readInt("Choose: ");
            if (choice == 1) login();
            else if (choice == 2) { System.out.println("Goodbye."); break; }
            else System.out.println("Invalid choice.");
        }
    }

    private static void login() {
        String card = readText("Card number: ");
        char[] pin = readPin("PIN: ");
        try {
            Bank.Session s = bank.login(card, pin);
            if (bank.mustChangePin(s)) {
                System.out.println("You must change your temporary PIN before continuing.");
                if (!changePin(s)) { bank.logout(s); return; }
            }
            if (s.admin) adminMenu(s); else customerMenu(s);
            bank.logout(s);
        } catch (Bank.BankException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void customerMenu(Bank.Session s) {
        while (true) {
            System.out.println("\n--- Welcome, " + bank.displayName(s) + " ---");
            System.out.println("1. Check Balance\n2. Withdraw\n3. Deposit\n4. Transfer\n5. Change PIN\n6. Transaction History\n7. Logout");
            int choice = readInt("Choose: ");
            if (!bank.isActive(s)) { System.out.println("Session timed out. Please log in again."); return; }
            try {
                switch (choice) {
                    case 1: System.out.println("Current balance: " + bank.balance(s)); break;
                    case 2: { long c = readAmount("Withdrawal amount: ", false); if (c >= 0) { bank.withdraw(s, c); System.out.println("Withdrawal successful. Balance: " + bank.balance(s)); } break; }
                    case 3: { long c = readAmount("Deposit amount: ", false); if (c >= 0) { bank.deposit(s, c); System.out.println("Deposit successful. Balance: " + bank.balance(s)); } break; }
                    case 4: {
                        String to = readText("Recipient card number: ");
                        long c = readAmount("Transfer amount: ", false);
                        if (c >= 0) { bank.transfer(s, to, c); System.out.println("Transfer successful."); }
                        break;
                    }
                    case 5: changePin(s); break;
                    case 6: showList("Transaction history:", bank.history(s)); break;
                    case 7: return;
                    default: System.out.println("Invalid choice.");
                }
            } catch (Bank.BankException e) {
                System.out.println(e.getMessage());
                if (!bank.isActive(s)) return;
            } catch (RuntimeException e) {
                System.out.println("Unexpected error. The last operation may not have been saved.");
            }
        }
    }

    private static void adminMenu(Bank.Session s) {
        while (true) {
            System.out.println("\n--- Admin Dashboard ---");
            System.out.println("1. List Accounts\n2. Create Account\n3. Delete Account\n4. View Account History\n5. Reset Customer PIN\n6. Change PIN\n7. Logout");
            int choice = readInt("Choose: ");
            if (!bank.isActive(s)) { System.out.println("Session timed out. Please log in again."); return; }
            try {
                switch (choice) {
                    case 1: showList("Accounts:", bank.listAccounts(s)); break;
                    case 2: createAccount(s); break;
                    case 3: {
                        String card = readText("Card number to delete: ");
                        if (readText("Type DELETE to confirm: ").equals("DELETE")) { bank.deleteAccount(s, card); System.out.println("Account deleted."); }
                        else System.out.println("Cancelled.");
                        break;
                    }
                    case 4: showList("Transaction history:", bank.accountHistory(s, readText("Card number: "))); break;
                    case 5: {
                        String temp = bank.resetPin(s, readText("Card number: "));
                        System.out.println("Temporary PIN: " + temp + "  (shown once; customer must change it at next login)");
                        break;
                    }
                    case 6: changePin(s); break;
                    case 7: return;
                    default: System.out.println("Invalid choice.");
                }
            } catch (Bank.BankException e) {
                System.out.println(e.getMessage());
                if (!bank.isActive(s)) return;
            } catch (RuntimeException e) {
                System.out.println("Unexpected error. The last operation may not have been saved.");
            }
        }
    }

    private static void createAccount(Bank.Session s) throws Bank.BankException {
        String card = readText("New card number (4-16 digits): ");
        String name = readText("Customer name: ");
        char[] pin = readPin("Initial PIN (4 digits): ");
        long balance = readAmount("Initial balance: ", true);
        if (balance < 0) { System.out.println("Cancelled."); return; }
        bank.createAccount(s, card, name, pin, balance);
        System.out.println("Account created. The customer must change the PIN at first login.");
    }

    /** Returns true if the PIN was changed. */
    private static boolean changePin(Bank.Session s) {
        char[] current = readPin("Current PIN: ");
        char[] fresh = readPin("New PIN (4 digits): ");
        char[] confirm = readPin("Confirm new PIN: ");
        try {
            if (!java.util.Arrays.equals(fresh, confirm)) { System.out.println("PINs do not match."); return false; }
            bank.changePin(s, current, fresh);
            System.out.println("PIN changed successfully.");
            return true;
        } catch (Bank.BankException e) {
            System.out.println(e.getMessage());
            return false;
        } finally {
            java.util.Arrays.fill(confirm, '\0');
        }
    }

    private static void showList(String title, List<String> lines) {
        System.out.println("\n" + title);
        if (lines.isEmpty()) System.out.println("(none)");
        for (String l : lines) System.out.println(l);
    }

    // ---- input helpers --------------------------------------------------------------------
    private static String readText(String prompt) {
        System.out.print(prompt);
        if (!scanner.hasNextLine()) { System.out.println(); System.exit(0); }
        return scanner.nextLine().trim();
    }

    private static char[] readPin(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] p = console.readPassword("%s", prompt);
            if (p == null) System.exit(0);
            return p;
        }
        if (!warnedVisiblePin) {
            System.out.println("(No secure console detected: PIN entry will be visible. Run from a real terminal.)");
            warnedVisiblePin = true;
        }
        return readText(prompt).toCharArray();
    }

    private static int readInt(String prompt) {
        while (true) {
            try { return Integer.parseInt(readText(prompt)); }
            catch (NumberFormatException e) { System.out.println("Enter a valid number."); }
        }
    }

    /** Returns cents, or -1 if the user entered nothing (cancel). */
    private static long readAmount(String prompt, boolean allowZero) {
        while (true) {
            String t = readText(prompt + "(blank to cancel) ");
            if (t.isEmpty()) return -1;
            try { return Bank.parseAmount(t, allowZero); }
            catch (Bank.BankException e) { System.out.println(e.getMessage()); }
        }
    }
}
