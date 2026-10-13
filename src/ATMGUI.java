import javax.swing.*;
import java.awt.*;
import java.util.List;

/** Swing front end. All rules and security checks live in {@link Bank}. */
public class ATMGUI extends JFrame {
    private interface Action { void run() throws Bank.BankException; }

    private final Bank bank;
    private final JPanel mainPanel = new JPanel(new BorderLayout(15, 15));
    private Bank.Session session;

    public ATMGUI(Bank bank) {
        this.bank = bank;
        setTitle("Java ATM System");
        setSize(520, 430);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        // Idle timeout: bounce back to the login screen when the session expires.
        new Timer(5000, e -> {
            if (session != null && !bank.isActive(session)) {
                bank.logout(session);
                session = null;
                showLogin();
                message("Session timed out. Please log in again.");
            }
        }).start();
        showLogin();
    }

    // ---- screens --------------------------------------------------------------------------
    private void showLogin() {
        mainPanel.removeAll();
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(8, 8, 8, 8);
        c.fill = GridBagConstraints.HORIZONTAL;
        JLabel title = new JLabel("ATM LOGIN", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 24));
        JTextField cardField = new JTextField(15);
        JPasswordField pinField = new JPasswordField(15);
        JButton loginButton = new JButton("Login");
        JButton forgotButton = new JButton("Forgot Admin PIN?");
        JButton exitButton = new JButton("Exit");
        addRow(form, c, 0, title, null);
        addRow(form, c, 1, new JLabel("Card Number:"), cardField);
        addRow(form, c, 2, new JLabel("PIN:"), pinField);
        JPanel buttons = new JPanel();
        buttons.add(loginButton);
        buttons.add(forgotButton);
        buttons.add(exitButton);
        addRow(form, c, 3, buttons, null);

        loginButton.addActionListener(e -> {
            try {
                session = bank.login(cardField.getText(), pinField.getPassword());
                pinField.setText("");
                if (bank.mustChangePin(session) && !forcePinChange()) {
                    bank.logout(session);
                    session = null;
                    showLogin();
                    return;
                }
                if (session.admin) showAdminMenu(); else showCustomerMenu();
            } catch (Bank.BankException ex) {
                pinField.setText("");
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Login Failed", JOptionPane.ERROR_MESSAGE);
            }
        });
        getRootPane().setDefaultButton(loginButton);
        forgotButton.addActionListener(e -> recoverAdminPin());
        exitButton.addActionListener(e -> System.exit(0));
        mainPanel.add(form, BorderLayout.CENTER);
        refresh();
    }

    private void showCustomerMenu() {
        mainPanel.removeAll();
        JLabel title = new JLabel("Welcome, " + bank.displayName(session), SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 22));
        JPanel buttons = new JPanel(new GridLayout(4, 2, 10, 10));
        addButton(buttons, "Check Balance", () -> message("Current balance: " + bank.balance(session)));
        addButton(buttons, "Withdraw", this::withdraw);
        addButton(buttons, "Deposit", this::deposit);
        addButton(buttons, "Transfer", this::transfer);
        addButton(buttons, "Change PIN", this::changePin);
        addButton(buttons, "Transaction History", () -> showList("Transaction History", bank.history(session)));
        addButton(buttons, "Logout", this::logout);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));
        mainPanel.add(title, BorderLayout.NORTH);
        mainPanel.add(buttons, BorderLayout.CENTER);
        refresh();
    }

    private void showAdminMenu() {
        mainPanel.removeAll();
        JLabel title = new JLabel("Admin Dashboard", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 22));
        JPanel buttons = new JPanel(new GridLayout(4, 2, 10, 10));
        addButton(buttons, "List Accounts", () -> showList("Accounts", bank.listAccounts(session)));
        addButton(buttons, "Create Account", this::createAccount);
        addButton(buttons, "Delete Account", this::deleteAccount);
        addButton(buttons, "View Account History", () -> {
            String card = ask("Enter card number:");
            if (card != null) showList("Transaction History", bank.accountHistory(session, card));
        });
        addButton(buttons, "Reset Customer PIN", this::resetPin);
        addButton(buttons, "Change PIN", this::changePin);
        addButton(buttons, "Logout", this::logout);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));
        mainPanel.add(title, BorderLayout.NORTH);
        mainPanel.add(buttons, BorderLayout.CENTER);
        refresh();
    }

    // ---- actions --------------------------------------------------------------------------
    private void recoverAdminPin() {
        String code = ask("Recovery code:");
        if (code == null) return;
        char[][] pins = askPins("New admin PIN (4 digits):", "Confirm new PIN:");
        if (pins == null) return;
        try {
            if (!java.util.Arrays.equals(pins[0], pins[1])) throw new Bank.BankException("PINs do not match.");
            bank.recoverAdminPin(code, pins[0]);
            message("Admin PIN reset successfully. You can now log in.");
        } catch (Bank.BankException ex) {
            message(ex.getMessage());
        } finally {
            java.util.Arrays.fill(pins[0], '\0');
            java.util.Arrays.fill(pins[1], '\0');
        }
    }

    private void withdraw() throws Bank.BankException {
        Long cents = askAmount("Withdrawal amount:", false);
        if (cents == null) return;
        bank.withdraw(session, cents);
        message("Withdrawal successful.");
    }

    private void deposit() throws Bank.BankException {
        Long cents = askAmount("Deposit amount:", false);
        if (cents == null) return;
        bank.deposit(session, cents);
        message("Deposit successful.");
    }

    private void transfer() throws Bank.BankException {
        String to = ask("Recipient card number:");
        if (to == null) return;
        Long cents = askAmount("Transfer amount:", false);
        if (cents == null) return;
        bank.transfer(session, to, cents);
        message("Transfer successful.");
    }

    private void changePin() throws Bank.BankException {
        char[][] pins = askPins("Current PIN:", "New PIN (4 digits):", "Confirm new PIN:");
        if (pins == null) return;
        if (!java.util.Arrays.equals(pins[1], pins[2])) {
            java.util.Arrays.fill(pins[0], '\0'); java.util.Arrays.fill(pins[1], '\0'); java.util.Arrays.fill(pins[2], '\0');
            throw new Bank.BankException("PINs do not match.");
        }
        java.util.Arrays.fill(pins[2], '\0');
        bank.changePin(session, pins[0], pins[1]);
        message("PIN changed successfully.");
    }

    /** Loops until the temporary PIN is replaced; returns false if the user gives up. */
    private boolean forcePinChange() {
        message("You must change your temporary PIN before continuing.");
        while (bank.isActive(session) && bank.mustChangePin(session)) {
            char[][] pins = askPins("Current (temporary) PIN:", "New PIN (4 digits):", "Confirm new PIN:");
            if (pins == null) return false;
            try {
                if (!java.util.Arrays.equals(pins[1], pins[2])) throw new Bank.BankException("PINs do not match.");
                bank.changePin(session, pins[0], pins[1]);
            } catch (Bank.BankException ex) {
                message(ex.getMessage());
            }
        }
        return bank.isActive(session);
    }

    private void createAccount() throws Bank.BankException {
        String card = ask("New card number (4-16 digits):");
        if (card == null) return;
        String name = ask("Customer name:");
        if (name == null) return;
        char[][] pin = askPins("Initial PIN (4 digits):");
        if (pin == null) return;
        Long balance = askAmount("Initial balance:", true);
        if (balance == null) { java.util.Arrays.fill(pin[0], '\0'); return; }
        bank.createAccount(session, card, name, pin[0], balance);
        message("Account created. The customer must change the PIN at first login.");
    }

    private void deleteAccount() throws Bank.BankException {
        String card = ask("Card number to delete:");
        if (card == null) return;
        if (JOptionPane.showConfirmDialog(this, "Permanently delete this account?", "Confirm", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        bank.deleteAccount(session, card);
        message("Account deleted.");
    }

    private void resetPin() throws Bank.BankException {
        String card = ask("Card number:");
        if (card == null) return;
        String temp = bank.resetPin(session, card);
        message("Temporary PIN: " + temp + "\nShown once. The customer must change it at next login.");
    }

    private void logout() {
        bank.logout(session);
        session = null;
        showLogin();
    }

    // ---- dialogs & helpers ----------------------------------------------------------------
    private void addButton(JPanel panel, String text, Action action) {
        JButton button = new JButton(text);
        button.addActionListener(e -> {
            try {
                action.run();
            } catch (Bank.BankException ex) {
                message(ex.getMessage());
                if (session != null && !bank.isActive(session)) { session = null; showLogin(); }
            } catch (RuntimeException ex) {
                message("Unexpected error. The last operation may not have been saved.");
            }
        });
        panel.add(button);
    }

    private String ask(String prompt) { return JOptionPane.showInputDialog(this, prompt); }

    private Long askAmount(String prompt, boolean allowZero) throws Bank.BankException {
        String v = ask(prompt);
        return v == null ? null : Long.valueOf(Bank.parseAmount(v, allowZero));
    }

    /** Masked PIN prompts; returns null if cancelled. */
    private char[][] askPins(String... labels) {
        JPanel p = new JPanel(new GridLayout(labels.length, 2, 6, 6));
        JPasswordField[] fields = new JPasswordField[labels.length];
        for (int i = 0; i < labels.length; i++) {
            fields[i] = new JPasswordField(10);
            p.add(new JLabel(labels[i]));
            p.add(fields[i]);
        }
        if (JOptionPane.showConfirmDialog(this, p, "PIN", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return null;
        char[][] out = new char[labels.length][];
        for (int i = 0; i < labels.length; i++) out[i] = fields[i].getPassword();
        return out;
    }

    private void showList(String title, List<String> lines) {
        StringBuilder text = new StringBuilder();
        if (lines.isEmpty()) text.append("(none)");
        for (String l : lines) text.append(l).append('\n');
        JTextArea area = new JTextArea(text.toString(), 14, 44);
        area.setEditable(false);
        JOptionPane.showMessageDialog(this, new JScrollPane(area), title, JOptionPane.INFORMATION_MESSAGE);
    }

    private void message(String text) { JOptionPane.showMessageDialog(this, text); }

    private void addRow(JPanel panel, GridBagConstraints c, int row, Component left, Component right) {
        c.gridy = row; c.gridx = 0; c.gridwidth = right == null ? 2 : 1;
        panel.add(left, c);
        if (right != null) { c.gridx = 1; c.gridwidth = 1; panel.add(right, c); }
    }

    private void refresh() { mainPanel.revalidate(); mainPanel.repaint(); setContentPane(mainPanel); }

    public static void main(String[] args) {
        final Bank bank;
        try {
            bank = new Bank(Bank.defaultDir());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Cannot start: " + e.getMessage(), "ATM", JOptionPane.ERROR_MESSAGE);
            return;
        }
        SwingUtilities.invokeLater(() -> {
            new ATMGUI(bank).setVisible(true);
            String first = bank.takeBootstrapPin();
            if (first != null) {
                JTextField f = new JTextField("Card: 0000    Temporary PIN: " + first);
                f.setEditable(false);
                JOptionPane.showMessageDialog(null, new Object[] {
                        "FIRST RUN - administrator account created.\nThis PIN is shown ONCE and must be changed at first login.", f },
                        "Administrator credentials", JOptionPane.INFORMATION_MESSAGE);
            }
        });
    }
}
