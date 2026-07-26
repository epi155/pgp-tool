package com.example.pgp.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

public class PasswordDialog extends JDialog {
    private JPasswordField passwordField;
    private JPasswordField confirmField;
    private JCheckBox showCheckBox;
    private JCheckBox protectCb;
    private boolean confirmed = false;
    private Mode mode;
    private JLabel statusLabel;
    private JButton okBtn;

    public enum Mode { REQUEST, CREATE }

    public PasswordDialog(Frame owner, String hint) {
        this(owner, null, hint, Mode.REQUEST);
    }

    public PasswordDialog(Frame owner, String hint, Mode mode) {
        this(owner, null, hint, mode);
    }

    public PasswordDialog(Frame owner, String hint, Mode mode, String title) {
        this(owner, null, hint, mode);
        setTitle(title);
    }

    public PasswordDialog(Frame owner, String uidText, String keyIdText, Mode mode) {
        super(owner, mode == Mode.CREATE ? "Create encryption password" : "Enter private key password", true);
        this.mode = mode;
        setLayout(new BorderLayout(10, 10));

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        if (uidText != null) {
            String escaped = uidText
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\n", "<br>");
            String html = "<html><div style='width:400px; font-size:9px; color:gray'>"
                    + escaped
                    + "</div></html>";
            JLabel uidLabel = new JLabel(html);
            JPanel uidPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            uidPanel.add(uidLabel);
            content.add(uidPanel, BorderLayout.NORTH);
        }

        JPanel fieldsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 5, 5);

        int row = 0;
        if (mode == Mode.CREATE) {
            protectCb = new JCheckBox("Protect the key with a password", true);
            gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
            gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
            fieldsPanel.add(protectCb, gbc);
            gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
            row++;
        }

        gbc.gridx = 0; gbc.gridy = row;
        fieldsPanel.add(new JLabel("Password for " + keyIdText + ":"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        passwordField = new JPasswordField(20);
        fieldsPanel.add(passwordField, gbc);
        row++;

        if (mode == Mode.CREATE) {
            gbc.gridx = 0; gbc.gridy = row;
            gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
            fieldsPanel.add(new JLabel("Confirm:"), gbc);
            gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
            confirmField = new JPasswordField(20);
            fieldsPanel.add(confirmField, gbc);
            row++;

            showCheckBox = new JCheckBox("Show password");
            gbc.gridx = 1; gbc.gridy = row;
            gbc.weightx = 1; gbc.fill = GridBagConstraints.NONE;
            fieldsPanel.add(showCheckBox, gbc);
            row++;
        }

        statusLabel = new JLabel(" ");
        statusLabel.setForeground(Color.RED.darker());
        if (mode == Mode.CREATE) {
            gbc.gridx = 1; gbc.gridy = row;
            gbc.weightx = 1;
            fieldsPanel.add(statusLabel, gbc);
        }

        content.add(fieldsPanel, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        okBtn = new JButton("OK");
        JButton cancelBtn = new JButton("Cancel");
        buttons.add(okBtn);
        buttons.add(cancelBtn);
        content.add(buttons, BorderLayout.SOUTH);

        add(content);

        okBtn.setEnabled(mode != Mode.CREATE);

        okBtn.addActionListener(e -> {
            if (mode == Mode.CREATE && (protectCb == null || protectCb.isSelected())) {
                char[] p1 = passwordField.getPassword();
                char[] p2 = confirmField.getPassword();
                if (p1.length == 0 || p2.length == 0) return;
                if (!java.util.Arrays.equals(p1, p2)) return;
            }
            confirmed = true;
            dispose();
        });
        cancelBtn.addActionListener(e -> dispose());

        if (mode == Mode.CREATE) {
            KeyAdapter validator = new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    updateCreateState();
                }
            };
            passwordField.addKeyListener(validator);
            confirmField.addKeyListener(validator);

            showCheckBox.addActionListener(e -> {
                boolean show = showCheckBox.isSelected();
                passwordField.setEchoChar(show ? (char) 0 : '\u2022');
                confirmField.setEchoChar(show ? (char) 0 : '\u2022');
            });

            protectCb.addActionListener(e -> updateCreateState());
        }

        passwordField.addActionListener(e -> {
            if (mode != Mode.CREATE || okBtn.isEnabled()) {
                confirmed = true;
                dispose();
            }
        });
        if (confirmField != null) {
            confirmField.addActionListener(e -> {
                if (okBtn.isEnabled()) {
                    confirmed = true;
                    dispose();
                }
            });
        }

        pack();
        setLocationRelativeTo(owner);
        setResizable(false);
    }

    private void updateCreateState() {
        boolean protect = protectCb.isSelected();
        passwordField.setEnabled(protect);
        confirmField.setEnabled(protect);
        showCheckBox.setEnabled(protect);
        if (protect) {
            char[] p1 = passwordField.getPassword();
            char[] p2 = confirmField.getPassword();
            boolean empty = p1.length == 0 || p2.length == 0;
            boolean match = java.util.Arrays.equals(p1, p2);
            okBtn.setEnabled(!empty && match);
            if (empty) {
                statusLabel.setText(" ");
            } else if (match) {
                statusLabel.setText("\u2713 Passwords match");
                statusLabel.setForeground(new Color(0x008800));
            } else {
                statusLabel.setText("\u2717 Passwords do not match");
                statusLabel.setForeground(Color.RED.darker());
            }
        } else {
            okBtn.setEnabled(true);
            statusLabel.setText(" ");
        }
    }

    public char[] getPassword() {
        return confirmed ? passwordField.getPassword() : null;
    }

    public boolean isProtectSelected() {
        return protectCb == null || protectCb.isSelected();
    }
}
