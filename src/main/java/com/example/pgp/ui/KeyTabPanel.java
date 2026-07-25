package com.example.pgp.ui;

import com.example.pgp.model.GeneratedKey;
import com.example.pgp.model.KeyConfig;
import com.example.pgp.model.PGPKeyInfo;
import com.example.pgp.service.KeyGeneratorService;
import com.example.pgp.service.KeyringLoader;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

public class KeyTabPanel extends JPanel {

    private final JTextField userIdField;
    private final JComboBox<String> masterAlgoCombo;
    private final JComboBox<String> masterExpCombo;
    private final JCheckBox masterCertifyCb;
    private final JCheckBox masterSignCb;
    private final JCheckBox masterEncryptCb;
    private final JPanel subKeysPanel;
    private final List<SubKeyRow> subKeyRows = new ArrayList<>();
    private final JButton generateBtn;
    private final KeyTreePanel treePanel;
    private final JButton savePubBtn;
    private final JButton savePrivBtn;

    private GeneratedKey generatedKey;

    public KeyTabPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 3, 3, 3);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;

        c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
        configPanel.add(new JLabel("User ID (e.g. Alice Smith <alice@example.com>):"), c);

        c.gridy = 1;
        userIdField = new JTextField(40);
        configPanel.add(userIdField, c);

        c.gridy = 2; c.gridwidth = 2;
        configPanel.add(Box.createVerticalStrut(10), c);

        c.gridy = 3; c.gridwidth = 1;
        TitledBorder masterBorder = BorderFactory.createTitledBorder("Master Key");
        JPanel masterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        masterPanel.setBorder(masterBorder);

        masterAlgoCombo = new JComboBox<>(new String[]{"RSA 2048", "RSA 3072", "RSA 4096", "EC secp256r1", "EC secp384r1", "EC secp521r1", "Ed25519", "Ed448"});
        masterAlgoCombo.addActionListener(e -> updateMasterCheckboxes());
        masterPanel.add(new JLabel("Type:"));
        masterPanel.add(masterAlgoCombo);

        masterExpCombo = new JComboBox<>(expirationOptions());
        masterPanel.add(new JLabel("Expiry:"));
        masterPanel.add(masterExpCombo);

        masterCertifyCb = new JCheckBox("Certify", true);
        masterSignCb = new JCheckBox("Sign", true);
        masterEncryptCb = new JCheckBox("Encrypt", false);
        masterPanel.add(masterCertifyCb);
        masterPanel.add(masterSignCb);
        masterPanel.add(masterEncryptCb);
        updateMasterCheckboxes();
        configPanel.add(masterPanel, c);

        c.gridy = 4;
        subKeysPanel = new JPanel();
        subKeysPanel.setLayout(new BoxLayout(subKeysPanel, BoxLayout.Y_AXIS));
        subKeysPanel.setBorder(BorderFactory.createTitledBorder("Subkeys"));

        JButton addSubBtn = new JButton("+ Add Subkey");
        addSubBtn.addActionListener(e -> addSubKeyRow());

        JPanel subKeysWrapper = new JPanel(new BorderLayout());
        subKeysWrapper.add(subKeysPanel, BorderLayout.NORTH);
        subKeysWrapper.add(addSubBtn, BorderLayout.SOUTH);
        configPanel.add(subKeysWrapper, c);

        c.gridy = 5; c.gridwidth = 1;
        generateBtn = new JButton("Generate");
        generateBtn.addActionListener(e -> onGenerate());

        JPanel generatePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        generatePanel.add(generateBtn);
        configPanel.add(generatePanel, c);

        c.gridy = 6; c.weighty = 0;
        configPanel.add(Box.createVerticalStrut(10), c);

        JPanel scrollConfig = new JPanel(new BorderLayout());
        scrollConfig.add(configPanel, BorderLayout.NORTH);

        JPanel resultPanel = new JPanel(new BorderLayout(5, 5));
        resultPanel.setBorder(BorderFactory.createTitledBorder("Generated Key"));

        treePanel = new KeyTreePanel("", false, false);
        treePanel.setLoadButtonVisible(false);
        treePanel.setSourceLabelVisible(false);
        treePanel.setUserSelectionAllowed(false);
        treePanel.setAutoSelectEnabled(false);
        resultPanel.add(treePanel, BorderLayout.CENTER);

        JPanel savePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        savePubBtn = new JButton("Save Public Key");
        savePubBtn.setEnabled(false);
        savePubBtn.addActionListener(e -> onSavePublic());
        savePrivBtn = new JButton("Save Private Key");
        savePrivBtn.setEnabled(false);
        savePrivBtn.addActionListener(e -> onSavePrivate());
        savePanel.add(savePubBtn);
        savePanel.add(savePrivBtn);
        resultPanel.add(savePanel, BorderLayout.SOUTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(scrollConfig), resultPanel);
        splitPane.setResizeWeight(0.4);
        add(splitPane, BorderLayout.CENTER);

        addSubKeyRow();
    }

    private void addSubKeyRow() {
        SubKeyRow row = new SubKeyRow();
        subKeyRows.add(row);
        subKeysPanel.add(row.panel);
        subKeysPanel.revalidate();
        subKeysPanel.repaint();
    }

    private void onGenerate() {
        String userId = userIdField.getText().trim();
        if (userId.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter a User ID.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        KeyConfig config = new KeyConfig();
        config.setUserId(userId);
        config.setMasterKey(buildMasterSpec());
        config.getSubKeys().addAll(buildSubSpecs());

        KeyConfig.KeySpec master = config.getMasterKey();
        if (!master.isCanCertify() && !master.isCanSign() && !master.isCanEncrypt()) {
            JOptionPane.showMessageDialog(this, "No operations selected for the master key.\nSelect at least Certify, Sign or Encrypt.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        for (int i = 0; i < config.getSubKeys().size(); i++) {
            KeyConfig.KeySpec sub = config.getSubKeys().get(i);
            if (!sub.isCanSign() && !sub.isCanEncrypt()) {
                JOptionPane.showMessageDialog(this, "Subkey " + (i + 1) + " has no operations.\nSelect at least Sign or Encrypt.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }

        try {
            generatedKey = KeyGeneratorService.generate(config);
            List<PGPKeyInfo> keyInfos = KeyringLoader.extractKeyInfos(generatedKey.getPublicKeyRing());
            treePanel.setKeys(keyInfos);
            treePanel.expandAllNodes();
            savePubBtn.setEnabled(true);
            savePrivBtn.setEnabled(true);
            JOptionPane.showMessageDialog(this, "Key generated successfully.",
                    "OK", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error during generation:\n" + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private KeyConfig.KeySpec buildMasterSpec() {
        String sel = (String) masterAlgoCombo.getSelectedItem();
        KeyConfig.KeySpec spec = parseSpec(sel, true);
        spec.setExpirationSeconds(parseExpiration((String) masterExpCombo.getSelectedItem()));
        spec.setCanCertify(masterCertifyCb.isSelected());
        spec.setCanSign(masterSignCb.isSelected());
        spec.setCanEncrypt(masterEncryptCb.isSelected());
        return spec;
    }

    private List<KeyConfig.KeySpec> buildSubSpecs() {
        List<KeyConfig.KeySpec> specs = new ArrayList<>();
        for (SubKeyRow row : subKeyRows) {
            String sel = (String) row.algoCombo.getSelectedItem();
            KeyConfig.KeySpec spec = parseSpec(sel, false);
            spec.setExpirationSeconds(parseExpiration((String) row.expCombo.getSelectedItem()));
            spec.setCanSign(row.signCb.isSelected());
            spec.setCanEncrypt(row.encryptCb.isSelected());
            // For EC secp* subkeys, choose ECDSA or ECDH based on checkboxes
            if (sel != null && sel.startsWith("EC")) {
                if (spec.isCanSign() && !spec.isCanEncrypt())
                    spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.ECDSA);
                else
                    spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.ECDH);
            }
            specs.add(spec);
        }
        return specs;
    }

    private String suggestedFileName(String extension) {
        String raw = userIdField.getText().trim();
        String name = raw;
        int at = raw.indexOf('<');
        int close = raw.lastIndexOf('>');
        if (at >= 0 && close > at) {
            name = raw.substring(at + 1, close).trim();
        }
        name = name.replaceAll("[\\\\/:*?\"<>|]", "_");
        if (name.isEmpty()) name = "key";
        return name + extension;
    }

    private KeyConfig.KeySpec parseSpec(String selection, boolean isMaster) {
        KeyConfig.KeySpec spec = new KeyConfig.KeySpec();
        if (selection.startsWith("RSA")) {
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.RSA);
            spec.setRsaSize(Integer.parseInt(selection.split(" ")[1]));
        } else if (selection.startsWith("EC")) {
            String curve = selection.split(" ", 2)[1];
            spec.setAlgorithm(isMaster ? KeyConfig.KeySpec.Algorithm.ECDSA : KeyConfig.KeySpec.Algorithm.ECDH);
            spec.setEcCurve(curve);
        } else if (selection.equals("Ed25519")) {
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.EDDSA);
        } else if (selection.equals("Ed448")) {
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.ED448);
        } else if (selection.equals("X25519")) {
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.XDH);
        } else if (selection.equals("X448")) {
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.X448);
        }
        return spec;
    }

    private static String[] expirationOptions() {
        return new String[]{"Never", "1 month", "3 months", "6 months", "1 year", "2 years", "5 years", "10 years"};
    }

    private static long parseExpiration(String text) {
        switch (text) {
            case "1 month": return 30L * 86400;
            case "3 months": return 90L * 86400;
            case "6 months": return 180L * 86400;
            case "1 year": return 365L * 86400;
            case "2 years": return 2L * 365 * 86400;
            case "5 years": return 5L * 365 * 86400;
            case "10 years": return 10L * 365 * 86400;
            default: return 0;
        }
    }

    private void updateMasterCheckboxes() {
        String sel = (String) masterAlgoCombo.getSelectedItem();
        boolean canEncrypt = sel != null && sel.startsWith("RSA");
        masterEncryptCb.setEnabled(canEncrypt);
        if (!canEncrypt) masterEncryptCb.setSelected(false);
    }

    private void updateSubkeyCheckboxes(SubKeyRow row) {
        String sel = (String) row.algoCombo.getSelectedItem();
        if (sel == null) return;
        if (sel.startsWith("RSA") || sel.startsWith("EC")) {
            row.syncing = true;
            row.signCb.setEnabled(true);
            row.signCb.setSelected(row.savedSign);
            row.encryptCb.setEnabled(true);
            row.encryptCb.setSelected(row.savedEncrypt);
            row.syncing = false;
        } else if (sel.equals("Ed25519") || sel.equals("Ed448")) {
            row.signCb.setEnabled(true);
            row.signCb.setSelected(true);
            row.encryptCb.setEnabled(false);
            row.encryptCb.setSelected(false);
        } else {
            row.signCb.setEnabled(false);
            row.signCb.setSelected(false);
            row.encryptCb.setEnabled(true);
            row.encryptCb.setSelected(true);
        }
    }

    private void onSavePublic() {
        if (generatedKey == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(suggestedFileName(".pkr")));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try (ArmoredOutputStream out = new ArmoredOutputStream(new FileOutputStream(file))) {
                PGPPublicKeyRing pubRing = generatedKey.getPublicKeyRing();
                pubRing.encode(out);
                JOptionPane.showMessageDialog(this, "Public key saved:\n" + file.getAbsolutePath(),
                        "OK", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(this, "Error during save:\n" + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void onSavePrivate() {
        if (generatedKey == null) return;

        PasswordDialog pwdDlg = new PasswordDialog(
                (Frame) SwingUtilities.getWindowAncestor(this),
                "generated private key",
                PasswordDialog.Mode.CREATE,
                "Create password for private key");
        pwdDlg.setVisible(true);
        if (pwdDlg.getPassword() == null) return;

        PGPSecretKeyRing secRing;
        if (pwdDlg.isProtectSelected()) {
            try {
                secRing = KeyGeneratorService.reEncrypt(generatedKey.getSecretKeyRing(), pwdDlg.getPassword());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error during key encryption:\n" + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        } else {
            secRing = generatedKey.getSecretKeyRing();
        }

        try {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File(suggestedFileName(".skr")));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                try (ArmoredOutputStream out = new ArmoredOutputStream(new FileOutputStream(file))) {
                    secRing.encode(out);
                }
                JOptionPane.showMessageDialog(this, "Private key saved:\n" + file.getAbsolutePath(),
                        "OK", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error during save:\n" + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private class SubKeyRow {
        final JPanel panel;
        final JComboBox<String> algoCombo;
        final JComboBox<String> expCombo;
        final JCheckBox signCb;
        final JCheckBox encryptCb;
        private boolean savedSign = true;
        private boolean savedEncrypt = true;
        boolean syncing;

        SubKeyRow() {
            panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
            algoCombo = new JComboBox<>(new String[]{"RSA 2048", "RSA 3072", "RSA 4096", "EC secp256r1", "EC secp384r1", "EC secp521r1", "Ed25519", "Ed448", "X25519", "X448"});
            expCombo = new JComboBox<>(expirationOptions());
            signCb = new JCheckBox("Sign", true);
            encryptCb = new JCheckBox("Encrypt", true);
            java.awt.event.ItemListener checkboxSaver = e -> {
                if (syncing) return;
                if (e.getStateChange() == java.awt.event.ItemEvent.SELECTED
                        || e.getStateChange() == java.awt.event.ItemEvent.DESELECTED) {
                    String sel = (String) algoCombo.getSelectedItem();
                    if (sel != null && (sel.startsWith("RSA") || sel.startsWith("EC"))) {
                        savedSign = signCb.isSelected();
                        savedEncrypt = encryptCb.isSelected();
                    }
                }
            };
            signCb.addItemListener(checkboxSaver);
            encryptCb.addItemListener(checkboxSaver);
            algoCombo.addActionListener(e -> updateSubkeyCheckboxes(this));
            JButton removeBtn = new JButton("X Remove");
            removeBtn.addActionListener(e -> {
                subKeyRows.remove(this);
                subKeysPanel.remove(panel);
                subKeysPanel.revalidate();
                subKeysPanel.repaint();
            });
            panel.add(new JLabel("Type:"));
            panel.add(algoCombo);
            panel.add(new JLabel("Expiry:"));
            panel.add(expCombo);
            panel.add(signCb);
            panel.add(encryptCb);
            panel.add(removeBtn);
            updateSubkeyCheckboxes(this);
        }
    }
}
