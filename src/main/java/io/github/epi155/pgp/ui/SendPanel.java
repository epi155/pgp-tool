package io.github.epi155.pgp.ui;

import io.github.epi155.pgp.model.CompoundCodec;
import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.KeyBundle;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.KeyringLoader;
import io.github.epi155.pgp.service.PGPEngine;
import io.github.epi155.pgp.service.ProgressCallback;
import static io.github.epi155.pgp.ui.UIUtils.createPublicFileChooser;
import static io.github.epi155.pgp.ui.UIUtils.createSecretFileChooser;
import static io.github.epi155.pgp.ui.UIUtils.isBinaryContent;
import static io.github.epi155.pgp.ui.UIUtils.wrapInScroll;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SendPanel extends JPanel {

    private final transient PGPEngine engine;
    private final boolean advancedMode;
    private final JTabbedPane encLayerTabs;
    private final List<EncryptLayerPanel> encLayers = new ArrayList<>();
    private int suppressEncLayerTabListener;
    private transient KeyTreePanel activeEncKeyPanel;
    private final JTabbedPane signerTabs;
    private final List<SignerPanel> signerPanels = new ArrayList<>();
    private int suppressTabListener;
    private final JTextArea plainTextArea;
    private final JTextArea cipherTextArea;
    private final JCheckBox signCheckBox;
    private final JCheckBox encCheckBox;
    private final JButton encryptButton;
    private final JTextField userFilterField;
    private final JButton clearSelButton;
    private final JToggleButton showViewBtn;
    private final JComboBox<String> compAlgoCombo;
    private final JList<String> attachList;
    private final DefaultListModel<String> attachListModel;
    private final List<File> attachmentFiles = new ArrayList<>();
    private final JButton addAttachButton;
    private final JButton removeAttachButton;
    private final JTextField outputFileField;
    private final JCheckBox armorCheckBox;
    private final CardLayout outputCardLayout;
    private final JPanel outputCardPanel;
    private final JPanel outerPanel;

    public SendPanel(PGPEngine engine, boolean advancedMode) {
        this.engine = engine;
        this.advancedMode = advancedMode;
        setLayout(new BorderLayout(5, 5));

        encCheckBox = new JCheckBox("Enc", true);
        compAlgoCombo = new JComboBox<>(new String[]{"ZIP", "ZLIB", "BZIP2", "None"});
        compAlgoCombo.setSelectedItem("ZLIB");
        compAlgoCombo.setEnabled(false);

        userFilterField = new JTextField(12);
        userFilterField.setEnabled(false);
        userFilterField.getDocument().addDocumentListener(new DocumentListener() {
            private void apply() {
                SwingUtilities.invokeLater(() -> {
                    if (activeEncKeyPanel != null)
                        activeEncKeyPanel.setFilterText(userFilterField.getText());
                });
            }
            @Override
            public void insertUpdate(DocumentEvent e) { apply(); }
            @Override
            public void removeUpdate(DocumentEvent e) { apply(); }
            @Override
            public void changedUpdate(DocumentEvent e) { apply(); }
        });
        clearSelButton = new JButton("Clear Sel");
        clearSelButton.setEnabled(false);
        clearSelButton.addActionListener(e -> {
            if (activeEncKeyPanel != null) activeEncKeyPanel.clearSelection();
        });
        showViewBtn = new JToggleButton("Show Sel");
        showViewBtn.setEnabled(false);
        showViewBtn.addActionListener(e -> {
            if (activeEncKeyPanel != null) activeEncKeyPanel.setSelectedViewActive(showViewBtn.isSelected());
        });

        encLayerTabs = new JTabbedPane();
        if (advancedMode) {
            encLayerTabs.addChangeListener(e -> {
                if (suppressEncLayerTabListener > 0) return;
                int idx = encLayerTabs.getSelectedIndex();
                if (idx >= 0 && idx == encLayerTabs.getTabCount() - 1) {
                    addEncryptLayer();
                }
                updateActiveEncLayer();
            });
            encLayerTabs.addTab("+", null);
        } else {
            hideTabArea(encLayerTabs);
        }
        plainTextArea = new JTextArea(12, 40);
        cipherTextArea = new JTextArea(12, 40);
        signCheckBox = new JCheckBox("Sign");
        encryptButton = new JButton("Encrypt") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                GradientPaint gp = new GradientPaint(
                        0, 0, Color.decode("#FFD700"), 0, getHeight(), Color.decode("#DAA520"));
                g2.setPaint(gp);
                g2.fillRect(0, 0, getWidth(), getHeight());
                g2.dispose();
                super.paintComponent(g);
            }
        };
        encryptButton.setContentAreaFilled(false);
        encryptButton.setOpaque(false);
        encryptButton.setForeground(new Color(0x302681));
        encryptButton.setFont(encryptButton.getFont().deriveFont(Font.BOLD));
        Font mono = new Font("Monospaced", Font.PLAIN, 12);
        plainTextArea.setFont(mono);
        cipherTextArea.setFont(mono);
        cipherTextArea.setLineWrap(true);
        cipherTextArea.setWrapStyleWord(true);
        cipherTextArea.setEditable(false);

        encryptButton.setEnabled(false);

        signerTabs = new JTabbedPane();
        if (advancedMode) {
            signerTabs.addChangeListener(e -> {
                if (suppressTabListener > 0) return;
                int idx = signerTabs.getSelectedIndex();
                if (idx >= 0 && idx == signerTabs.getTabCount() - 1) {
                    addSignerTab();
                }
            });
            signerTabs.addTab("+", null);
        } else {
            hideTabArea(signerTabs);
        }

        JPanel signerContainer = new JPanel(new BorderLayout(0, 2));
        signerContainer.add(signerTabs, BorderLayout.CENTER);

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                signerContainer, UIUtils.wrapInScroll(plainTextArea, "Plain Text Message"));
        topSplit.setResizeWeight(0.35);

        outputCardLayout = new CardLayout();
        outputCardPanel = new JPanel(outputCardLayout);

        outputCardPanel.add(UIUtils.wrapInScroll(cipherTextArea, "Armored Ciphertext"), "text");

        JPanel fileOutputPanel = new JPanel(new BorderLayout(5, 5));
        fileOutputPanel.setBorder(BorderFactory.createTitledBorder("File Output"));
        JPanel fileRow = new JPanel(new BorderLayout(5, 2));
        outputFileField = new JTextField();
        outputFileField.setEditable(false);
        JButton outputBrowseBtn = new JButton("Browse...");
        armorCheckBox = new JCheckBox("ASCII Armor", true);
        fileRow.add(new JLabel("File:"), BorderLayout.WEST);
        fileRow.add(outputFileField, BorderLayout.CENTER);
        JPanel btnEast = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        btnEast.add(outputBrowseBtn);
        btnEast.add(armorCheckBox);
        fileRow.add(btnEast, BorderLayout.EAST);
        fileOutputPanel.add(fileRow, BorderLayout.CENTER);

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                encLayerTabs, outputCardPanel);
        bottomSplit.setResizeWeight(0.35);

        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        centerPanel.add(encryptButton);
        centerPanel.add(encCheckBox);
        centerPanel.add(new JLabel("Comp:"));
        centerPanel.add(compAlgoCombo);
        centerPanel.add(signCheckBox);
        addAttachButton = new JButton("Add File...");
        removeAttachButton = new JButton("Remove");
        removeAttachButton.setEnabled(false);
        centerPanel.add(addAttachButton);
        centerPanel.add(removeAttachButton);
        centerPanel.add(new JLabel("User:"));
        centerPanel.add(userFilterField);
        centerPanel.add(clearSelButton);
        centerPanel.add(showViewBtn);

        attachListModel = new DefaultListModel<>();
        attachList = new JList<>(attachListModel);
        attachList.setVisibleRowCount(3);
        JScrollPane attachScroll = new JScrollPane(attachList);
        attachScroll.setBorder(BorderFactory.createTitledBorder("Attachments"));

        JSplitPane compoundSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                attachScroll, fileOutputPanel);
        compoundSplit.setResizeWeight(1);
        compoundSplit.setBorder(null);
        outputCardPanel.add(compoundSplit, "compound");

        outputBrowseBtn.addActionListener(e -> chooseOutputFile());

        outerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;

        gbc.gridy = 0; gbc.weighty = 1;
        outerPanel.add(topSplit, gbc);
        gbc.gridy = 1; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        outerPanel.add(centerPanel, gbc);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridy = 2; gbc.weighty = 1;
        outerPanel.add(bottomSplit, gbc);
        add(outerPanel, BorderLayout.CENTER);

        encryptButton.addActionListener(this::onEncrypt);
        encCheckBox.addActionListener(e -> {
            boolean enc = encCheckBox.isSelected();
            setEncLayersEnabled(enc);
            updateEncryptButton();
        });
        signCheckBox.addActionListener(e -> {
            boolean sign = signCheckBox.isSelected();
            setSignersEnabled(sign);
            updateEncryptButton();
        });

        addEncryptLayer();
        addSignerTab();
        addAttachButton.addActionListener(this::addAttachment);
        removeAttachButton.addActionListener(this::removeAttachment);
        attachList.addListSelectionListener(e ->
                removeAttachButton.setEnabled(!attachList.isSelectionEmpty()));
        attachList.setTransferHandler(new TransferHandler() {
            @Override
            public boolean canImport(TransferSupport support) {
                return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override
            public boolean importData(TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    for (File f : files) {
                        if (!attachmentFiles.contains(f)) {
                            attachmentFiles.add(f);
                            attachListModel.addElement(f.getName());
                        }
                    }
                    updateOutputMode();
                    return true;
                } catch (Exception ex) { return false; }
            }
        });
        plainTextArea.setTransferHandler(new TransferHandler() {
            @Override
            public int getSourceActions(JComponent c) {
                return COPY_OR_MOVE;
            }

            @Override
            protected Transferable createTransferable(JComponent c) {
                String sel = ((JTextArea) c).getSelectedText();
                return sel != null ? new StringSelection(sel) : null;
            }

            @Override
            public boolean canImport(TransferSupport support) {
                return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)
                        || support.isDataFlavorSupported(DataFlavor.stringFlavor);
            }
            @Override
            public boolean importData(TransferSupport support) {
                if (support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                    try {
                        java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                                .getTransferData(DataFlavor.javaFileListFlavor);
                        if (files.isEmpty()) return false;
                        for (int i = 0; i < files.size(); i++) {
                            File f = files.get(i);
                            if (attachmentFiles.contains(f)) continue;
                            boolean attach = i > 0;
                            if (!attach) {
                                byte[] header = new byte[16384];
                                int len;
                                try (FileInputStream fis = new FileInputStream(f)) {
                                    len = fis.read(header);
                                }
                                if (len > 0 && !isBinaryContent(header, len)) {
                                    long fileSize = f.length();
                                    if (fileSize > 1_048_576) {
                                        attach = true;
                                    } else {
                                        String content = new String(
                                                Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                                        String sizeStr = String.format("%.1f KB", fileSize / 1024.0);
                                        String[] options = {"Paste as Text", "Attach as File"};
                                        int ret = JOptionPane.showOptionDialog(
                                                plainTextArea,
                                                "The file \"" + f.getName() + "\" (" + sizeStr + ") is textual.\n"
                                                        + "How do you wish to handle it?",
                                                "Textual file detected",
                                                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                                                null, options, options[1]);
                                        if (ret == 0) {
                                            plainTextArea.replaceSelection(content);
                                            continue;
                                        }
                                        attach = true;
                                    }
                                } else {
                                    attach = true;
                                }
                            }
                            attachmentFiles.add(f);
                            attachListModel.addElement(f.getName());
                        }
                        updateOutputMode();
                        return true;
                    } catch (Exception ex) { return false; }
                }
                try {
                    String text = (String) support.getTransferable()
                            .getTransferData(DataFlavor.stringFlavor);
                    plainTextArea.replaceSelection(text);
                    return true;
                } catch (Exception ex) { return false; }
            }

            @Override
            protected void exportDone(JComponent source, Transferable data, int action) {
                if (action == MOVE) ((JTextArea) source).replaceSelection("");
            }
        });
        plainTextArea.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (SwingUtilities.isMiddleMouseButton(e)) {
                    try {
                        Clipboard primary = Toolkit.getDefaultToolkit().getSystemSelection();
                        if (primary != null) {
                            String text = (String) primary.getData(DataFlavor.stringFlavor);
                            if (text != null) plainTextArea.replaceSelection(text);
                        } else {
                            String text = (String) Toolkit.getDefaultToolkit()
                                    .getSystemClipboard().getData(DataFlavor.stringFlavor);
                            if (text != null) plainTextArea.replaceSelection(text);
                        }
                    } catch (Exception ignored) {}
                }
            }
        });
        UndoManager undoManager = new UndoManager();
        plainTextArea.getDocument().addUndoableEditListener(undoManager);
        plainTextArea.getActionMap().put("Undo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (undoManager.canUndo()) undoManager.undo();
            }
        });
        plainTextArea.getInputMap().put(KeyStroke.getKeyStroke("control Z"), "Undo");
        plainTextArea.getActionMap().put("Redo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (undoManager.canRedo()) undoManager.redo();
            }
        });
        plainTextArea.getInputMap().put(KeyStroke.getKeyStroke("control Y"), "Redo");
        plainTextArea.getInputMap().put(KeyStroke.getKeyStroke("control shift Z"), "Redo");
    }

    private void updateFilterField() {
        boolean multi = activeEncKeyPanel != null && activeEncKeyPanel.hasMultipleMasterKeys();
        boolean active = activeEncKeyPanel != null && activeEncKeyPanel.isSelectedViewActive();
        userFilterField.setEnabled(!active && multi);
        clearSelButton.setEnabled(!active && multi);
    }

    private void updateEncryptButton() {
        if (!attachmentFiles.isEmpty()) {
            updateOutputMode();
            return;
        }
        if (!encCheckBox.isSelected()) {
            encryptButton.setEnabled(true);
            compAlgoCombo.setEnabled(true);
            return;
        }
        boolean allValid = !encLayers.isEmpty();
        for (EncryptLayerPanel layer : encLayers) {
            if (layer.usePasswordCheckBox.isSelected()) {
                char[] pw = layer.passwordField.getPassword();
                char[] vw = layer.verifyField.getPassword();
                boolean pwOk = pw != null && pw.length > 0;
                boolean matchOk = java.util.Arrays.equals(pw, vw);
                if (!pwOk || !matchOk) { allValid = false; break; }
            } else {
                boolean hasKeys = layer.keyPanel.getSelectedKeys().stream()
                    .anyMatch(PGPKeyInfo::canEncrypt);
                if (!hasKeys) { allValid = false; break; }
            }
        }
        encryptButton.setEnabled(allValid);
        compAlgoCombo.setEnabled(true);
        updateShowViewButton();
    }

    private void updateSignCheckbox() {
        updateEncryptButton();
    }

    private void updateShowViewButton() {
        boolean active = activeEncKeyPanel != null && activeEncKeyPanel.isSelectedViewActive();
        showViewBtn.setSelected(active);
        if (active) {
            showViewBtn.setEnabled(true);
        } else {
            showViewBtn.setEnabled(activeEncKeyPanel != null
                && activeEncKeyPanel.getSelectedKeys().size() >= 2);
        }
    }

    private void updateOutputMode() {
        boolean has = !attachmentFiles.isEmpty();
        outputCardLayout.show(outputCardPanel, has ? "compound" : "text");
        if (has) {
            boolean outputChosen = outputFileField.getText() != null && !outputFileField.getText().trim().isEmpty();
            if (!encCheckBox.isSelected()) {
                encryptButton.setEnabled(outputChosen);
                compAlgoCombo.setEnabled(true);
            } else {
                boolean allValid = !encLayers.isEmpty();
                for (EncryptLayerPanel layer : encLayers) {
                    if (layer.usePasswordCheckBox.isSelected()) {
                        char[] pw = layer.passwordField.getPassword();
                        char[] vw = layer.verifyField.getPassword();
                        boolean pwOk = pw != null && pw.length > 0;
                        boolean matchOk = java.util.Arrays.equals(pw, vw);
                        if (!pwOk || !matchOk) { allValid = false; break; }
                    } else {
                        boolean hasKeys = layer.keyPanel.getSelectedKeys().stream()
                            .anyMatch(PGPKeyInfo::canEncrypt);
                        if (!hasKeys) { allValid = false; break; }
                    }
                }
                encryptButton.setEnabled(allValid && outputChosen);
                compAlgoCombo.setEnabled(true);
            }
        } else {
            updateEncryptButton();
        }
    }

    private void addAttachment(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        fc.setMultiSelectionEnabled(true);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            for (File f : fc.getSelectedFiles()) {
                attachmentFiles.add(f);
                attachListModel.addElement(f.getName());
            }
            updateOutputMode();
        }
    }

    private void removeAttachment(ActionEvent e) {
        int idx = attachList.getSelectedIndex();
        if (idx >= 0) {
            attachmentFiles.remove(idx);
            attachListModel.remove(idx);
            updateOutputMode();
        }
    }

    private void chooseOutputFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogType(JFileChooser.SAVE_DIALOG);
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            outputFileField.setText(fc.getSelectedFile().getAbsolutePath());
            updateOutputMode();
        }
    }

    private int mapEncAlgo(String name) {
        switch (name) {
            case "AES-128": return SymmetricKeyAlgorithmTags.AES_128;
            case "AES-192": return SymmetricKeyAlgorithmTags.AES_192;
            case "AES-256": return SymmetricKeyAlgorithmTags.AES_256;
            case "CAST5": return SymmetricKeyAlgorithmTags.CAST5;
            case "Blowfish": return SymmetricKeyAlgorithmTags.BLOWFISH;
            case "Triple-DES": return SymmetricKeyAlgorithmTags.TRIPLE_DES;
            case "Twofish": return SymmetricKeyAlgorithmTags.TWOFISH;
            default: return SymmetricKeyAlgorithmTags.AES_128;
        }
    }

    private int mapCompAlgo(String name) {
        switch (name) {
            case "ZLIB": return CompressionAlgorithmTags.ZLIB;
            case "ZIP": return CompressionAlgorithmTags.ZIP;
            case "BZIP2": return CompressionAlgorithmTags.BZIP2;
            default: return CompressionAlgorithmTags.UNCOMPRESSED;
        }
    }

    private int mapHashAlgo(String name) {
        switch (name) {
            case "SHA-256": return HashAlgorithmTags.SHA256;
            case "SHA-384": return HashAlgorithmTags.SHA384;
            case "SHA-512": return HashAlgorithmTags.SHA512;
            case "RIPEMD160": return HashAlgorithmTags.RIPEMD160;
            default: return HashAlgorithmTags.SHA256;
        }
    }

    public void savePreferences(java.util.prefs.Preferences prefs) {
        prefs.putBoolean("enc_enabled", encCheckBox.isSelected());
        prefs.putBoolean("sign_enabled", signCheckBox.isSelected());
        prefs.put("comp_algo", (String) compAlgoCombo.getSelectedItem());
        prefs.remove("hash_algo");
        int count = signerPanels.size();
        prefs.putInt("signer_count", count);
        for (int i = 0; i < count; i++)
            prefs.put("signer_hash_" + i,
                (String) signerPanels.get(i).hashCombo.getSelectedItem());
        for (int i = count; ; i++) {
            if (prefs.get("signer_hash_" + i, null) == null) break;
            prefs.remove("signer_hash_" + i);
        }
        prefs.remove("send_pub_paths");
        prefs.remove("send_priv_paths");
        prefs.remove("enc_algo");
        int layerCount = encLayers.size();
        prefs.putInt("layer_count", layerCount);
        for (int i = 0; i < layerCount; i++) {
            EncryptLayerPanel layer = encLayers.get(i);
            prefs.put("layer_algo_" + i, (String) layer.algoCombo.getSelectedItem());
            prefs.putBoolean("layer_is_password_" + i, layer.usePasswordCheckBox.isSelected());
            prefs.put("layer_paths_" + i, String.join(File.pathSeparator, layer.keyringPaths));
        }
        for (int i = layerCount; ; i++) {
            if (prefs.get("layer_algo_" + i, null) == null) break;
            prefs.remove("layer_algo_" + i);
            prefs.remove("layer_is_password_" + i);
            prefs.remove("layer_paths_" + i);
        }
        for (int i = 0; i < count; i++) {
            String path = signerPanels.get(i).keyringPath;
            if (path != null)
                prefs.put("signer_path_" + i, path);
            else
                prefs.remove("signer_path_" + i);
        }
        for (int i = count; ; i++) {
            if (prefs.get("signer_path_" + i, null) == null) break;
            prefs.remove("signer_path_" + i);
        }
    }

    public void restorePreferences(java.util.prefs.Preferences prefs) {
        encCheckBox.setSelected(prefs.getBoolean("enc_enabled", true));
        signCheckBox.setSelected(prefs.getBoolean("sign_enabled", false));
        compAlgoCombo.setSelectedItem(prefs.get("comp_algo", "ZLIB"));

        int signerCount = prefs.getInt("signer_count", 0);
        if (!advancedMode && signerCount > 1) signerCount = 1;
        suppressTabListener++;
        while (signerTabs.getTabCount() > 0) {
            signerTabs.removeTabAt(0);
        }
        if (advancedMode) {
            signerTabs.addTab("+", null);
        }
        signerPanels.clear();
        suppressTabListener--;
        if (signerCount > 0) {
            for (int i = 0; i < signerCount; i++)
                addSignerTab(prefs.get("signer_hash_" + i, "SHA-256"));
        } else {
            addSignerTab(prefs.get("hash_algo", "SHA-256"));
        }

        // Restore encrypt layers
        int layerCount = prefs.getInt("layer_count", 0);
        if (!advancedMode && layerCount > 1) layerCount = 1;
        suppressEncLayerTabListener++;
        while (encLayerTabs.getTabCount() > 0) {
            encLayerTabs.removeTabAt(0);
        }
        if (advancedMode) {
            encLayerTabs.addTab("+", null);
        }
        encLayers.clear();
        suppressEncLayerTabListener--;

        if (layerCount > 0) {
            for (int i = 0; i < layerCount; i++) {
                addEncryptLayer(prefs.get("layer_algo_" + i, "AES-128"));
                EncryptLayerPanel layer = encLayers.get(i);
                boolean isPassword = prefs.getBoolean("layer_is_password_" + i, false);
                layer.usePasswordCheckBox.setSelected(isPassword);
                if (isPassword) {
                    layer.cardLayout.show(layer.cardsPanel, "password");
                }
                String paths = prefs.get("layer_paths_" + i, "");
                if (!paths.isEmpty()) {
                    for (String path : paths.split(File.pathSeparator)) {
                        File f = new File(path);
                        if (f.exists())
                            layer.addKeyring(f);
                    }
                }
            }
        } else {
            // Backward compat: old send_pub_paths
            String pubPaths = prefs.get("send_pub_paths", "");
            if (!pubPaths.isEmpty()) {
                addEncryptLayer(prefs.get("enc_algo", "AES-128"));
                for (String path : pubPaths.split(File.pathSeparator)) {
                    File f = new File(path);
                    if (f.exists())
                        encLayers.get(0).loadKeyring(f);
                }
            } else {
                addEncryptLayer();
            }
        }

        String privPaths = prefs.get("send_priv_paths", "");
        if (!privPaths.isEmpty()) {
            for (String path : privPaths.split(File.pathSeparator)) {
                File f = new File(path);
                if (f.exists() && !signerPanels.isEmpty()) {
                    signerPanels.get(0).loadKeyring(f);
                } else {
                    System.err.println("File not found: " + path);
                }
            }
        }
        for (int i = 0; i < signerPanels.size(); i++) {
            String path = prefs.get("signer_path_" + i, "");
            if (!path.isEmpty()) {
                File f = new File(path);
                if (f.exists())
                    signerPanels.get(i).loadKeyring(f);
            }
        }
        // Apply sign/enc enable state after all tabs are fully created
        setSignersEnabled(signCheckBox.isSelected());
        setEncLayersEnabled(encCheckBox.isSelected());
    }

    private void onEncrypt(ActionEvent e) {
        boolean encEnabled = encCheckBox.isSelected();

        if (encEnabled) {
            for (int i = 0; i < encLayers.size(); i++) {
                EncryptLayerPanel layer = encLayers.get(i);
                if (layer.usePasswordCheckBox.isSelected()) {
                    char[] pw = layer.passwordField.getPassword();
                    char[] vw = layer.verifyField.getPassword();
                    if (pw == null || pw.length == 0) {
                        JOptionPane.showMessageDialog(this,
                            "Layer " + (i + 1) + ": password is required.",
                            "Warning", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    if (!java.util.Arrays.equals(pw, vw)) {
                        JOptionPane.showMessageDialog(this,
                            "Layer " + (i + 1) + ": passwords do not match.",
                            "Warning", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                } else {
                    boolean hasKeys = layer.keyPanel.getSelectedKeys().stream()
                        .anyMatch(PGPKeyInfo::canEncrypt);
                    if (!hasKeys) {
                        JOptionPane.showMessageDialog(this,
                            "Layer " + (i + 1) + ": select at least one public key with encryption capability.",
                            "Warning", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                }
            }
        }

        String plainText = plainTextArea.getText();
        boolean hasAttachments = !attachmentFiles.isEmpty();

        if (!hasAttachments && plainText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Enter the message to encrypt.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (hasAttachments && (outputFileField.getText() == null || outputFileField.getText().trim().isEmpty())) {
            JOptionPane.showMessageDialog(this, "Choose the output file.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<PGPSecretKey> signKeys = new ArrayList<>();
        List<char[]> signPassphrases = new ArrayList<>();
        List<Integer> hashAlgos = new ArrayList<>();

        if (signCheckBox.isSelected()) {
            for (SignerPanel sp : signerPanels) {
                List<PGPKeyInfo> sel = sp.keyPanel.getSelectedKeys();
                if (sel.isEmpty()) continue;
                PGPKeyInfo ki = sel.get(0);
                PGPSecretKey sk = ki.getBcKey(PGPSecretKey.class);
                long keyId = sk.getKeyID();
                char[] passphrase;
                if (!engine.hasPassphrase(keyId)) {
                    if (engine.cacheEmptyPassphraseIfUnprotected(sk)) {
                        passphrase = new char[0];
                    } else {
                        PasswordDialog dlg = new PasswordDialog(
                                (Frame) SwingUtilities.getWindowAncestor(this),
                                resolveSignKeyUserId(ki, sp), ki.getKeyIdHex(),
                                PasswordDialog.Mode.REQUEST);
                        dlg.setVisible(true);
                        passphrase = dlg.getPassword();
                        if (passphrase == null) return;
                        engine.cachePassphrase(keyId, passphrase);
                    }
                } else {
                    passphrase = engine.getPassphraseFor(keyId);
                }
                signKeys.add(sk);
                signPassphrases.add(passphrase);
                hashAlgos.add(mapHashAlgo((String) sp.hashCombo.getSelectedItem()));
            }
            if (signKeys.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Select at least one private key to sign.",
                        "Error", JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        // Collect per-layer info on EDT
        final int compAlgo = mapCompAlgo((String) compAlgoCombo.getSelectedItem());
        final java.util.List<java.util.List<PGPPublicKey>> fEncKeyLayers;
        final java.util.List<char[]> fPasswordLayers;
        final java.util.List<Boolean> fLayerIsPassword;
        final java.util.List<Integer> fLayerAlgos;
        if (encEnabled) {
            fEncKeyLayers = new java.util.ArrayList<>();
            fPasswordLayers = new java.util.ArrayList<>();
            fLayerIsPassword = new java.util.ArrayList<>();
            fLayerAlgos = new java.util.ArrayList<>();
            for (EncryptLayerPanel layer : encLayers) {
                String algoName = (String) layer.algoCombo.getSelectedItem();
                int symAlgo = mapEncAlgo(algoName);
                fLayerAlgos.add(symAlgo);
                boolean isPw = layer.usePasswordCheckBox.isSelected();
                fLayerIsPassword.add(isPw);
                if (isPw) {
                    fEncKeyLayers.add(null);
                    fPasswordLayers.add(layer.passwordField.getPassword());
                } else {
                    java.util.List<PGPKeyInfo> selected = layer.keyPanel.getSelectedKeys();
                    java.util.List<PGPPublicKey> keys = new java.util.ArrayList<>();
                    for (PGPKeyInfo ki : selected) {
                        if (ki.canEncrypt()) keys.add(ki.getBcKey(PGPPublicKey.class));
                    }
                    fEncKeyLayers.add(keys);
                    fPasswordLayers.add(null);
                }
            }
        } else {
            fEncKeyLayers = null;
            fPasswordLayers = null;
            fLayerIsPassword = null;
            fLayerAlgos = null;
        }

        try {
            final String fPlainText = plainText;
            final boolean fHasAttachments = hasAttachments;
            final boolean fEncEnabled = encEnabled;
            final List<PGPSecretKey> fSignKeys = signKeys;
            final List<char[]> fSignPassphrases = signPassphrases;
            final List<Integer> fHashAlgos = hashAlgos;

            Frame owner = (Frame) SwingUtilities.getWindowAncestor(this);
            ProgressDialog progress = new ProgressDialog(owner, "Encrypting...");

            SwingWorker<Void, Void> worker = new SwingWorker<>() {
                @Override
                protected Void doInBackground() throws Exception {
                    String fileName;
                    byte[] data;
                    boolean armor;
                    if (fHasAttachments) {
                        boolean rawFile = fPlainText.isEmpty() && attachmentFiles.size() == 1;
                        fileName = rawFile ? attachmentFiles.get(0).getName() : "_CONSOLE";
                        if (rawFile) {
                            data = Files.readAllBytes(attachmentFiles.get(0).toPath());
                        } else {
                            List<CompoundMessage.Attachment> atts = new ArrayList<>();
                            for (File f : attachmentFiles) {
                                atts.add(new CompoundMessage.Attachment(f.getName(), Files.readAllBytes(f.toPath())));
                            }
                            data = CompoundCodec.encode(new CompoundMessage(fPlainText, atts));
                        }
                        armor = armorCheckBox.isSelected();
                    } else {
                        fileName = "_CONSOLE";
                        data = fPlainText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        armor = true;
                    }

                    byte[] encrypted;
                    if (!fEncEnabled) {
                        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                        engine.encryptCompress(data, fileName, bOut,
                                fSignKeys, fSignPassphrases, compAlgo, fHashAlgos, armor, progress);
                        encrypted = bOut.toByteArray();
                    } else {
                        encrypted = data;
                        boolean firstLayer = true;
                        for (int i = 0; i < fLayerIsPassword.size(); i++) {
                            boolean lastLayer = (i == fLayerIsPassword.size() - 1);
                            int layerSymAlgo = fLayerAlgos.get(i);
                            boolean isPw = fLayerIsPassword.get(i);
                            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                            if (firstLayer) {
                                if (isPw) {
                                    engine.encryptPassword(encrypted, fileName, bOut, fPasswordLayers.get(i),
                                            fSignKeys, fSignPassphrases, layerSymAlgo, compAlgo, fHashAlgos,
                                            lastLayer && armor, progress);
                                } else {
                                    engine.encrypt(encrypted, fileName, bOut, fEncKeyLayers.get(i),
                                            fSignKeys, fSignPassphrases, layerSymAlgo, compAlgo, fHashAlgos,
                                            lastLayer && armor, progress);
                                }
                            } else {
                                if (isPw) {
                                    engine.encryptRawPassword(encrypted, bOut, fPasswordLayers.get(i),
                                            layerSymAlgo, lastLayer && armor, progress);
                                } else {
                                    engine.encryptRaw(encrypted, bOut, fEncKeyLayers.get(i),
                                            layerSymAlgo, lastLayer && armor, progress);
                                }
                            }
                            encrypted = bOut.toByteArray();
                            firstLayer = false;
                        }
                    }

                    if (fHasAttachments) {
                        Files.write(new File(outputFileField.getText().trim()).toPath(), encrypted);
                    } else {
                        String resultStr = new String(encrypted, java.nio.charset.StandardCharsets.UTF_8);
                        SwingUtilities.invokeLater(() -> cipherTextArea.setText(resultStr));
                    }
                    return null;
                }
                @Override
                protected void done() {
                    progress.dispose();
                    try {
                        get();
                        if (fHasAttachments) {
                            JOptionPane.showMessageDialog(SendPanel.this,
                                    "Encrypted file saved successfully.",
                                    "OK", JOptionPane.INFORMATION_MESSAGE);
                        }
                    } catch (Exception ex) {
                        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                        if (cause.getMessage() != null && cause.getMessage().contains("checksum")) {
                            JOptionPane.showMessageDialog(SendPanel.this, "Wrong password for private key.",
                                    "Error", JOptionPane.ERROR_MESSAGE);
                            if (!fSignKeys.isEmpty()) engine.clearPassphraseCache();
                        } else {
                            JOptionPane.showMessageDialog(SendPanel.this,
                                    "Error during encryption:\n" + cause.getMessage(),
                                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
            };
            worker.execute();
            progress.setVisible(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            if (ex.getMessage() != null && ex.getMessage().contains("checksum")) {
                JOptionPane.showMessageDialog(this, "Wrong password for private key.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                if (!signKeys.isEmpty()) engine.clearPassphraseCache();
            } else {
                JOptionPane.showMessageDialog(this, "Error during encryption:\n" + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private class EncryptLayerPanel extends JPanel {
        final JCheckBox usePasswordCheckBox;
        final JPasswordField passwordField;
        final JPasswordField verifyField;
        final JCheckBox showPasswordCheckBox;
        final JLabel matchLabel;
        final KeyTreePanel keyPanel;
        final JComboBox<String> algoCombo;
        final CardLayout cardLayout;
        final JPanel cardsPanel;
        final List<String> keyringPaths = new ArrayList<>();

        EncryptLayerPanel() {
            super(new BorderLayout(0, 2));

            usePasswordCheckBox = new JCheckBox("Use password");
            algoCombo = new JComboBox<>(new String[]{"AES-128", "AES-192", "AES-256", "CAST5", "Blowfish", "Triple-DES", "Twofish"});
            algoCombo.setSelectedItem("AES-128");

            // Password card — aligned top, aligned labels/fields
            JPanel passwordCard = new JPanel(new BorderLayout());
            JPanel pwRows = new JPanel(new GridBagLayout());
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(1, 4, 1, 4);
            g.gridx = 0; g.anchor = GridBagConstraints.EAST;
            pwRows.add(new JLabel("Password:"), g);
            g.gridx = 1; g.anchor = GridBagConstraints.WEST; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
            passwordField = new JPasswordField(20);
            pwRows.add(passwordField, g);
            g.gridy = 1; g.gridx = 0; g.weightx = 0; g.fill = GridBagConstraints.NONE; g.anchor = GridBagConstraints.EAST;
            pwRows.add(new JLabel("Verify:"), g);
            g.gridx = 1; g.anchor = GridBagConstraints.WEST; g.fill = GridBagConstraints.HORIZONTAL;
            verifyField = new JPasswordField(20);
            pwRows.add(verifyField, g);
            g.gridy = 2; g.gridx = 0; g.gridwidth = 2; g.anchor = GridBagConstraints.WEST; g.fill = GridBagConstraints.NONE;
            showPasswordCheckBox = new JCheckBox("Show password");
            pwRows.add(showPasswordCheckBox, g);
            g.gridy = 3;
            matchLabel = new JLabel(" ");
            matchLabel.setFont(matchLabel.getFont().deriveFont(Font.PLAIN));
            pwRows.add(matchLabel, g);
            passwordCard.add(pwRows, BorderLayout.NORTH);

            // Public key card
            keyPanel = new KeyTreePanel("Recipient Public Key (Encrypt)", true, false);
            JPanel keyCard = new JPanel(new BorderLayout());
            keyCard.add(keyPanel, BorderLayout.CENTER);

            // CardLayout
            cardLayout = new CardLayout();
            cardsPanel = new JPanel(cardLayout);
            cardsPanel.add(passwordCard, "password");
            cardsPanel.add(keyCard, "publickey");
            cardLayout.show(cardsPanel, "publickey");

            // Top row
            JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            topRow.add(usePasswordCheckBox);
            topRow.add(new JLabel("Algo:"));
            topRow.add(algoCombo);
            add(topRow, BorderLayout.NORTH);
            add(cardsPanel, BorderLayout.CENTER);

            usePasswordCheckBox.addActionListener(e -> {
                boolean pwMode = usePasswordCheckBox.isSelected();
                cardLayout.show(cardsPanel, pwMode ? "password" : "publickey");
                updateEncryptButton();
                updateActiveEncLayer();
            });

            showPasswordCheckBox.addActionListener(e -> {
                char echo = showPasswordCheckBox.isSelected() ? (char) 0 : '\u2022';
                passwordField.setEchoChar(echo);
                verifyField.setEchoChar(echo);
            });

            DocumentListener docListener = new DocumentListener() {
                private void upd() { updateEncryptButton(); updateMatchLabel(); }
                @Override public void insertUpdate(DocumentEvent e) { upd(); }
                @Override public void removeUpdate(DocumentEvent e) { upd(); }
                @Override public void changedUpdate(DocumentEvent e) { upd(); }
            };
            passwordField.getDocument().addDocumentListener(docListener);
            verifyField.getDocument().addDocumentListener(docListener);

            // Initial match state
            updateMatchLabel();

            keyPanel.addSelectionListener(e -> updateEncryptButton());
            keyPanel.addViewModeListener(active -> {
                updateFilterField();
                updateShowViewButton();
            });
        }

        void loadKeyring(File file) {
            try {
                KeyBundle bundle = KeyringLoader.loadPublicKeys(file);
                keyPanel.setKeys(null);
                keyPanel.resetKeyringCount();
                keyPanel.setKeys(bundle.getKeys());
                keyPanel.setSourceFile(file.getAbsolutePath());
                keyringPaths.clear();
                keyringPaths.add(file.getAbsolutePath());
                userFilterField.setText("");
                updateFilterField();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(SendPanel.this,
                    "Error loading public key:\n" + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
            updateEncryptButton();
            updateShowViewButton();
        }

        void addKeyring(File file) {
            try {
                KeyBundle bundle = KeyringLoader.loadPublicKeys(file);
                keyPanel.addKeys(bundle.getKeys());
                keyPanel.incrementKeyringCount();
                keyringPaths.add(file.getAbsolutePath());
                updateFilterField();
                updateEncryptButton();
                updateShowViewButton();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(SendPanel.this,
                    "Error loading public key:\n" + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        void updateMatchLabel() {
            char[] pw = passwordField.getPassword();
            char[] vw = verifyField.getPassword();
            boolean bothEmpty = (pw == null || pw.length == 0) && (vw == null || vw.length == 0);
            boolean match = java.util.Arrays.equals(pw, vw);
            if (bothEmpty) {
                matchLabel.setText(" ");
                matchLabel.setForeground(UIManager.getColor("Label.foreground"));
            } else if (match) {
                matchLabel.setText("\u2713 Passwords match");
                matchLabel.setForeground(new Color(0x009600));
            } else {
                matchLabel.setText("\u2717 Passwords do not match");
                matchLabel.setForeground(new Color(0xCC0000));
            }
        }
    }

    private void addEncryptLayer() {
        addEncryptLayer("AES-128");
    }

    private void addEncryptLayer(String initialAlgo) {
        suppressEncLayerTabListener++;
        try {
            EncryptLayerPanel layer = new EncryptLayerPanel();
            layer.algoCombo.setSelectedItem(initialAlgo);
            encLayers.add(layer);
            int insertIdx = advancedMode
                    ? encLayerTabs.getTabCount() - 1
                    : encLayerTabs.getTabCount();
            if (advancedMode) {
                encLayerTabs.insertTab(null, null, layer, null, insertIdx);
            } else {
                encLayerTabs.addTab(null, layer);
            }
            encLayerTabs.setSelectedIndex(insertIdx);
            refreshEncLayerTabComponents();
            updateActiveEncLayer();
            layer.keyPanel.getLoadButton().addActionListener(e -> loadEncKeyring(layer));
            layer.keyPanel.getAddButton().addActionListener(e -> addEncKeyring(layer));
            layer.keyPanel.setAddButtonVisible(true);
            layer.keyPanel.getClearButton();
            layer.keyPanel.setOnClearCallback(() -> {
                layer.keyPanel.setKeys(null);
                layer.keyPanel.setSourceFile(null);
                layer.keyringPaths.clear();
                updateEncryptButton();
            });
            setupEncLayerDrop(layer.keyPanel, layer);
            layer.keyPanel.getLoadButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(f -> layer.loadKeyring(f)));
            layer.keyPanel.getAddButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(f -> layer.addKeyring(f)));
        } finally {
            suppressEncLayerTabListener--;
        }
    }

    private void removeEncryptLayer(EncryptLayerPanel layer) {
        if (encLayers.size() <= 1) return;
        suppressEncLayerTabListener++;
        try {
            int listIdx = encLayers.indexOf(layer);
            if (listIdx < 0) return;
            encLayers.remove(listIdx);
            encLayerTabs.removeTabAt(listIdx);
            if (encLayerTabs.getSelectedIndex() == encLayerTabs.getTabCount() - 1
                    && encLayerTabs.getSelectedIndex() > 0) {
                encLayerTabs.setSelectedIndex(encLayerTabs.getSelectedIndex() - 1);
            }
            refreshEncLayerTabComponents();
            updateActiveEncLayer();
            updateEncryptButton();
        } finally {
            suppressEncLayerTabListener--;
        }
    }

    private void refreshEncLayerTabComponents() {
        int n = encLayers.size();
        for (int i = 0; i < n; i++) {
            if (advancedMode) {
                JPanel comp = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
                comp.setOpaque(false);
                comp.add(new JLabel("Encrypt " + (i + 1)));
                if (n > 1) {
                    JButton closeBtn = new JButton("\u00D7");
                    closeBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
                    closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
                    closeBtn.setContentAreaFilled(false);
                    closeBtn.setFocusable(false);
                    closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    EncryptLayerPanel layer = encLayers.get(i);
                    closeBtn.addActionListener(ev -> removeEncryptLayer(layer));
                    comp.add(closeBtn);
                }
                encLayerTabs.setTabComponentAt(i, comp);
            } else {
                encLayerTabs.setTitleAt(i, " ");
                encLayerTabs.setTabComponentAt(i, null);
            }
        }
        if (advancedMode && encLayerTabs.getTabCount() > 0) {
            encLayerTabs.setTitleAt(encLayerTabs.getTabCount() - 1, "+");
            encLayerTabs.setTabComponentAt(encLayerTabs.getTabCount() - 1, null);
        }
    }

    private void updateActiveEncLayer() {
        int idx = encLayerTabs.getSelectedIndex();
        if (idx >= 0 && idx < encLayers.size()) {
            EncryptLayerPanel layer = encLayers.get(idx);
            if (layer.usePasswordCheckBox.isSelected()) {
                activeEncKeyPanel = null;
                userFilterField.setEnabled(false);
                clearSelButton.setEnabled(false);
                showViewBtn.setEnabled(false);
                return;
            }
            activeEncKeyPanel = layer.keyPanel;
        } else {
            activeEncKeyPanel = null;
            updateFilterField();
            updateShowViewButton();
            return;
        }
        updateFilterField();
        updateShowViewButton();
    }

    private void loadEncKeyring(EncryptLayerPanel layer) {
        JFileChooser fc = createPublicFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            layer.loadKeyring(fc.getSelectedFile());
    }

    private void addEncKeyring(EncryptLayerPanel layer) {
        JFileChooser fc = createPublicFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            layer.addKeyring(fc.getSelectedFile());
    }

    private void setupEncLayerDrop(KeyTreePanel panel, EncryptLayerPanel layer) {
        panel.setTransferHandler(new TransferHandler() {
            @Override public boolean canImport(TransferSupport support) {
                return support.getComponent().isEnabled()
                    && support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override public boolean importData(TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    if (support.isDrop() && support.getDropAction() == MOVE)
                        layer.addKeyring(files.get(0));
                    else
                        layer.loadKeyring(files.get(0));
                    return true;
                } catch (Exception ex) { return false; }
            }
        });
    }

    private class SignerPanel extends JPanel {
        final KeyTreePanel keyPanel;
        final JComboBox<String> hashCombo;
        String keyringPath;

        SignerPanel() {
            super(new BorderLayout(0, 2));
            keyPanel = new KeyTreePanel("Sender Private Key (Signature)", false, true);
            hashCombo = new JComboBox<>(new String[]{"SHA-256", "SHA-384", "SHA-512", "RIPEMD160"});
            hashCombo.setSelectedItem("SHA-256");
            hashCombo.setEnabled(false);

            JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            topRow.add(new JLabel("Hash:"));
            topRow.add(hashCombo);
            add(topRow, BorderLayout.NORTH);
            add(keyPanel, BorderLayout.CENTER);

            keyPanel.addSelectionListener(e -> {
                boolean hasSigning = keyPanel.getSelectedKeys().stream()
                    .anyMatch(PGPKeyInfo::canSign);
                hashCombo.setEnabled(hasSigning);
                updateSignCheckbox();
            });
        }

        void loadKeyring(File file) {
            try {
                KeyBundle bundle = KeyringLoader.loadSecretKeys(file);
                keyPanel.setKeys(bundle.getKeys());
                keyPanel.setSourceFile(file.getAbsolutePath());
                keyringPath = file.getAbsolutePath();
                keyPanel.selectDefaultIfEmpty();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(SendPanel.this,
                    "Error loading private key:\n" + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
            updateSignCheckbox();
        }
    }

    private void addSignerTab() {
        addSignerTab("SHA-256");
    }

    private void addSignerTab(String initialHash) {
        suppressTabListener++;
        try {
            SignerPanel sp = new SignerPanel();
            sp.hashCombo.setSelectedItem(initialHash);
            sp.keyPanel.setAutoSelectEnabled(signerPanels.isEmpty());
            signerPanels.add(sp);
            int insertIdx = advancedMode
                    ? signerTabs.getTabCount() - 1
                    : signerTabs.getTabCount();
            if (advancedMode) {
                signerTabs.insertTab(null, null, sp, null, insertIdx);
            } else {
                signerTabs.addTab(null, sp);
            }
            signerTabs.setSelectedIndex(insertIdx);
            refreshTabComponents();
            sp.keyPanel.getLoadButton().addActionListener(e -> loadPrivateKeyring(sp));
            sp.keyPanel.getClearButton();
            sp.keyPanel.setOnClearCallback(() -> {
                sp.keyPanel.setKeys(null);
                sp.keyPanel.setSourceFile(null);
                sp.keyringPath = null;
                updateSignCheckbox();
            });
            setupSignerDrop(sp.keyPanel, sp);
            sp.keyPanel.getLoadButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(f -> sp.loadKeyring(f)));
        } finally {
            suppressTabListener--;
        }
    }

    private void refreshTabComponents() {
        int n = signerPanels.size();
        for (int i = 0; i < n; i++) {
            if (advancedMode) {
                JPanel comp = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
                comp.setOpaque(false);
                comp.add(new JLabel("Signer " + (i + 1)));
                if (n > 1) {
                    JButton closeBtn = new JButton("\u00D7");
                    closeBtn.setFont(new Font("SansSerif", Font.PLAIN, 10));
                    closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
                    closeBtn.setContentAreaFilled(false);
                    closeBtn.setFocusable(false);
                    closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    SignerPanel sp = signerPanels.get(i);
                    closeBtn.addActionListener(ev -> removeSignerTab(sp));
                    comp.add(closeBtn);
                }
                signerTabs.setTabComponentAt(i, comp);
            } else {
                signerTabs.setTitleAt(i, " ");
                signerTabs.setTabComponentAt(i, null);
            }
        }
        if (advancedMode && signerTabs.getTabCount() > 0) {
            signerTabs.setTitleAt(signerTabs.getTabCount() - 1, "+");
            signerTabs.setTabComponentAt(signerTabs.getTabCount() - 1, null);
        }
    }

    private void removeSignerTab(SignerPanel sp) {
        if (signerPanels.size() <= 1) return;
        suppressTabListener++;
        try {
            int listIdx = signerPanels.indexOf(sp);
            if (listIdx < 0) return;
            signerPanels.remove(listIdx);
            signerTabs.removeTabAt(listIdx);
            if (signerTabs.getSelectedIndex() == signerTabs.getTabCount() - 1
                    && signerTabs.getSelectedIndex() > 0) {
                signerTabs.setSelectedIndex(signerTabs.getSelectedIndex() - 1);
            }
            refreshTabComponents();
            updateSignCheckbox();
        } finally {
            suppressTabListener--;
        }
    }

    private void loadPrivateKeyring(SignerPanel sp) {
        JFileChooser fc = createSecretFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            sp.loadKeyring(fc.getSelectedFile());
    }

    private void setupSignerDrop(KeyTreePanel panel, SignerPanel sp) {
        panel.setTransferHandler(new TransferHandler() {
            @Override public boolean canImport(TransferSupport support) {
                return support.getComponent().isEnabled()
                    && support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override public boolean importData(TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    sp.loadKeyring(files.get(0));
                    return true;
                } catch (Exception ex) { return false; }
            }
        });
    }

    private String resolveSignKeyUserId(PGPKeyInfo key, SignerPanel sp) {
        String uid = key.getUserId();
        if (uid != null) return uid;
        java.util.List<PGPKeyInfo> allKeys = sp.keyPanel.getAllKeys();
        if (allKeys == null) return null;
        for (PGPKeyInfo master : allKeys) {
            for (PGPKeyInfo sub : master.getSubKeys()) {
                if (sub.getKeyId() == key.getKeyId()) return master.getUserId();
            }
        }
        return null;
    }

    private void setEncLayersEnabled(boolean enabled) {
        for (EncryptLayerPanel layer : encLayers) {
            setRecursiveEnabled(layer, enabled);
        }
        encLayerTabs.setEnabled(enabled);
        if (enabled) {
            for (EncryptLayerPanel layer : encLayers)
                layer.keyPanel.refreshClearButtonState();
        }
    }

    private void setSignersEnabled(boolean enabled) {
        for (SignerPanel sp : signerPanels) {
            setRecursiveEnabled(sp, enabled);
        }
        signerTabs.setEnabled(enabled);
        if (enabled) {
            for (SignerPanel sp : signerPanels)
                sp.keyPanel.refreshClearButtonState();
        }
    }

    private void setRecursiveEnabled(Container c, boolean enabled) {
        for (Component child : c.getComponents()) {
            child.setEnabled(enabled);
            if (child instanceof Container) {
                setRecursiveEnabled((Container) child, enabled);
            }
        }
    }

    private static void hideTabArea(JTabbedPane pane) {
        pane.setUI(new javax.swing.plaf.basic.BasicTabbedPaneUI() {
            @Override
            protected int calculateTabAreaHeight(int tabPlacement, int runCount, int maxTabHeight) {
                return 0;
            }
            @Override
            protected int calculateTabAreaWidth(int tabPlacement, int runCount, int maxTabWidth) {
                return 0;
            }
            @Override
            protected Insets getTabAreaInsets(int tabPlacement) {
                return new Insets(0, 0, 0, 0);
            }
        });
    }


}
