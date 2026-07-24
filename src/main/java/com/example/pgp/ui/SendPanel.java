package com.example.pgp.ui;

import com.example.pgp.model.CompoundCodec;
import com.example.pgp.model.CompoundMessage;
import com.example.pgp.model.KeyBundle;
import com.example.pgp.model.PGPKeyInfo;
import com.example.pgp.service.KeyringLoader;
import com.example.pgp.service.PGPEngine;
import com.example.pgp.service.ProgressCallback;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class SendPanel extends JPanel {

    private final transient PGPEngine engine;
    private final KeyTreePanel privateKeyPanel;
    private final KeyTreePanel publicKeyPanel;
    private final JTextArea plainTextArea;
    private final JTextArea cipherTextArea;
    private final JCheckBox signCheckBox;
    private final JButton encryptButton;
    private final JTextField userFilterField;
    private final JButton clearSelButton;
    private final JToggleButton showViewBtn;
    private final JComboBox<String> encModeCombo;
    private final JComboBox<String> encAlgoCombo;
    private final JComboBox<String> compAlgoCombo;
    private final JComboBox<String> hashAlgoCombo;
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

    private transient KeyBundle publicKeyBundle;
    private transient KeyBundle privateKeyBundle;

    private final java.util.List<String> publicKeyringPaths = new java.util.ArrayList<>();
    private final java.util.List<String> privateKeyringPaths = new java.util.ArrayList<>();

    public SendPanel(PGPEngine engine) {
        this.engine = engine;
        setLayout(new BorderLayout(5, 5));

        privateKeyPanel = new KeyTreePanel("Chiave privata mittente (firma)", false, true);
        publicKeyPanel = new KeyTreePanel("Chiave pubblica destinatario (cifratura)", true, false);
        plainTextArea = new JTextArea(12, 40);
        cipherTextArea = new JTextArea(12, 40);
        signCheckBox = new JCheckBox("Firma");
        encryptButton = new JButton("Encrypt");
        encAlgoCombo = new JComboBox<>(new String[]{"AES-128", "AES-192", "AES-256", "CAST5", "Blowfish", "Triple-DES", "Twofish"});
        encAlgoCombo.setSelectedItem("AES-128");
        encAlgoCombo.setEnabled(false);
        encModeCombo = new JComboBox<>(new String[]{"Public Key", "Password", "Compress"});
        encModeCombo.setSelectedItem("Public Key");
        compAlgoCombo = new JComboBox<>(new String[]{"ZIP", "ZLIB", "BZIP2", "None"});
        compAlgoCombo.setSelectedItem("ZLIB");
        compAlgoCombo.setEnabled(false);
        hashAlgoCombo = new JComboBox<>(new String[]{"SHA-256", "SHA-384", "SHA-512", "RIPEMD160"});
        hashAlgoCombo.setSelectedItem("SHA-256");
        hashAlgoCombo.setEnabled(false);

        Font mono = new Font("Monospaced", Font.PLAIN, 12);
        plainTextArea.setFont(mono);
        cipherTextArea.setFont(mono);
        cipherTextArea.setLineWrap(true);
        cipherTextArea.setWrapStyleWord(true);
        cipherTextArea.setEditable(false);

        signCheckBox.setEnabled(false);
        signCheckBox.setSelected(false);
        encryptButton.setEnabled(false);

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                privateKeyPanel, wrapInScroll(plainTextArea, "Plain Text Message"));
        topSplit.setResizeWeight(0.35);

        outputCardLayout = new CardLayout();
        outputCardPanel = new JPanel(outputCardLayout);

        outputCardPanel.add(wrapInScroll(cipherTextArea, "Armored Ciphertext"), "text");

        JPanel fileOutputPanel = new JPanel(new BorderLayout(5, 5));
        fileOutputPanel.setBorder(BorderFactory.createTitledBorder("File Output"));
        JPanel fileRow = new JPanel(new BorderLayout(5, 2));
        outputFileField = new JTextField();
        outputFileField.setEditable(false);
        JButton outputBrowseBtn = new JButton("Sfoglia...");
        armorCheckBox = new JCheckBox("ASCII Armor", true);
        fileRow.add(new JLabel("File:"), BorderLayout.WEST);
        fileRow.add(outputFileField, BorderLayout.CENTER);
        JPanel btnEast = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        btnEast.add(outputBrowseBtn);
        btnEast.add(armorCheckBox);
        fileRow.add(btnEast, BorderLayout.EAST);
        fileOutputPanel.add(fileRow, BorderLayout.CENTER);

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                publicKeyPanel, outputCardPanel);
        bottomSplit.setResizeWeight(0.35);

        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        centerPanel.add(encryptButton);
        centerPanel.add(new JLabel("Mode:"));
        centerPanel.add(encModeCombo);
        centerPanel.add(new JLabel("Enc:"));
        centerPanel.add(encAlgoCombo);
        centerPanel.add(new JLabel("Comp:"));
        centerPanel.add(compAlgoCombo);
        centerPanel.add(signCheckBox);
        centerPanel.add(new JLabel("Hash:"));
        centerPanel.add(hashAlgoCombo);
        addAttachButton = new JButton("Add File...");
        removeAttachButton = new JButton("Remove");
        removeAttachButton.setEnabled(false);
        centerPanel.add(addAttachButton);
        centerPanel.add(removeAttachButton);
        centerPanel.add(new JLabel("User:"));
        userFilterField = new JTextField(12);
        centerPanel.add(userFilterField);
        userFilterField.setEnabled(false);
        userFilterField.getDocument().addDocumentListener(new DocumentListener() {
            private void apply() {
                SwingUtilities.invokeLater(() ->
                        publicKeyPanel.setFilterText(userFilterField.getText()));
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
        clearSelButton.addActionListener(e -> publicKeyPanel.clearSelection());
        centerPanel.add(clearSelButton);
        showViewBtn = new JToggleButton("Show Sel");
        showViewBtn.setEnabled(false);
        showViewBtn.addActionListener(e -> publicKeyPanel.setSelectedViewActive(showViewBtn.isSelected()));
        centerPanel.add(showViewBtn);

        attachListModel = new DefaultListModel<>();
        attachList = new JList<>(attachListModel);
        attachList.setVisibleRowCount(3);
        JScrollPane attachScroll = new JScrollPane(attachList);
        attachScroll.setBorder(BorderFactory.createTitledBorder("Allegati"));

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

        privateKeyPanel.getLoadButton().addActionListener(this::loadPrivateKeyring);
        publicKeyPanel.getLoadButton().addActionListener(this::loadPublicKeyring);
        publicKeyPanel.getAddButton().addActionListener(e -> addPublicKeyring());
        publicKeyPanel.setAddButtonVisible(true);
        encryptButton.addActionListener(this::onEncrypt);
        encModeCombo.addActionListener(e -> {
            String mode = (String) encModeCombo.getSelectedItem();
            boolean isPublicKey = "Public Key".equals(mode);
            publicKeyPanel.setLoadEnabled(isPublicKey);
            publicKeyPanel.setAddButtonEnabled(isPublicKey);
            encAlgoCombo.setEnabled(isPublicKey || "Password".equals(mode));
            updateEncryptButton();
        });
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
                                        String[] options = {"Incolla come testo", "Allega come file"};
                                        int ret = JOptionPane.showOptionDialog(
                                                plainTextArea,
                                                "Il file \"" + f.getName() + "\" (" + sizeStr + ") è testuale.\n"
                                                        + "Come desideri gestirlo?",
                                                "File testuale rilevato",
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
        privateKeyPanel.addSelectionListener(e -> updateSignCheckbox());
        publicKeyPanel.addSelectionListener(e -> updateEncryptButton());
        publicKeyPanel.addViewModeListener(active -> {
            updateFilterField();
            updateShowViewButton();
        });

        setupKeyDrop(privateKeyPanel, false);
        setupKeyDrop(publicKeyPanel, true);

        privateKeyPanel.getClearButton();
        privateKeyPanel.setOnClearCallback(() -> {
            privateKeyBundle = null;
            privateKeyringPaths.clear();
        });

        publicKeyPanel.getClearButton();
        publicKeyPanel.setOnClearCallback(() -> {
            publicKeyBundle = null;
            publicKeyringPaths.clear();
        });

        setupKeyButtonDrops();
    }

    private void setupKeyButtonDrops() {
        publicKeyPanel.getLoadButton().setTransferHandler(
                createKeyringDropHandler(this::loadPublicKeyring));
        publicKeyPanel.getAddButton().setTransferHandler(
                createKeyringDropHandler(this::loadPublicKeyringAdd));
        privateKeyPanel.getLoadButton().setTransferHandler(
                createKeyringDropHandler(this::loadPrivateKeyring));
    }

    private TransferHandler createKeyringDropHandler(java.util.function.Consumer<File> handler) {
        return new TransferHandler() {
            @Override public boolean canImport(TransferSupport support) {
                return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override public boolean importData(TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>)
                            support.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!files.isEmpty()) handler.accept(files.get(0));
                    return true;
                } catch (Exception ex) { return false; }
            }
        };
    }

    private JScrollPane wrapInScroll(JTextArea ta, String title) {
        JScrollPane sp = new JScrollPane(ta);
        sp.setBorder(BorderFactory.createTitledBorder(title));
        return sp;
    }

    private void loadPrivateKeyring(ActionEvent e) {
        JFileChooser fc = createSecretFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadPrivateKeyring(fc.getSelectedFile());
        }
    }

    private void loadPrivateKeyring(File file) {
        try {
            engine.clearPassphraseCache();
            privateKeyBundle = KeyringLoader.loadSecretKeys(file);
            privateKeyPanel.setKeys(privateKeyBundle.getKeys());
            privateKeyPanel.setSourceFile(file.getAbsolutePath());
            privateKeyringPaths.clear();
            privateKeyringPaths.add(file.getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Errore caricamento chiave privata:\n" + ex.getMessage(),
                    "Errore", JOptionPane.ERROR_MESSAGE);
            privateKeyBundle = null;
            privateKeyPanel.setKeys(null);
        }
        updateSignCheckbox();
    }

    private void loadPublicKeyring(ActionEvent e) {
        JFileChooser fc = createPublicFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadPublicKeyring(fc.getSelectedFile());
        }
    }

    private void loadPublicKeyring(File file) {
        try {
            publicKeyBundle = KeyringLoader.loadPublicKeys(file);
            publicKeyPanel.resetKeyringCount();
            publicKeyPanel.setKeys(publicKeyBundle.getKeys());
            publicKeyPanel.setSourceFile(file.getAbsolutePath());
            userFilterField.setText("");
            updateFilterField();
            publicKeyringPaths.clear();
            publicKeyringPaths.add(file.getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Errore caricamento chiave pubblica:\n" + ex.getMessage(),
                    "Errore", JOptionPane.ERROR_MESSAGE);
            publicKeyBundle = null;
            publicKeyPanel.setKeys(null);
        }
        updateEncryptButton();
        updateShowViewButton();
    }

    private void addPublicKeyring() {
        JFileChooser fc = createPublicFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadPublicKeyringAdd(fc.getSelectedFile());
        }
    }

    private void loadPublicKeyringAdd(File file) {
        try {
            KeyBundle bundle = KeyringLoader.loadPublicKeys(file);
            publicKeyPanel.addKeys(bundle.getKeys());
            publicKeyPanel.incrementKeyringCount();
            mergePublicKeyBundle(bundle);
            publicKeyringPaths.add(file.getAbsolutePath());
            updateFilterField();
            updateEncryptButton();
            updateShowViewButton();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Errore caricamento chiave pubblica:\n" + ex.getMessage(),
                    "Errore", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void mergePublicKeyBundle(KeyBundle bundle) {
        if (publicKeyBundle != null) {
            java.util.Set<Long> ids = new java.util.HashSet<>();
            for (PGPKeyInfo k : publicKeyBundle.getKeys()) {
                ids.add(k.getKeyId());
                for (PGPKeyInfo s : k.getSubKeys()) ids.add(s.getKeyId());
            }
            for (PGPKeyInfo k : bundle.getKeys()) {
                if (!ids.contains(k.getKeyId())) {
                    publicKeyBundle.getKeys().add(k);
                    ids.add(k.getKeyId());
                }
            }
        } else {
            publicKeyBundle = bundle;
        }
    }

    private void updateFilterField() {
        boolean multi = publicKeyPanel.hasMultipleMasterKeys();
        boolean active = publicKeyPanel.isSelectedViewActive();
        userFilterField.setEnabled(!active && multi);
        clearSelButton.setEnabled(!active && multi);
    }

    private void setupKeyDrop(KeyTreePanel panel, boolean isPublic) {
        panel.setTransferHandler(new TransferHandler() {
            @Override public boolean canImport(TransferHandler.TransferSupport support) {
                return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override public boolean importData(TransferHandler.TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    if (isPublic) {
                        if (support.isDrop() && support.getDropAction() == MOVE)
                            loadPublicKeyringAdd(files.get(0));
                        else
                            loadPublicKeyring(files.get(0));
                    } else {
                        loadPrivateKeyring(files.get(0));
                    }
                    return true;
                } catch (Exception ex) { return false; }
            }
        });
    }

    private void updateEncryptButton() {
        if (!attachmentFiles.isEmpty()) {
            updateOutputMode();
            return;
        }
        String mode = (String) encModeCombo.getSelectedItem();
        if ("Compress".equals(mode)) {
            encryptButton.setEnabled(true);
            encAlgoCombo.setEnabled(false);
            compAlgoCombo.setEnabled(true);
            return;
        }
        boolean isPassword = "Password".equals(mode);
        if (isPassword) {
            encryptButton.setEnabled(true);
            encAlgoCombo.setEnabled(true);
            compAlgoCombo.setEnabled(true);
            return;
        }
        // Public Key mode
        List<PGPKeyInfo> sel = publicKeyPanel.getSelectedKeys();
        boolean hasKeys = sel.stream().anyMatch(PGPKeyInfo::canEncrypt);
        if (!attachmentFiles.isEmpty()) {
            boolean outputChosen = outputFileField.getText() != null && !outputFileField.getText().trim().isEmpty();
            encryptButton.setEnabled(hasKeys && outputChosen);
        } else {
            encryptButton.setEnabled(hasKeys);
        }
        encAlgoCombo.setEnabled(hasKeys);
        compAlgoCombo.setEnabled(hasKeys);
        updateShowViewButton();
    }

    private void updateSignCheckbox() {
        PGPKeyInfo sel = privateKeyPanel.getSelectedKey();
        boolean valid = sel != null && sel.canSign();
        signCheckBox.setEnabled(valid);
        signCheckBox.setSelected(valid);
        hashAlgoCombo.setEnabled(valid);
    }

    private void updateShowViewButton() {
        boolean active = publicKeyPanel.isSelectedViewActive();
        showViewBtn.setSelected(active);
        if (active) {
            showViewBtn.setEnabled(true);
        } else {
            showViewBtn.setEnabled(publicKeyPanel.getSelectedKeys().size() >= 2);
        }
    }

    private void updateOutputMode() {
        boolean has = !attachmentFiles.isEmpty();
        outputCardLayout.show(outputCardPanel, has ? "compound" : "text");
        if (has) {
            String mode = (String) encModeCombo.getSelectedItem();
            boolean outputChosen = outputFileField.getText() != null && !outputFileField.getText().trim().isEmpty();
            if ("Compress".equals(mode)) {
                encryptButton.setEnabled(outputChosen);
                encAlgoCombo.setEnabled(false);
                compAlgoCombo.setEnabled(true);
            } else if ("Password".equals(mode)) {
                encryptButton.setEnabled(outputChosen);
                encAlgoCombo.setEnabled(true);
                compAlgoCombo.setEnabled(true);
            } else {
                boolean hasKeys = publicKeyPanel.getSelectedKeys().stream().anyMatch(PGPKeyInfo::canEncrypt);
                encryptButton.setEnabled(hasKeys && outputChosen);
                encAlgoCombo.setEnabled(hasKeys);
                compAlgoCombo.setEnabled(hasKeys);
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
        prefs.put("enc_algo", (String) encAlgoCombo.getSelectedItem());
        prefs.put("comp_algo", (String) compAlgoCombo.getSelectedItem());
        prefs.put("hash_algo", (String) hashAlgoCombo.getSelectedItem());
        prefs.put("send_pub_paths", String.join(File.pathSeparator, publicKeyringPaths));
        prefs.put("send_priv_paths", String.join(File.pathSeparator, privateKeyringPaths));
    }

    public void restorePreferences(java.util.prefs.Preferences prefs) {
        encAlgoCombo.setSelectedItem(prefs.get("enc_algo", "AES-128"));
        compAlgoCombo.setSelectedItem(prefs.get("comp_algo", "ZLIB"));
        hashAlgoCombo.setSelectedItem(prefs.get("hash_algo", "SHA-256"));

        String pubPaths = prefs.get("send_pub_paths", "");
        if (!pubPaths.isEmpty()) {
            for (String path : pubPaths.split(File.pathSeparator)) {
                File f = new File(path);
                if (f.exists()) {
                    if (publicKeyringPaths.isEmpty()) {
                        loadPublicKeyring(f);
                    } else {
                        loadPublicKeyringAdd(f);
                    }
                } else {
                    System.err.println("File non trovato: " + path);
                }
            }
        }

        String privPaths = prefs.get("send_priv_paths", "");
        if (!privPaths.isEmpty()) {
            for (String path : privPaths.split(File.pathSeparator)) {
                File f = new File(path);
                if (f.exists()) {
                    loadPrivateKeyring(f);
                } else {
                    System.err.println("File non trovato: " + path);
                }
            }
        }
    }

    private void onEncrypt(ActionEvent e) {
        String mode = (String) encModeCombo.getSelectedItem();
        boolean isPassword = "Password".equals(mode);
        boolean isCompress = "Compress".equals(mode);
        boolean isPublicKey = !isPassword && !isCompress;

        List<PGPPublicKey> encKeys = null;
        if (isPublicKey) {
            List<PGPKeyInfo> selectedPubs = publicKeyPanel.getSelectedKeys();
            encKeys = new ArrayList<>();
            for (PGPKeyInfo ki : selectedPubs) {
                if (ki.canEncrypt()) encKeys.add(ki.getBcKey(PGPPublicKey.class));
            }
            if (encKeys.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Seleziona almeno una chiave pubblica con capacita' di cifratura.",
                        "Errore", JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        char[] messagePassword = null;
        if (isPassword) {
            PasswordDialog pwdDlg = new PasswordDialog(
                    (Frame) SwingUtilities.getWindowAncestor(this),
                    "cifratura simmetrica", PasswordDialog.Mode.CREATE);
            pwdDlg.setVisible(true);
            messagePassword = pwdDlg.getPassword();
            if (messagePassword == null) return;
        }

        String plainText = plainTextArea.getText();
        boolean hasAttachments = !attachmentFiles.isEmpty();

        if (!hasAttachments && plainText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Inserisci il messaggio da cifrare.",
                    "Attenzione", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (hasAttachments && (outputFileField.getText() == null || outputFileField.getText().trim().isEmpty())) {
            JOptionPane.showMessageDialog(this, "Scegli il file di output.",
                    "Attenzione", JOptionPane.WARNING_MESSAGE);
            return;
        }

        PGPSecretKey signKey = null;
        char[] signPassphrase = null;

        if (signCheckBox.isSelected()) {
            PGPKeyInfo selectedPriv = privateKeyPanel.getSelectedKey();
            if (selectedPriv == null) {
                JOptionPane.showMessageDialog(this, "Seleziona una chiave privata per firmare.",
                        "Errore", JOptionPane.WARNING_MESSAGE);
                return;
            }
            signKey = selectedPriv.getBcKey(PGPSecretKey.class);
            long keyId = signKey.getKeyID();

            if (!engine.hasPassphrase(keyId)) {
                if (engine.cacheEmptyPassphraseIfUnprotected(signKey)) {
                    signPassphrase = new char[0];
                } else {
                    PasswordDialog dlg = new PasswordDialog(
                            (Frame) SwingUtilities.getWindowAncestor(this),
                            resolveSignKeyUserId(selectedPriv), selectedPriv.getKeyIdHex(),
                            PasswordDialog.Mode.REQUEST);
                    dlg.setVisible(true);
                    signPassphrase = dlg.getPassword();
                    if (signPassphrase == null) return;
                    engine.cachePassphrase(keyId, signPassphrase);
                }
            } else {
                signPassphrase = engine.getPassphraseFor(keyId);
            }
        }

        try {
            int symAlgo = isCompress ? 0 : mapEncAlgo((String) encAlgoCombo.getSelectedItem());
            int compAlgo = mapCompAlgo((String) compAlgoCombo.getSelectedItem());
            int hashAlgo = mapHashAlgo((String) hashAlgoCombo.getSelectedItem());

            final String fMode = mode;
            final String fPlainText = plainText;
            final boolean fHasAttachments = hasAttachments;
            final List<PGPPublicKey> fEncKeys = encKeys;
            final char[] fMessagePassword = messagePassword;
            final PGPSecretKey fSignKey = signKey;
            final char[] fSignPassphrase = signPassphrase;

            Frame owner = (Frame) SwingUtilities.getWindowAncestor(this);
            ProgressDialog progress = new ProgressDialog(owner, "Cifratura in corso");

            SwingWorker<Void, Void> worker = new SwingWorker<>() {
                @Override
                protected Void doInBackground() throws Exception {
                    if (fHasAttachments) {
                        boolean rawFile = fPlainText.isEmpty() && attachmentFiles.size() == 1;
                        String fileName = rawFile ? attachmentFiles.get(0).getName() : "_CONSOLE";
                        byte[] data;
                        if (rawFile) {
                            data = Files.readAllBytes(attachmentFiles.get(0).toPath());
                        } else {
                            List<CompoundMessage.Attachment> atts = new ArrayList<>();
                            for (File f : attachmentFiles) {
                                atts.add(new CompoundMessage.Attachment(f.getName(), Files.readAllBytes(f.toPath())));
                            }
                            data = CompoundCodec.encode(new CompoundMessage(fPlainText, atts));
                        }
                        boolean armor = armorCheckBox.isSelected();
                        byte[] encrypted = encryptWithMode(fMode, data, fileName, fEncKeys, fMessagePassword,
                                fSignKey, fSignPassphrase, symAlgo, compAlgo, hashAlgo, armor, progress);
                        Files.write(new File(outputFileField.getText().trim()).toPath(), encrypted);
                    } else {
                        String result = encryptWithModeText(fPlainText, fEncKeys, fMessagePassword,
                                fSignKey, fSignPassphrase, symAlgo, compAlgo, hashAlgo, progress);
                        if (result != null) {
                            SwingUtilities.invokeLater(() -> cipherTextArea.setText(result));
                        }
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
                                    "File cifrato salvato correttamente.",
                                    "OK", JOptionPane.INFORMATION_MESSAGE);
                        }
                    } catch (Exception ex) {
                        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                        if (cause.getMessage() != null && cause.getMessage().contains("checksum")) {
                            JOptionPane.showMessageDialog(SendPanel.this, "Password errata per la chiave privata.",
                                    "Errore", JOptionPane.ERROR_MESSAGE);
                            if (fSignKey != null) engine.clearPassphraseCache();
                        } else {
                            JOptionPane.showMessageDialog(SendPanel.this,
                                    "Errore durante la cifratura:\n" + cause.getMessage(),
                                    "Errore", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            };
            worker.execute();
            progress.setVisible(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            if (ex.getMessage() != null && ex.getMessage().contains("checksum")) {
                JOptionPane.showMessageDialog(this, "Password errata per la chiave privata.",
                        "Errore", JOptionPane.ERROR_MESSAGE);
                if (signKey != null) engine.clearPassphraseCache();
            } else {
                JOptionPane.showMessageDialog(this, "Errore durante la cifratura:\n" + ex.getMessage(),
                        "Errore", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private byte[] encryptWithMode(String mode, byte[] data, String fileName,
                                    List<PGPPublicKey> encKeys, char[] messagePassword,
                                    PGPSecretKey signKey, char[] signPassphrase,
                                    int symAlgo, int compAlgo, int hashAlgo,
                                    boolean armor) throws Exception {
        return encryptWithMode(mode, data, fileName, encKeys, messagePassword,
                signKey, signPassphrase, symAlgo, compAlgo, hashAlgo, armor, null);
    }

    private byte[] encryptWithMode(String mode, byte[] data, String fileName,
                                    List<PGPPublicKey> encKeys, char[] messagePassword,
                                    PGPSecretKey signKey, char[] signPassphrase,
                                    int symAlgo, int compAlgo, int hashAlgo,
                                    boolean armor,
                                    ProgressCallback progress) throws Exception {
        switch (mode) {
            case "Password":
                return engine.encryptPassword(data, fileName, messagePassword,
                        signKey, signPassphrase, symAlgo, compAlgo, hashAlgo, armor, progress);
            case "Compress":
                return engine.encryptCompress(data, fileName,
                        signKey, signPassphrase, compAlgo, hashAlgo, armor, progress);
            default:
                return engine.encrypt(data, fileName, encKeys, signKey, signPassphrase,
                        symAlgo, compAlgo, hashAlgo, armor, progress);
        }
    }

    private String encryptWithModeText(String plainText,
                                        List<PGPPublicKey> encKeys, char[] messagePassword,
                                        PGPSecretKey signKey, char[] signPassphrase,
                                        int symAlgo, int compAlgo, int hashAlgo) throws Exception {
        return encryptWithModeText(plainText, encKeys, messagePassword,
                signKey, signPassphrase, symAlgo, compAlgo, hashAlgo, null);
    }

    private String encryptWithModeText(String plainText,
                                        List<PGPPublicKey> encKeys, char[] messagePassword,
                                        PGPSecretKey signKey, char[] signPassphrase,
                                        int symAlgo, int compAlgo, int hashAlgo,
                                        ProgressCallback progress) throws Exception {
        byte[] data = plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] result = encryptWithMode(
                (String) encModeCombo.getSelectedItem(),
                data, "_CONSOLE", encKeys, messagePassword,
                signKey, signPassphrase, symAlgo, compAlgo, hashAlgo, true, progress);
        return new String(result, java.nio.charset.StandardCharsets.UTF_8);
    }

    private String resolveSignKeyUserId(PGPKeyInfo key) {
        String uid = key.getUserId();
        if (uid != null) return uid;
        for (PGPKeyInfo master : privateKeyPanel.getAllKeys()) {
            for (PGPKeyInfo sub : master.getSubKeys()) {
                if (sub.getKeyId() == key.getKeyId()) return master.getUserId();
            }
        }
        return null;
    }

    private static boolean isBinaryContent(byte[] data, int len) {
        int control = 0;
        for (int i = 0; i < len; i++) {
            int b = data[i] & 0xFF;
            if (b == 0x00) return true;
            if (b < 0x09 || (b > 0x0D && b < 0x20) || b > 0x7E) control++;
        }
        return (double) control / len > 0.30;
    }

    private JFileChooser createPublicFileChooser() {
        JFileChooser fc = new JFileChooser();
        fc.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "Tutti i file (*.*)", "*"));
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "PGP Public Key files (*.asc, *.gpg, *.pgp, *.key, *.pkr)",
                "asc", "gpg", "pgp", "key", "pkr"));
        return fc;
    }

    private JFileChooser createSecretFileChooser() {
        JFileChooser fc = new JFileChooser();
        fc.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "Tutti i file (*.*)", "*"));
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "PGP Secret Key files (*.asc, *.gpg, *.pgp, *.key, *.skr)",
                "asc", "gpg", "pgp", "key", "skr"));
        return fc;
    }
}
