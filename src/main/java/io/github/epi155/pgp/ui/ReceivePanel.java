package io.github.epi155.pgp.ui;

import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.DecryptResult;
import io.github.epi155.pgp.model.KeyBundle;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.KeyringLoader;
import io.github.epi155.pgp.service.PGPEngine;
import io.github.epi155.pgp.service.ProgressCallback;
import static io.github.epi155.pgp.ui.UIUtils.createPublicFileChooser;
import static io.github.epi155.pgp.ui.UIUtils.createSecretFileChooser;
import static io.github.epi155.pgp.ui.UIUtils.isBinaryContent;
import static io.github.epi155.pgp.ui.UIUtils.wrapInScroll;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ReceivePanel extends JPanel {

    private final transient PGPEngine engine;
    private final KeyTreePanel publicKeyPanel;
    private final KeyTreePanel privateKeyPanel;
    private final JTextArea cipherTextArea;
    private final JTextArea plainTextArea;
    private final JEditorPane verificationArea;
    private final JEditorPane encryptionMetadataArea;
    private final JButton decryptButton;
    private final JToggleButton showUsedBtn;
    private final JRadioButton messageRadio;
    private final JRadioButton fileRadio;
    private final JTextField cipherFileField;
    private final CardLayout inputCardLayout;
    private final JPanel inputCardPanel;
    private final JList<String> attachList;
    private final DefaultListModel<String> attachListModel;
    private final JButton saveAttachButton;

    private transient KeyBundle publicKeyBundle;
    private transient KeyBundle privateKeyBundle;
    private byte[] cipherBytes;
    private CompoundMessage lastCompound;
    private final java.util.List<java.nio.file.Path> tempFiles = new java.util.ArrayList<>();
    private final java.util.List<String> publicKeyringPaths = new java.util.ArrayList<>();
    private final java.util.List<String> privateKeyringPaths = new java.util.ArrayList<>();

    public ReceivePanel(PGPEngine engine) {
        this.engine = engine;
        setLayout(new BorderLayout(5, 5));

        publicKeyPanel = new KeyTreePanel("Public Keys (Verify Signature)", false, false);
        privateKeyPanel = new KeyTreePanel("Private Keys (Decryption)", false, false);
        publicKeyPanel.setAutoSelectEnabled(false);
        privateKeyPanel.setAutoSelectEnabled(false);
        publicKeyPanel.setUserSelectionAllowed(false);
        privateKeyPanel.setUserSelectionAllowed(false);
        cipherTextArea = new JTextArea(10, 40);
        plainTextArea = new JTextArea(10, 40);
        verificationArea = new JEditorPane("text/html", "");
        encryptionMetadataArea = new JEditorPane("text/html", "");
        decryptButton = new JButton("Decrypt") {
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
        decryptButton.setContentAreaFilled(false);
        decryptButton.setOpaque(false);
        decryptButton.setForeground(new Color(0x302681));
        decryptButton.setFont(decryptButton.getFont().deriveFont(Font.BOLD));
        decryptButton.setEnabled(false);

        Font mono = new Font("Monospaced", Font.PLAIN, 12);
        cipherTextArea.setFont(mono);
        plainTextArea.setFont(mono);
        cipherTextArea.setLineWrap(true);
        cipherTextArea.setWrapStyleWord(true);
        cipherTextArea.setTransferHandler(new TransferHandler() {
            @Override
            protected Transferable createTransferable(JComponent c) {
                String sel = ((JTextArea) c).getSelectedText();
                return sel != null ? new StringSelection(sel) : null;
            }

            @Override
            public int getSourceActions(JComponent c) {
                return COPY_OR_MOVE;
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
                        File f = files.get(0);
                        byte[] header = new byte[16384];
                        int len;
                        try (FileInputStream fis = new FileInputStream(f)) {
                            len = fis.read(header);
                        }
                        if (len <= 0) return false;
                        boolean bin = isBinaryContent(header, len);
                        if (bin) {
                            int ret = JOptionPane.showConfirmDialog(
                                    cipherTextArea,
                                    "The file \"" + f.getName() + "\" appears to be binary.\n"
                                            + "Paste the content anyway?",
                                    "Binary file detected",
                                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                            if (ret != JOptionPane.YES_OPTION) return false;
                        }
                        long fileSize = f.length();
                        if (fileSize > 1_048_576) {
                            String sizeStr = String.format("%.1f MB", fileSize / (1024.0 * 1024.0));
                            int ret = JOptionPane.showConfirmDialog(
                                    cipherTextArea,
                                    "The file \"" + f.getName() + "\" (" + sizeStr + ") exceeds 1 MB.\n"
                                            + "It would be better to handle it as a file rather than as a message.\n"
                                            + "Paste the content anyway?",
                                    "Large file detected",
                                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                            if (ret != JOptionPane.YES_OPTION) return false;
                        }
                        String full = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                        int pos = cipherTextArea.getCaretPosition();
                        cipherTextArea.getDocument().insertString(pos, full, null);
                        return true;
                    } catch (Exception ex) {
                        return false;
                    }
                }
                if (support.isDataFlavorSupported(DataFlavor.stringFlavor)) {
                    try {
                        String text = (String) support.getTransferable()
                                .getTransferData(DataFlavor.stringFlavor);
                        cipherTextArea.replaceSelection(text);
                        return true;
                    } catch (Exception ex) {
                        return false;
                    }
                }
                return false;
            }
        });
        plainTextArea.setEditable(false);
        verificationArea.setEditable(false);
        verificationArea.setBackground(UIManager.getColor("Panel.background"));
        encryptionMetadataArea.setEditable(false);
        encryptionMetadataArea.setBackground(UIManager.getColor("Panel.background"));

        messageRadio = new JRadioButton("Message", true);
        fileRadio = new JRadioButton("File");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(messageRadio);
        modeGroup.add(fileRadio);

        inputCardLayout = new CardLayout();
        inputCardPanel = new JPanel(inputCardLayout);
        inputCardPanel.add(wrapInScroll(cipherTextArea, "Ciphertext"), "message");

        JPanel cipherFilePanel = new JPanel(new BorderLayout(5, 5));
        cipherFileField = new JTextField();
        cipherFileField.setEditable(false);
        JButton cipherBrowseBtn = new JButton("Browse...");
        cipherBrowseBtn.addActionListener(this::browseCipherFile);
        cipherFileField.setTransferHandler(new TransferHandler() {
            @Override public boolean canImport(TransferHandler.TransferSupport support) {
                return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override public boolean importData(TransferHandler.TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    File f = files.get(0);
                    cipherBytes = Files.readAllBytes(f.toPath());
                    cipherFileField.setText(f.getAbsolutePath());
                    clearDecryptResults();
                    return true;
                } catch (Exception ex) { return false; }
            }
        });
        JPanel fileRow = new JPanel(new BorderLayout(5, 2));
        fileRow.setBorder(BorderFactory.createTitledBorder("Encrypted File"));
        fileRow.add(new JLabel("File:"), BorderLayout.WEST);
        fileRow.add(cipherFileField, BorderLayout.CENTER);
        JPanel btnEast = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        btnEast.add(cipherBrowseBtn);
        fileRow.add(btnEast, BorderLayout.EAST);

        attachListModel = new DefaultListModel<>();
        attachList = new JList<>(attachListModel);
        attachList.setVisibleRowCount(3);
        JScrollPane attachScroll = new JScrollPane(attachList);
        attachScroll.setBorder(BorderFactory.createTitledBorder("Attachments"));
        saveAttachButton = new JButton("Save attachment...");
        saveAttachButton.setEnabled(false);
        attachList.addListSelectionListener(e ->
                saveAttachButton.setEnabled(!attachList.isSelectionEmpty()));

        cipherFilePanel.add(fileRow, BorderLayout.NORTH);
        cipherFilePanel.add(attachScroll, BorderLayout.CENTER);
        JPanel fileSouth = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        fileSouth.add(saveAttachButton);
        cipherFilePanel.add(fileSouth, BorderLayout.SOUTH);
        inputCardPanel.add(cipherFilePanel, "file");

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                publicKeyPanel, inputCardPanel);
        topSplit.setResizeWeight(0.35);

        JPanel centerLeftPanel = new JPanel(new BorderLayout(5, 5));
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttonPanel.add(decryptButton);
        buttonPanel.add(messageRadio);
        buttonPanel.add(fileRadio);
        showUsedBtn = new JToggleButton("Show Used");
        showUsedBtn.setEnabled(false);
        buttonPanel.add(showUsedBtn);
        centerLeftPanel.add(buttonPanel, BorderLayout.NORTH);
        centerLeftPanel.add(wrapInScroll(verificationArea, "Verify Signature"), BorderLayout.CENTER);

        JPanel centerRow = new JPanel(new GridLayout(1, 2, 5, 5)) {
            private final int fixedRowHeight = 105;
            @Override public Dimension getPreferredSize() {
                Dimension d = super.getPreferredSize();
                d.height = fixedRowHeight;
                return d;
            }
            @Override public Dimension getMinimumSize() {
                Dimension d = super.getMinimumSize();
                d.height = fixedRowHeight;
                return d;
            }
            @Override public Dimension getMaximumSize() {
                Dimension d = super.getMaximumSize();
                d.height = fixedRowHeight;
                return d;
            }
        };
        centerRow.add(centerLeftPanel);
        JScrollPane metaScroll = wrapInScroll(encryptionMetadataArea, "PGP Metadata");
        metaScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        centerRow.add(metaScroll);

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                privateKeyPanel, wrapInScroll(plainTextArea, "Decrypted Plain Text"));
        bottomSplit.setResizeWeight(0.35);

        JPanel outerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;

        gbc.gridy = 0; gbc.weighty = 1;
        outerPanel.add(topSplit, gbc);
        gbc.gridy = 1; gbc.weighty = 0;
        outerPanel.add(centerRow, gbc);
        gbc.gridy = 2; gbc.weighty = 1;
        outerPanel.add(bottomSplit, gbc);
        add(outerPanel, BorderLayout.CENTER);

        publicKeyPanel.getLoadButton().addActionListener(this::loadPublicKeyring);
        privateKeyPanel.getLoadButton().addActionListener(this::loadPrivateKeyring);
        publicKeyPanel.getAddButton().addActionListener(e -> addPublicKeyring());
        privateKeyPanel.getAddButton().addActionListener(e -> addPrivateKeyring());
        publicKeyPanel.setAddButtonVisible(true);
        privateKeyPanel.setAddButtonVisible(true);
        decryptButton.addActionListener(this::onDecrypt);
        saveAttachButton.addActionListener(this::saveAttachment);
        showUsedBtn.addActionListener(e -> {
            if (showUsedBtn.isSelected()) {
                if (!privateKeyPanel.getSelectedKeys().isEmpty())
                    privateKeyPanel.setSelectedViewActive(true);
                if (!publicKeyPanel.getSelectedKeys().isEmpty())
                    publicKeyPanel.setSelectedViewActive(true);
            } else {
                if (privateKeyPanel.isSelectedViewActive())
                    privateKeyPanel.setSelectedViewActive(false);
                if (publicKeyPanel.isSelectedViewActive())
                    publicKeyPanel.setSelectedViewActive(false);
            }
        });
        privateKeyPanel.addViewModeListener(active -> updateShowUsedButton());
        publicKeyPanel.addViewModeListener(active -> updateShowUsedButton());

        setupKeyDrop(privateKeyPanel, false);
        setupKeyDrop(publicKeyPanel, true);

        setupKeyButtonDrops();

        publicKeyPanel.getClearButton();
        publicKeyPanel.setOnClearCallback(() -> {
            publicKeyBundle = null;
            publicKeyringPaths.clear();
        });

        privateKeyPanel.getClearButton();
        privateKeyPanel.setOnClearCallback(() -> {
            privateKeyBundle = null;
            privateKeyringPaths.clear();
            engine.clearPassphraseCache();
        });

        messageRadio.addActionListener(e -> {
            cipherBytes = null;
            cipherTextArea.setText("");
            clearDecryptResults();
            inputCardLayout.show(inputCardPanel, "message");
        });
        fileRadio.addActionListener(e -> {
            cipherTextArea.setText("");
            cipherFileField.setText("");
            cipherBytes = null;
            clearDecryptResults();
            inputCardLayout.show(inputCardPanel, "file");
        });

        updateDecryptButton();
    }

    private void setupKeyButtonDrops() {
        publicKeyPanel.getLoadButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(this::loadPublicKeyring));
        publicKeyPanel.getAddButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(this::loadPublicKeyringAdd));
        privateKeyPanel.getLoadButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(this::loadPrivateKeyring));
        privateKeyPanel.getAddButton().setTransferHandler(
                UIUtils.createKeyringDropHandler(this::loadPrivateKeyringAdd));
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
            publicKeyringPaths.clear();
            publicKeyringPaths.add(file.getAbsolutePath());
        } catch (Exception ex) {
            UIUtils.showError(this, "Error loading public keys:\n" + ex.getMessage(), ex);
        }
        updateDecryptButton();
        updateShowUsedButton();
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
            if (publicKeyBundle != null) {
                UIUtils.mergeKeyBundle(publicKeyBundle, bundle);
            } else {
                publicKeyBundle = bundle;
            }
            publicKeyringPaths.add(file.getAbsolutePath());
            updateDecryptButton();
            updateShowUsedButton();
        } catch (Exception ex) {
            UIUtils.showError(this, "Error loading public keys:\n" + ex.getMessage(), ex);
        }
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
            UIUtils.showError(this, "Error loading private keys:\n" + ex.getMessage(), ex);
        }
        updateDecryptButton();
        updateShowUsedButton();
    }

    private void addPrivateKeyring() {
        JFileChooser fc = createSecretFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadPrivateKeyringAdd(fc.getSelectedFile());
        }
    }

    private void loadPrivateKeyringAdd(File file) {
        try {
            engine.clearPassphraseCache();
            KeyBundle bundle = KeyringLoader.loadSecretKeys(file);
            privateKeyPanel.addKeys(bundle.getKeys());
            privateKeyPanel.incrementKeyringCount();
            mergePrivateKeyBundle(bundle);
            privateKeyringPaths.add(file.getAbsolutePath());
            updateDecryptButton();
            updateShowUsedButton();
        } catch (Exception ex) {
            UIUtils.showError(this, "Error loading private keys:\n" + ex.getMessage(), ex);
        }
    }

    private void mergePrivateKeyBundle(KeyBundle bundle) {
        if (privateKeyBundle != null) {
            UIUtils.mergeKeyBundle(privateKeyBundle, bundle);
        } else {
            privateKeyBundle = bundle;
        }
    }

    private void setupKeyDrop(KeyTreePanel panel, boolean isPublic) {
        panel.setTransferHandler(new TransferHandler() {
            @Override public boolean canImport(TransferSupport support) {
                return support.getComponent().isEnabled()
                    && support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }
            @Override public boolean importData(TransferSupport support) {
                if (!canImport(support)) return false;
                Point pt = support.getDropLocation().getDropPoint();
                Component target = ((JComponent) support.getComponent()).findComponentAt(pt);
                if (target == panel.getClearButton()) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>) support.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    if (isPublic) {
                        if (support.isDrop() && support.getDropAction() == MOVE)
                            loadPublicKeyringAdd(files.get(0));
                        else
                            loadPublicKeyring(files.get(0));
                    } else {
                        if (support.isDrop() && support.getDropAction() == MOVE)
                            loadPrivateKeyringAdd(files.get(0));
                        else
                            loadPrivateKeyring(files.get(0));
                    }
                    return true;
                } catch (Exception ex) { return false; }
            }
        });
    }

    private void updateDecryptButton() {
        boolean hasPrivateKeys = privateKeyBundle != null && !privateKeyBundle.getKeys().isEmpty();
        boolean hasPublicKeys = publicKeyBundle != null && !publicKeyBundle.getKeys().isEmpty();
        decryptButton.setEnabled(hasPrivateKeys || hasPublicKeys);
    }

    private void clearDecryptResults() {
        lastCompound = null;
        attachListModel.clear();
        saveAttachButton.setEnabled(false);
        verificationArea.setText("");
        encryptionMetadataArea.setText("");
        cleanupTempFiles();
    }

    private void browseCipherFile(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        fc.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "All files (*.*)", "*"));
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "PGP encrypted files (*.asc, *.gpg, *.pgp)", "asc", "gpg", "pgp"));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                cipherBytes = Files.readAllBytes(fc.getSelectedFile().toPath());
                cipherFileField.setText(fc.getSelectedFile().getAbsolutePath());
                clearDecryptResults();
            } catch (IOException ex) {
                UIUtils.showError(this, "Error reading file:\n" + ex.getMessage(), ex);
            }
        }
    }

    private void saveAttachment(ActionEvent e) {
        int idx = attachList.getSelectedIndex();
        if (idx < 0 || lastCompound == null || idx >= lastCompound.getAttachments().size()) return;
        CompoundMessage.Attachment att = lastCompound.getAttachments().get(idx);
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(att.getFilename()));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                att.saveTo(fc.getSelectedFile().toPath());
            } catch (IOException ex) {
                UIUtils.showError(this, "Error saving attachment:\n" + ex.getMessage(), ex);
            }
        }
    }

    private void updateShowUsedButton() {
        boolean active = privateKeyPanel.isSelectedViewActive() || publicKeyPanel.isSelectedViewActive();
        showUsedBtn.setSelected(active);
        if (active) {
            showUsedBtn.setEnabled(true);
        } else {
            showUsedBtn.setEnabled(!privateKeyPanel.getSelectedKeys().isEmpty()
                    || !publicKeyPanel.getSelectedKeys().isEmpty());
        }
    }

    private void onDecrypt(ActionEvent e) {
        boolean isBinary = fileRadio.isSelected();
        String cipherText = cipherTextArea.getText();
        if (isBinary) {
            if (cipherBytes == null) {
                JOptionPane.showMessageDialog(this, "Select an encrypted file.",
                        "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }
        } else if (cipherText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Paste the encrypted message.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        byte[] cipherData = isBinary ? cipherBytes : cipherText.getBytes(StandardCharsets.UTF_8);
        List<PGPPublicKey> publicKeys = extractPublicKeys();
        Map<Long, String> publicKeyUserIdByKeyId = buildPublicKeyUserIds();
        List<PGPSecretKey> secretKeys = extractSecretKeys();
        Map<Long, String> secretKeyUserIds = new HashMap<>();
        if (privateKeyBundle != null) {
            for (PGPKeyInfo info : privateKeyBundle.getKeys()) {
                String uid = info.getUserId();
                if (uid != null) {
                    for (PGPKeyInfo sub : info.getSubKeys()) {
                        secretKeyUserIds.put(sub.getKeyId(), uid);
                    }
                    secretKeyUserIds.put(info.getKeyId(), uid);
                }
            }
        }

        // Pre-scan: collect recipient key IDs from the outermost layer
        Set<Long> allMsgKeyIds = new HashSet<>();
        try {
            allMsgKeyIds = engine.getAllRecipientKeyIdsRecursive(cipherData);
        } catch (Exception ex) {
            // ignore — treat as no recipient keys
        }

        // Match keys — check at least one is available
        if (!allMsgKeyIds.isEmpty()) {
            if (secretKeys.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No private keys loaded.",
                        "Error", JOptionPane.WARNING_MESSAGE);
                return;
            }
            boolean hasMatch = false;
            for (PGPSecretKey sk : secretKeys) {
                if (allMsgKeyIds.contains(sk.getKeyID())) {
                    hasMatch = true;
                    break;
                }
            }
            if (!hasMatch) {
                String keyIds = allMsgKeyIds.stream()
                        .map(id -> String.format("0x%08X", id))
                        .reduce((a, b) -> a + ", " + b)
                        .orElse("");
                JOptionPane.showMessageDialog(this,
                        "No matching private key found.\n"
                        + "Key IDs required by the message: " + keyIds,
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            // Cache empty passphrases for unprotected keys
            for (PGPSecretKey sk : secretKeys) {
                if (allMsgKeyIds.contains(sk.getKeyID()) && !engine.hasPassphrase(sk.getKeyID())) {
                    engine.cacheEmptyPassphraseIfUnprotected(sk);
                }
            }
        }

        // Setup passphrase provider — called from background thread when engine needs a passphrase
        Frame owner = (Frame) SwingUtilities.getWindowAncestor(this);
        engine.setPassphraseProvider(keyId -> {
            try {
                final char[][] result = new char[1][];
                String uid = secretKeyUserIds.get(keyId);
                String keyIdStr = String.format("0x%08X", keyId);
                SwingUtilities.invokeAndWait(() -> {
                    PasswordDialog dlg = new PasswordDialog(owner, uid, keyIdStr,
                            PasswordDialog.Mode.REQUEST);
                    dlg.setVisible(true);
                    result[0] = dlg.getPassword();
                });
                return result[0];
            } catch (Exception ex) {
                return null;
            }
        });

        // Setup password provider — called from background thread when engine
        // encounters a PBE layer (including nested/hybrid layers)
        engine.setPasswordProvider(layerIndex -> {
            try {
                final char[][] result = new char[1][];
                SwingUtilities.invokeAndWait(() -> {
                    PasswordDialog dlg = new PasswordDialog(owner,
                            "Encrypted layer #" + layerIndex + ": Password-based",
                            "",
                            PasswordDialog.Mode.REQUEST);
                    dlg.setTitle("Encryption password");
                    dlg.setVisible(true);
                    result[0] = dlg.getPassword();
                });
                return result[0];
            } catch (Exception ex) {
                return null;
            }
        });

        // Unified decrypt
        boolean hasEncryption = !allMsgKeyIds.isEmpty();
        ProgressDialog progress = new ProgressDialog(owner, hasEncryption ? "Decrypting..." : "Decompressing...");
        boolean decodeText = !isBinary;
        SwingWorker<DecryptResult, Void> worker = new SwingWorker<>() {
            @Override
            protected DecryptResult doInBackground() throws Exception {
                return engine.decryptNested(cipherData, secretKeys, publicKeys,
                        publicKeyUserIdByKeyId, secretKeyUserIds, null,
                        progress, decodeText);
            }
            @Override
            protected void done() {
                progress.dispose();
                engine.setPassphraseProvider(null);
                engine.setPasswordProvider(null);
                try {
                    handleDecryptResult(get(), isBinary);
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    String msg = cause.getMessage();
                    if (msg != null && msg.contains("checksum")) {
                        UIUtils.showError(ReceivePanel.this,
                                "Wrong password for private key.", cause);
                        engine.clearPassphraseCache();
                    } else if (msg != null && msg.contains("No matching private key")) {
                        UIUtils.showError(ReceivePanel.this,
                                msg, cause);
                    } else if (msg != null && msg.contains("Password required")) {
                        UIUtils.showError(ReceivePanel.this,
                                "Wrong password for encrypted layer.", cause);
                    } else {
                        UIUtils.showError(ReceivePanel.this,
                                "Error during decryption:\n" + msg, cause);
                    }
                }
            }
        };
        worker.execute();
        progress.setVisible(true);
    }

    private static void scrollToTop(JComponent comp) {
        JScrollPane sp = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, comp);
        if (sp != null) {
            sp.getVerticalScrollBar().setValue(0);
        }
    }

    private void handleDecryptResult(DecryptResult result, boolean isBinary) {
        cleanupTempFiles();
        if (result.getTempFilePath() != null) {
            tempFiles.add(result.getTempFilePath());
        }
        verificationArea.setText(result.getVerificationDetail());
        EventQueue.invokeLater(() -> scrollToTop(verificationArea));
        encryptionMetadataArea.setText(result.getEncryptionMetadataText());
        EventQueue.invokeLater(() -> scrollToTop(encryptionMetadataArea));

        // Handle compound message attachments
        lastCompound = result.getCompoundMessage();
        attachListModel.clear();
        DecryptResult.Metadata meta = result.getMetadata();
        boolean hasCompound = lastCompound != null && !lastCompound.getAttachments().isEmpty();
        if (hasCompound) {
            plainTextArea.setText(result.getPlainText());
            EventQueue.invokeLater(() -> scrollToTop(plainTextArea));
            for (CompoundMessage.Attachment att : lastCompound.getAttachments()) {
                attachListModel.addElement(att.getFilename());
            }
        } else if (isBinary) {
            // File mode, non-compound: prompt save immediately
            String origName = meta != null ? meta.getOriginalFileName() : null;
            if (origName == null) {
                String path = cipherFileField.getText();
                if (path != null && !path.isEmpty()) {
                    String baseName = new File(path).getName();
                    int dot = baseName.lastIndexOf('.');
                    origName = dot > 0 ? baseName.substring(0, dot) : baseName;
                }
            }
            if (origName == null || origName.isEmpty()) origName = "cipher.dec";
            java.nio.file.Path tempPath = result.getTempFilePath();
            byte[] rawContent = result.getRawContent();

            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File(origName));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                java.nio.file.Path dest = fc.getSelectedFile().toPath();
                try {
                    if (tempPath != null) {
                        java.nio.file.Files.copy(tempPath, dest,
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    } else if (rawContent != null) {
                        java.nio.file.Files.write(dest, rawContent);
                    }
                    plainTextArea.setText("[Decrypted file saved to: " + dest + "]");
                    saveAttachButton.setEnabled(false);
                } catch (Exception ex) {
                    UIUtils.showError(this, "Error saving file:\n" + ex.getMessage(), ex);
                    plainTextArea.setText("[Error saving file. Use 'Save attachment' to retry.]");
                    wrapBinaryAsAttachment(result, origName, tempPath, rawContent);
                }
            } else {
                plainTextArea.setText("[Decrypted file not saved. Use the 'Save attachment' button to save it.]");
                wrapBinaryAsAttachment(result, origName, tempPath, rawContent);
            }
        } else {
            plainTextArea.setText(result.getPlainText());
            EventQueue.invokeLater(() -> scrollToTop(plainTextArea));
            saveAttachButton.setEnabled(false);
        }

        // Highlight keys used for decryption and signature verification
        publicKeyPanel.clearSelection();
        privateKeyPanel.clearSelection();
        if (meta != null) {
            List<DecryptResult.EncryptionLayer> layers = meta.getEncryptionLayers();
            if (layers != null && !layers.isEmpty()) {
                List<PGPKeyInfo> usedPrivKeys = new ArrayList<>();
                for (DecryptResult.EncryptionLayer layer : layers) {
                    if (layer.getType() == DecryptResult.EncryptionLayer.Type.PUBLIC_KEY
                            && layer.getRecipientKeyId() != null) {
                        PGPKeyInfo privKey = findKeyByKeyId(privateKeyBundle, layer.getRecipientKeyId());
                        if (privKey != null && !usedPrivKeys.contains(privKey))
                            usedPrivKeys.add(privKey);
                    }
                }
                if (!usedPrivKeys.isEmpty())
                    privateKeyPanel.setProgrammaticSelection(usedPrivKeys);
            } else if (meta.getRecipientKeyId() != null) {
                PGPKeyInfo privKey = findKeyByKeyId(privateKeyBundle, meta.getRecipientKeyId());
                if (privKey != null)
                    privateKeyPanel.setProgrammaticSelection(List.of(privKey));
            }
        }
        List<PGPKeyInfo> signerKeys = new ArrayList<>();
        for (DecryptResult.SignerInfo si : result.getSigners()) {
            PGPKeyInfo pubKey = findKeyByKeyId(publicKeyBundle, si.getKeyId());
            if (pubKey != null) signerKeys.add(pubKey);
        }
        if (!signerKeys.isEmpty()) {
            publicKeyPanel.setProgrammaticSelection(signerKeys);
        }
        updateShowUsedButton();
    }

    private void wrapBinaryAsAttachment(DecryptResult result, String origName,
                                         java.nio.file.Path tempPath, byte[] rawContent) {
        if (tempPath != null) {
            lastCompound = new CompoundMessage("", java.util.List.of(
                    new CompoundMessage.Attachment(origName, tempPath, 0, -1)));
        } else if (rawContent != null) {
            lastCompound = new CompoundMessage("", java.util.List.of(
                    new CompoundMessage.Attachment(origName, rawContent)));
        } else {
            byte[] content = result.getPlainText().getBytes(StandardCharsets.UTF_8);
            lastCompound = new CompoundMessage("", java.util.List.of(
                    new CompoundMessage.Attachment(origName, content)));
        }
        attachListModel.addElement(origName);
    }

    private List<PGPSecretKey> extractSecretKeys() {
        List<PGPSecretKey> result = new ArrayList<>();
        if (privateKeyBundle == null) return result;
        for (PGPKeyInfo info : privateKeyBundle.getKeys()) {
            result.add(info.getBcKey(PGPSecretKey.class));
            for (PGPKeyInfo sub : info.getSubKeys()) {
                result.add(sub.getBcKey(PGPSecretKey.class));
            }
        }
        return result;
    }

    private List<PGPPublicKey> extractPublicKeys() {
        List<PGPPublicKey> result = new ArrayList<>();
        if (publicKeyBundle == null) return result;
        for (PGPKeyInfo info : publicKeyBundle.getKeys()) {
            result.add(info.getBcKey(PGPPublicKey.class));
            for (PGPKeyInfo sub : info.getSubKeys()) {
                result.add(sub.getBcKey(PGPPublicKey.class));
            }
        }
        return result;
    }

    private Map<Long, String> buildPublicKeyUserIds() {
        Map<Long, String> map = new HashMap<>();
        if (publicKeyBundle == null) return map;
        for (PGPKeyInfo info : publicKeyBundle.getKeys()) {
            String uid = info.getUserId();
            if (uid != null) {
                PGPPublicKey masterKey = info.getBcKey(PGPPublicKey.class);
                map.put(masterKey.getKeyID(), uid);
                for (PGPKeyInfo sub : info.getSubKeys()) {
                    map.put(sub.getBcKey(PGPPublicKey.class).getKeyID(), uid);
                }
            }
        }
        return map;
    }

    private PGPKeyInfo findKeyByKeyId(KeyBundle bundle, long keyId) {
        if (bundle == null) return null;
        for (PGPKeyInfo key : bundle.getKeys()) {
            if (key.getKeyId() == keyId) return key;
            for (PGPKeyInfo sub : key.getSubKeys()) {
                if (sub.getKeyId() == keyId) return sub;
            }
        }
        return null;
    }



    public void savePreferences(java.util.prefs.Preferences prefs) {
        prefs.put("recv_pub_paths", String.join(File.pathSeparator, publicKeyringPaths));
        prefs.put("recv_priv_paths", String.join(File.pathSeparator, privateKeyringPaths));
    }

    public void restorePreferences(java.util.prefs.Preferences prefs) {
        String pubPaths = prefs.get("recv_pub_paths", "");
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
                    System.err.println("File not found: " + path);
                }
            }
        }

        String privPaths = prefs.get("recv_priv_paths", "");
        if (!privPaths.isEmpty()) {
            for (String path : privPaths.split(File.pathSeparator)) {
                File f = new File(path);
                if (f.exists()) {
                    if (privateKeyringPaths.isEmpty()) {
                        loadPrivateKeyring(f);
                    } else {
                        loadPrivateKeyringAdd(f);
                    }
                } else {
                    System.err.println("File not found: " + path);
                }
            }
        }
    }

    void cleanupTempFiles() {
        for (java.nio.file.Path p : tempFiles) {
            try { java.nio.file.Files.deleteIfExists(p); } catch (java.io.IOException ignored) {}
        }
        tempFiles.clear();
    }
}
