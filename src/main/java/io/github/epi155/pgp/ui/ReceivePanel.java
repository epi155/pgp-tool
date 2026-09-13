package io.github.epi155.pgp.ui;

import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.DecryptResult;
import io.github.epi155.pgp.model.KeyBundle;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.model.TarArchive;
import io.github.epi155.pgp.model.TarEntry;
import io.github.epi155.pgp.service.KeyringLoader;
import io.github.epi155.pgp.service.PGPEngine;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.Frame;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.*;
import java.util.List;

import static io.github.epi155.pgp.ui.UIUtils.*;

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
    private final JTree attachTree;
    private final DefaultTreeModel attachTreeModel;
    private final AttachmentNode attachRoot;
    private final JButton saveAttachButton;
    private final JButton exportTarButton;
    private final JLabel statusLabel;

    private transient KeyBundle publicKeyBundle;
    private transient KeyBundle privateKeyBundle;
    private byte[] cipherBytes;
    private CompoundMessage lastCompound;
    private TarArchive lastTarArchive;
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
                        long fileSize = f.length();
                        boolean large = fileSize > 1_048_576;
                        if (bin || large) {
                            StringBuilder msg = new StringBuilder();
                            if (bin) {
                                msg.append("The file \"").append(f.getName())
                                        .append("\" appears to be binary.\n");
                            }
                            if (large) {
                                String sizeStr = String.format("%.1f MB", fileSize / (1024.0 * 1024.0));
                                msg.append("The file \"").append(f.getName())
                                        .append("\" (").append(sizeStr).append(") exceeds 1 MB.\n")
                                        .append("It would be better to handle it as a file rather than as a message.\n");
                            }
                            msg.append("How do you want to handle this file?");
                            Object[] options = {"as Message", "as File", "Cancel"};
                            int ret = JOptionPane.showOptionDialog(
                                    cipherTextArea,
                                    msg.toString(),
                                    "File detected",
                                    JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
                                    null, options, options[0]);
                            if (ret == 1) {
                                fileRadio.setSelected(true);
                                switchToFileMode();
                                setCipherFile(f);
                                return true;
                            }
                            if (ret != 0) return false;
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
                    setCipherFile(f);
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

        attachRoot = AttachmentNode.root("Attachments");
        attachTreeModel = new DefaultTreeModel(attachRoot);
        attachTree = new JTree(attachTreeModel);
        attachTree.setRootVisible(true);
        attachTree.setShowsRootHandles(true);
        attachTree.setVisibleRowCount(3);
        JScrollPane attachScroll = new JScrollPane(attachTree);
        attachScroll.setBorder(BorderFactory.createTitledBorder("Attachments"));
        saveAttachButton = new JButton("Save attachment...");
        saveAttachButton.setEnabled(false);
        exportTarButton = new JButton("Export tar...");
        exportTarButton.setEnabled(false);
        attachTree.addTreeSelectionListener(e ->
                saveAttachButton.setEnabled(attachTree.getSelectionCount() > 0));

        // Key bindings for attachment tree
        InputMap im = attachTree.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = attachTree.getActionMap();
        im.put(KeyStroke.getKeyStroke("control A"), "selectAllAttachments");
        am.put("selectAllAttachments", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                UIUtils.expandAll(attachTree);
                attachTree.setSelectionInterval(0, attachTree.getRowCount() - 1);
            }
        });
        im.put(KeyStroke.getKeyStroke("control S"), "saveAttachments");
        am.put("saveAttachments", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveAttachments();
            }
        });
        im.put(KeyStroke.getKeyStroke("control T"), "exportTar");
        am.put("exportTar", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportTar();
            }
        });

        cipherFilePanel.add(fileRow, BorderLayout.NORTH);
        cipherFilePanel.add(attachScroll, BorderLayout.CENTER);
        JPanel fileSouth = new JPanel(new BorderLayout(5, 2));
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        btnRow.add(saveAttachButton);
        btnRow.add(exportTarButton);
        fileSouth.add(btnRow, BorderLayout.WEST);
        statusLabel = new JLabel(" ");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        statusLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        statusLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                statusLabel.setText(" ");
            }
        });
        fileSouth.add(statusLabel, BorderLayout.CENTER);
        fileSouth.add(new JLabel(" "), BorderLayout.EAST); // spacer
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
        exportTarButton.addActionListener(e -> exportTar());
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

        messageRadio.addActionListener(e -> switchToMessageMode());
        fileRadio.addActionListener(e -> switchToFileMode());

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
        lastTarArchive = null;
        attachRoot.removeAllChildren();
        attachTreeModel.reload();
        saveAttachButton.setEnabled(false);
        exportTarButton.setEnabled(false);
        verificationArea.setText("");
        encryptionMetadataArea.setText("");
        cleanupTempFiles();
    }

    private void switchToMessageMode() {
        cipherBytes = null;
        cipherTextArea.setText("");
        clearDecryptResults();
        inputCardLayout.show(inputCardPanel, "message");
    }

    private void switchToFileMode() {
        cipherTextArea.setText("");
        cipherFileField.setText("");
        cipherBytes = null;
        clearDecryptResults();
        inputCardLayout.show(inputCardPanel, "file");
    }

    private void setCipherFile(File f) throws IOException {
        cipherBytes = Files.readAllBytes(f.toPath());
        cipherFileField.setText(f.getAbsolutePath());
        clearDecryptResults();
    }

    private void browseCipherFile(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        fc.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "All files (*.*)", "*"));
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "PGP encrypted files (*.asc, *.gpg, *.pgp)", "asc", "gpg", "pgp"));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                setCipherFile(fc.getSelectedFile());
            } catch (IOException ex) {
                UIUtils.showError(this, "Error reading file:\n" + ex.getMessage(), ex);
            }
        }
    }

    private void saveAttachment(ActionEvent e) {
        saveAttachments();
    }

    private void saveAttachments() {
        List<AttachmentNode> selected = getSelectedLeafNodes();
        if (selected.isEmpty()) return;

        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        fc.setDialogTitle(selected.size() == 1 ? "Save Attachment" : "Save Attachments");

        if (selected.size() == 1) {
            AttachmentNode node = selected.get(0);
            String name = node.getDisplayName();
            if (name != null) fc.setSelectedFile(new File(name));
        }

        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        Path target = fc.getSelectedFile().toPath();
        boolean isDir = Files.isDirectory(target);

        if (selected.size() > 1 && !isDir) {
            UIUtils.showError(this, "To save multiple attachments, select a directory.", null);
            return;
        }

        saveNodesTo(selected, target, isDir);
    }

    private List<AttachmentNode> getSelectedLeafNodes() {
        List<AttachmentNode> result = new ArrayList<>();
        TreePath[] paths = attachTree.getSelectionPaths();
        if (paths == null) return result;
        for (TreePath path : paths) {
            Object node = path.getLastPathComponent();
            if (node instanceof AttachmentNode) {
                AttachmentNode an = (AttachmentNode) node;
                if (an.isLeaf()) {
                    result.add(an);
                } else {
                    collectLeafChildren(an, result);
                }
            }
        }
        return result;
    }

    private void collectLeafChildren(AttachmentNode node, List<AttachmentNode> result) {
        for (int i = 0; i < node.getChildCount(); i++) {
            AttachmentNode child = (AttachmentNode) node.getChildAt(i);
            if (child.isLeaf()) {
                result.add(child);
            } else {
                collectLeafChildren(child, result);
            }
        }
    }

    private void saveNodesTo(List<AttachmentNode> nodes, Path target, boolean isDir) {
        Frame frame = (Frame) SwingUtilities.getWindowAncestor(this);
        ConflictResolver resolver = new ConflictResolver(frame);
        int saved = 0, skipped = 0, errors = 0;
        for (AttachmentNode node : nodes) {
            Path dest;
            if (isDir) {
                String relPath = getRelativePath(node);
                dest = target.resolve(relPath);
            } else {
                dest = target;
            }
            Path parentDir = dest.getParent();
            if (parentDir != null) {
                try { Files.createDirectories(parentDir); } catch (IOException ignored) {}
            }
            if (Files.exists(dest)) {
                ConflictResolver.Action action = resolver.prompt(node.getDisplayName());
                if (action == ConflictResolver.Action.SKIP) { skipped++; continue; }
                if (action == ConflictResolver.Action.RENAME) { dest = findUniqueName(dest.getParent(), dest.getFileName().toString()); }
            }
            try {
                switch (node.getKind()) {
                    case TAR_ENTRY:
                        TarEntry te = node.getTarEntry();
                        try (java.io.InputStream in = te.getInputStream()) {
                            if (in != null) Files.copy(in, dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        }
                        if (te.getModificationTime() > 0) Files.setLastModifiedTime(dest, FileTime.fromMillis(te.getModificationTime()));
                        restoreOwnership(dest, te);
                        break;
                    case COMPOUND_ENTRY:
                        CompoundMessage.Attachment ca = node.getCompoundAtt();
                        ca.saveTo(dest);
                        if (ca.getModificationTime() > 0) Files.setLastModifiedTime(dest, FileTime.fromMillis(ca.getModificationTime()));
                        break;
                    case FILE:
                        Files.copy(node.getFile().toPath(), dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        break;
                    default:
                        continue;
                }
                saved++;
            } catch (IOException ex) {
                errors++;
                UIUtils.showError(this, "Error saving attachment:\n" + ex.getMessage(), ex);
            }
        }
        StringBuilder msg = new StringBuilder();
        if (saved > 0) msg.append(saved).append(" file(s) saved");
        if (skipped > 0) { if (msg.length() > 0) msg.append(", "); msg.append(skipped).append(" skipped"); }
        if (errors > 0) { if (msg.length() > 0) msg.append(", "); msg.append(errors).append(" error(s)"); }
        setStatus(msg.length() > 0 ? msg.toString() : "No files saved");
    }

    private String getRelativePath(AttachmentNode node) {
        StringBuilder sb = new StringBuilder();
        javax.swing.tree.TreeNode[] path = node.getPath();
        for (int i = 1; i < path.length; i++) {
            AttachmentNode n = (AttachmentNode) path[i];
            if (sb.length() > 0) sb.append("/");
            sb.append(n.isDirectory() ? n.getDisplayName() : n.getDisplayName());
        }
        return sb.toString();
    }

    private void restoreOwnership(Path target, TarEntry te) {
        if (!target.getFileSystem().supportedFileAttributeViews().contains("posix")) return;
        java.nio.file.attribute.PosixFileAttributeView posixView =
                Files.getFileAttributeView(target, java.nio.file.attribute.PosixFileAttributeView.class);
        if (posixView == null) return;
        String userName = te.getUserName();
        if (userName != null && !userName.isEmpty()) {
            try {
                java.nio.file.attribute.UserPrincipal owner = target.getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByName(userName);
                posixView.setOwner(owner);
            } catch (Exception ignored) {}
        }
        String groupName = te.getGroupName();
        if (groupName != null && !groupName.isEmpty()) {
            try {
                java.nio.file.attribute.GroupPrincipal group = target.getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByGroupName(groupName);
                posixView.setGroup(group);
            } catch (Exception ignored) {}
        }
    }

    private Path findUniqueName(Path dir, String filename) {
        Path base = dir.resolve(filename);
        if (!Files.exists(base)) return base;
        String name = filename;
        String ext = "";
        int dot = filename.lastIndexOf('.');
        if (dot > 0) {
            name = filename.substring(0, dot);
            ext = filename.substring(dot);
        }
        int counter = 1;
        Path candidate;
        do {
            candidate = dir.resolve(name + "_" + counter + ext);
            counter++;
        } while (Files.exists(candidate));
        return candidate;
    }

    private void exportTar() {
        if (lastTarArchive == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export Tar Archive");
        fc.setSelectedFile(new File(lastTarArchive.getBaseName() + ".tar"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path target = fc.getSelectedFile().toPath();
        if (!target.toString().endsWith(".tar")) {
            target = target.resolveSibling(target.getFileName() + ".tar");
        }
        try {
            lastTarArchive.writeTo(Files.newOutputStream(target));
            setStatus("Exported to " + target.getFileName());
        } catch (IOException ex) {
            UIUtils.showError(this, "Error exporting tar:\n" + ex.getMessage(), ex);
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
                    Long wrongKeyId = PGPEngine.wrongPassphraseKeyId(cause);
                    if (wrongKeyId != null) {
                        UIUtils.showError(ReceivePanel.this,
                                "Wrong password for private key.", cause);
                        engine.removePassphrase(wrongKeyId);
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

    private void setPlainTextOrPlaceholder(String text) {
        if (text == null || text.isEmpty()) {
            plainTextArea.setText("");
        } else if (isLikelyBinary(text)) {
            plainTextArea.setText("[Binary content — see attachment tree for extracted files]");
        } else {
            plainTextArea.setText(text);
        }
    }

    private static boolean isLikelyBinary(String text) {
        int len = text.length();
        if (len == 0) return false;
        int nonPrintable = 0;
        for (int i = 0; i < len; i++) {
            char c = text.charAt(i);
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') nonPrintable++;
            else if (c == 0xFFFD) nonPrintable++;
            else if (c > 0x7F && Character.getType(c) == Character.CONTROL) nonPrintable++;
        }
        return nonPrintable * 20 > len;
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

        // Handle compound message / tar attachments
        lastCompound = result.getCompoundMessage();
        lastTarArchive = result.getTarArchive();
        DecryptResult.Metadata meta = result.getMetadata();
        attachRoot.removeAllChildren();
        boolean hasTar = lastTarArchive != null && lastTarArchive.hasAttachments();
        boolean hasCompound = lastCompound != null && !lastCompound.getAttachments().isEmpty();
        if (hasTar) {
            setPlainTextOrPlaceholder(result.getPlainText());
            EventQueue.invokeLater(() -> scrollToTop(plainTextArea));
            for (TarEntry entry : lastTarArchive.getFlatEntries()) {
                addTarEntryToTree(entry);
            }
            attachTreeModel.reload();
            exportTarButton.setEnabled(true);
        } else if (hasCompound) {
            setPlainTextOrPlaceholder(result.getPlainText());
            EventQueue.invokeLater(() -> scrollToTop(plainTextArea));
            for (CompoundMessage.Attachment att : lastCompound.getAttachments()) {
                attachRoot.add(AttachmentNode.ofCompound(att));
            }
            attachTreeModel.reload();
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
            setPlainTextOrPlaceholder(result.getPlainText());
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
        attachRoot.add(AttachmentNode.ofCompound(lastCompound.getAttachments().get(0)));
        attachTreeModel.reload();
    }

    private void addTarEntryToTree(TarEntry entry) {
        String name = entry.getName();
        String[] parts = name.split("/");
        AttachmentNode current = attachRoot;
        for (int i = 0; i < parts.length - 1; i++) {
            AttachmentNode child = findChildDir(current, parts[i]);
            if (child == null) {
                child = AttachmentNode.directory(parts[i]);
                current.add(child);
            }
            current = child;
        }
        String fileName = parts[parts.length - 1];
        if (!fileName.isEmpty()) {
            AttachmentNode fileNode = AttachmentNode.ofTarEntry(entry);
            current.add(fileNode);
        }
    }

    private AttachmentNode findChildDir(AttachmentNode parent, String name) {
        for (int i = 0; i < parent.getChildCount(); i++) {
            AttachmentNode child = (AttachmentNode) parent.getChildAt(i);
            if (child.isDirectory() && child.getDisplayName().equals(name)) {
                return child;
            }
        }
        return null;
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

    private void setStatus(String msg) {
        statusLabel.setText(msg);
    }

    private static class ConflictResolver {
        private final Frame owner;
        private Action lastAction = Action.SKIP;
        private boolean applyToAll = false;

        ConflictResolver(Frame owner) {
            this.owner = owner;
        }

        enum Action { OVERWRITE, SKIP, RENAME }

        Action prompt(String filename) {
            if (applyToAll) {
                return lastAction;
            }

            JPanel panel = new JPanel(new BorderLayout(10, 10));
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            panel.add(new JLabel("<html>File <b>" + escapeHtml(filename) + "</b> already exists.<br>Overwrite?</html>"), BorderLayout.CENTER);

            JCheckBox applyAll = new JCheckBox("Apply to all");
            panel.add(applyAll, BorderLayout.SOUTH);

            Object[] options = {
                "Overwrite", "Skip", "Rename"
            };
            int result = JOptionPane.showOptionDialog(
                owner, panel, "File Exists",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[0]
            );

            Action action;
            switch (result) {
                case 0: action = Action.OVERWRITE; break;
                case 1: action = Action.SKIP; break;
                case 2: action = Action.RENAME; break;
                default: action = Action.SKIP;
            }

            if (applyAll.isSelected()) {
                applyToAll = true;
                lastAction = action;
            }
            return action;
        }

        private String escapeHtml(String s) {
            return s.replace("&", "\u0026").replace("<", "\u003C").replace(">", "\u003E");
        }
    }
}
