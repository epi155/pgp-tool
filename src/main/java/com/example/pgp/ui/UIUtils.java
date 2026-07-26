package com.example.pgp.ui;

import com.example.pgp.model.PGPKeyInfo;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.io.File;
import java.util.List;
import java.util.function.Consumer;

public final class UIUtils {
    private UIUtils() {}

    public static boolean isBinaryContent(byte[] data, int len) {
        int control = 0;
        for (int i = 0; i < len; i++) {
            int b = data[i] & 0xFF;
            if (b == 0x00) return true;
            if (b < 0x09 || (b > 0x0D && b < 0x20) || b > 0x7E) control++;
        }
        return (double) control / len > 0.30;
    }

    public static JScrollPane wrapInScroll(JComponent comp, String title) {
        JScrollPane sp = new JScrollPane(comp);
        sp.setBorder(BorderFactory.createTitledBorder(title));
        return sp;
    }

    public static JFileChooser createPublicFileChooser() {
        JFileChooser fc = new JFileChooser();
        fc.addChoosableFileFilter(new FileNameExtensionFilter("All files (*.*)", "*"));
        fc.setFileFilter(new FileNameExtensionFilter(
                "PGP Public Key files (*.asc, *.gpg, *.pgp, *.key, *.pkr)",
                "asc", "gpg", "pgp", "key", "pkr"));
        return fc;
    }

    public static JFileChooser createSecretFileChooser() {
        JFileChooser fc = new JFileChooser();
        fc.addChoosableFileFilter(new FileNameExtensionFilter("All files (*.*)", "*"));
        fc.setFileFilter(new FileNameExtensionFilter(
                "PGP Secret Key files (*.asc, *.gpg, *.pgp, *.key, *.skr)",
                "asc", "gpg", "pgp", "key", "skr"));
        return fc;
    }

    public static TransferHandler createKeyringDropHandler(Consumer<File> handler) {
        return new TransferHandler() {
            @Override
            public boolean canImport(TransferSupport support) {
                return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }

            @Override
            public boolean importData(TransferSupport support) {
                if (!canImport(support)) return false;
                try {
                    java.util.List<File> files = (java.util.List<File>)
                            support.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!files.isEmpty()) handler.accept(files.get(0));
                    return true;
                } catch (Exception ex) {
                    return false;
                }
            }
        };
    }

    public static void mergeKeyBundle(com.example.pgp.model.KeyBundle target, com.example.pgp.model.KeyBundle incoming) {
        if (incoming == null || incoming.getKeys() == null) return;
        java.util.Set<Long> ids = new java.util.HashSet<>();
        for (PGPKeyInfo k : target.getKeys()) {
            ids.add(k.getKeyId());
            for (PGPKeyInfo s : k.getSubKeys()) ids.add(s.getKeyId());
        }
        for (PGPKeyInfo k : incoming.getKeys()) {
            if (!ids.contains(k.getKeyId())) {
                target.getKeys().add(k);
                ids.add(k.getKeyId());
            }
        }
    }

}