package com.example.pgp;

import com.example.pgp.ui.MainFrame;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.security.Security;

public class PGPTool {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> {
            MainFrame frame = new MainFrame();
            frame.setVisible(true);
        });
    }
}
