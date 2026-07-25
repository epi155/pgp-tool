package com.example.pgp;

import com.example.pgp.ui.MainFrame;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.security.Security;

public class PGPTool {
    public static void main(String[] args) {
        boolean showKeyTab = false;
        for (String arg : args) {
            switch (arg) {
                case "-h":
                case "--help":
                    printHelp();
                    return;
                case "-k":
                case "--key":
                    showKeyTab = true;
                    break;
                default:
                    System.err.println("Unknown option: " + arg);
                    System.err.println("Use -h or --help for usage.");
                    return;
            }
        }

        Security.addProvider(new BouncyCastleProvider());

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        boolean keyTab = showKeyTab;
        SwingUtilities.invokeLater(() -> {
            MainFrame frame = new MainFrame(keyTab);
            frame.setVisible(true);
        });
    }

    private static void printHelp() {
        System.out.println("PGP Tool - Graphical PGP encryption/decryption utility");
        System.out.println();
        System.out.println("Usage: pgp-tool [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -k, --key    Enable the Key generation tab");
        System.out.println("  -h, --help   Show this help message and exit");
    }
}