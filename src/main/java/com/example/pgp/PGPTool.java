package com.example.pgp;

import com.example.pgp.ui.MainFrame;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.security.Security;

public class PGPTool {
    public static void main(String[] args) {
        boolean showKeyTab = false;
        boolean advanced = false;
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
                case "--advanced":
                case "--expert":
                    advanced = true;
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
        boolean adv = advanced;
        SwingUtilities.invokeLater(() -> {
            MainFrame frame = new MainFrame(keyTab, adv);
            frame.setVisible(true);
        });
    }

    private static void printHelp() {
        System.out.println("PGP Tool - Graphical PGP encryption/decryption utility");
        System.out.println();
        System.out.println("Usage: pgp-tool [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -k, --key        Enable the Key generation tab");
        System.out.println("  --advanced       Enable advanced multi-signer and multi-layer encryption");
        System.out.println("  --expert         Same as --advanced");
        System.out.println("  -h, --help       Show this help message and exit");
    }
}