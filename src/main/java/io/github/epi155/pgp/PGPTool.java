package io.github.epi155.pgp;

import io.github.epi155.pgp.cli.Cli;
import io.github.epi155.pgp.cli.CliException;
import io.github.epi155.pgp.log.AppLog;
import io.github.epi155.pgp.ui.MainFrame;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import javax.swing.plaf.metal.MetalLookAndFeel;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class PGPTool {
    public static void main(String[] args) {
        AppLog.init();
        Security.addProvider(new BouncyCastleProvider());

        boolean privateExtensions = false;
        List<String> filtered = new ArrayList<>();
        for (String arg : args) {
            if (arg.equals("-p") || arg.equals("--private")) {
                privateExtensions = true;
            } else {
                filtered.add(arg);
            }
        }
        String[] rest = filtered.toArray(new String[0]);

        if (rest.length > 0 && Cli.isCommand(rest[0])) {
            System.exit(runCli(rest, privateExtensions));
            return;
        }
        boolean showKeyTab = false;
        boolean advanced = false;
        for (String arg : rest) {
            switch (arg) {
                case "-h":
                case "--help":
                    printHelp();
                    return;
                case "-k":
                case "--key":
                    showKeyTab = true;
                    break;
                case "-a":
                case "--advanced":
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
            UIManager.setLookAndFeel(new MetalLookAndFeel());
        } catch (Exception e) {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
        }

        boolean keyTab = showKeyTab;
        boolean adv = advanced;
        boolean priv = privateExtensions;
        SwingUtilities.invokeLater(() -> {
            MainFrame frame = new MainFrame(keyTab, adv, priv);
            frame.setVisible(true);
        });
    }

    private static int runCli(String[] args, boolean privateExtensions) {
        try {
            return Cli.run(args, privateExtensions);
        } catch (CliException e) {
            System.err.println("pgp-tool: " + e.getMessage());
            if (e.isUsage()) {
                System.err.println("Run 'pgp-tool --help' for usage.");
            }
            return e.isUsage() ? 2 : 1;
        } catch (Exception e) {
            System.err.println("pgp-tool: " + (e.getMessage() != null ? e.getMessage() : e.toString()));
            return 1;
        }
    }

    private static void printHelp() {
        System.out.println("PGP Tool - Graphical PGP encryption/decryption utility");
        System.out.println();
        System.out.println("Usage: pgp-tool [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -k, --key        Enable the Key generation tab");
        System.out.println("  -a, --advanced   Enable advanced multi-signer and multi-layer encryption");
        System.out.println("  -p, --private    Enable private extension algorithms (Serpent, ChaCha20-Poly1305,");
        System.out.println("                    ASCON ciphers, XZ/ZSTD compression, SHA3 hashes)");
        System.out.println("  -h, --help       Show this help message and exit");
        System.out.println();
        System.out.println("Batch mode (no GUI):");
        System.out.println("  -l, --list <keyring.asc>...");
        System.out.println("  -g, --generate ...");
        System.out.println("  -e, --encrypt ...");
        System.out.println("  -d, --decrypt ...");
        System.out.println("  Run a batch command with -h or --help for its options, e.g. pgp-tool -e --help");
    }
}