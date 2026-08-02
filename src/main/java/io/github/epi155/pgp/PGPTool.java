package io.github.epi155.pgp;

import io.github.epi155.pgp.cli.Cli;
import io.github.epi155.pgp.cli.CliException;
import io.github.epi155.pgp.log.AppLog;
import io.github.epi155.pgp.ui.MainFrame;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.security.Security;

public class PGPTool {
    public static void main(String[] args) {
        AppLog.init();
        Security.addProvider(new BouncyCastleProvider());
        if (args.length > 0 && Cli.isCommand(args[0])) {
            System.exit(runCli(args));
            return;
        }
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

    private static int runCli(String[] args) {
        try {
            return Cli.run(args);
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
        System.out.println("  --advanced       Enable advanced multi-signer and multi-layer encryption");
        System.out.println("  --expert         Same as --advanced");
        System.out.println("  -h, --help       Show this help message and exit");
        System.out.println();
        System.out.println("Batch mode (no GUI):");
        System.out.println("  --list <keyring.asc>...");
        System.out.println("  --generate ...  --encrypt ...  --decrypt ...");
        System.out.println("  Run a batch command with --help for its options, e.g. pgp-tool --encrypt --help");
    }
}