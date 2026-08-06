package io.github.epi155.pgp.cli;

import java.util.Arrays;

public final class Cli {

    private Cli() {}

    public static boolean isCommand(String arg) {
        switch (arg) {
            case "--list":
            case "--generate":
            case "--encrypt":
            case "--decrypt":
                return true;
            default:
                return false;
        }
    }

    public static int run(String[] args) throws Exception {
        String cmd = args[0];
        Args a = new Args(Arrays.copyOfRange(args, 1, args.length));
        switch (cmd) {
            case "--list":
                return ListCommand.run(a);
            case "--generate":
                return GenerateCommand.run(a);
            case "--encrypt":
                return EncryptCommand.run(a);
            case "--decrypt":
                return DecryptCommand.run(a);
            default:
                throw new CliException("Unknown command: " + cmd, true);
        }
    }

    public static String usage() {
        return "PGP Tool batch mode\n"
                + "\n"
                + "Commands:\n"
                + "  pgp-tool --generate [options]          Generate a new key pair\n"
                + "  pgp-tool --encrypt [options] [file]    Encrypt data\n"
                + "  pgp-tool --decrypt [options] [file]    Decrypt data\n"
                + "  pgp-tool --list <keyring.asc>...       List keys in a public keyring\n"
                + "\n"
                + "Run a command with --help for its options, e.g. pgp-tool --encrypt --help.\n"
                + "Exit codes: 0 success, 1 runtime failure, 2 usage error.\n";
    }
}
