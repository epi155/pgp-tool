package io.github.epi155.pgp.cli;

import java.util.Arrays;

public final class Cli {

    private Cli() {}

    public static boolean isCommand(String arg) {
        switch (arg) {
            case "--list":
            case "-l":
            case "--generate":
            case "-g":
            case "--encrypt":
            case "-e":
            case "--decrypt":
            case "-d":
                return true;
            default:
                return false;
        }
    }

    public static int run(String[] args, boolean privateExtensions) throws Exception {
        String cmd = args[0];
        Args a = new Args(Arrays.copyOfRange(args, 1, args.length));
        switch (cmd) {
            case "--list":
            case "-l":
                return ListCommand.run(a);
            case "--generate":
            case "-g":
                return GenerateCommand.run(a);
            case "--encrypt":
            case "-e":
                return EncryptCommand.run(a, privateExtensions);
            case "--decrypt":
            case "-d":
                return DecryptCommand.run(a);
            default:
                throw new CliException("Unknown command: " + cmd, true);
        }
    }

    public static String usage() {
        return "PGP Tool batch mode\n"
                + "\n"
                + "Commands:\n"
                + "  pgp-tool -g, --generate [options]      Generate a new key pair\n"
                + "  pgp-tool -e, --encrypt [options] [file] Encrypt data\n"
                + "  pgp-tool -d, --decrypt [options] [file] Decrypt data\n"
                + "  pgp-tool -l, --list <keyring.asc>...   List keys in a public keyring\n"
                + "\n"
                + "  -p, --private      Enable private extension algorithms (Serpent, ChaCha20-Poly1305,\n"
                + "                     ASCON ciphers, XZ/ZSTD compression, SHA3 hashes).\n"
                + "                     Place it before the command, e.g. pgp-tool -p -e ...\n"
                + "\n"
                + "Run a command with -h or --help for its options, e.g. pgp-tool -e --help.\n"
                + "Exit codes: 0 success, 1 runtime failure, 2 usage error.\n";
    }
}
