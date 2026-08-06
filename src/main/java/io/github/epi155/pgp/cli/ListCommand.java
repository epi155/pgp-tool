package io.github.epi155.pgp.cli;

import io.github.epi155.pgp.model.KeyBundle;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.KeyringLoader;

import java.io.File;
import java.util.List;

public final class ListCommand {

    private ListCommand() {}

    public static int run(Args args) throws Exception {
        if (args.flag("--help") || args.flag("-h")) {
            System.out.println(usage());
            return 0;
        }
        List<String> files = args.remaining();
        if (files.isEmpty()) {
            throw new CliException("No keyring file given", true);
        }
        for (String f : files) {
            File file = new File(f);
            if (!file.isFile()) {
                throw new CliException(f + ": no such file", true);
            }
            KeyBundle bundle;
            boolean secret = false;
            try {
                bundle = KeyringLoader.loadPublicKeys(file);
            } catch (Exception e) {
                try {
                    bundle = KeyringLoader.loadSecretKeys(file);
                    secret = true;
                } catch (Exception e2) {
                    throw new CliException("Failed to load " + f + ": " + e.getMessage());
                }
            }
            System.out.println("File: " + f + (secret ? " (secret keyring)" : ""));
            for (PGPKeyInfo master : bundle.getKeys()) {
                System.out.println("  " + master);
                for (PGPKeyInfo sub : master.getSubKeys()) {
                    System.out.println("     \\- " + sub);
                }
            }
        }
        return 0;
    }

    static String usage() {
        return "Usage: pgp-tool -l, --list <keyring.asc>...\n"
                + "List the public keys (and subkeys) contained in the given keyrings.\n"
                + "Each line shows algorithm, key ID and [S]ign/[E]ncrypt capability.\n";
    }
}
