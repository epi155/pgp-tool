package io.github.epi155.pgp.cli;

public class CliException extends Exception {

    private final boolean usage;

    public CliException(String message) {
        this(message, false);
    }

    public CliException(String message, boolean usage) {
        super(message);
        this.usage = usage;
    }

    public boolean isUsage() {
        return usage;
    }
}
