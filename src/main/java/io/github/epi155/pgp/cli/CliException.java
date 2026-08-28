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

    public CliException(String message, Throwable cause, boolean usage) {
        super(message, cause);
        this.usage = usage;
    }

    public CliException(String message, Throwable cause) {
        this(message, cause, false);
    }

    public boolean isUsage() {
        return usage;
    }
}
