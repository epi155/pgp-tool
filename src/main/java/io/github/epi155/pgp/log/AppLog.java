package io.github.epi155.pgp.log;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.GraphicsEnvironment;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AppLog {

    public static final String LOGGER_NAME = "pgp.tool";
    private static final Logger LOGGER = Logger.getLogger(LOGGER_NAME);

    private static volatile boolean initialized;

    private AppLog() {
    }

    public static void init() {
        if (initialized) return;
        synchronized (AppLog.class) {
            if (initialized) return;
            try {
                DailyRollingFileHandler handler = new DailyRollingFileHandler();
                LOGGER.setLevel(Level.WARNING);
                LOGGER.addHandler(handler);
                LOGGER.setUseParentHandlers(false);
            } catch (Exception e) {
                System.err.println("Error initializing log file: " + e.getMessage());
            }
            installUncaughtExceptionHandler();
            initialized = true;
        }
    }

    public static void error(String context, Throwable t) {
        if (t == null) {
            LOGGER.severe(context);
        } else {
            LOGGER.log(Level.SEVERE, context, t);
        }
    }

    private static void installUncaughtExceptionHandler() {
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            error("Uncaught exception in thread " + thread.getName(), throwable);
            showUnexpectedError(throwable);
        });
    }

    private static void showUnexpectedError(Throwable throwable) {
        if (GraphicsEnvironment.isHeadless()) return;
        try {
            String message = throwable.getMessage() != null ? throwable.getMessage() : throwable.getClass().getSimpleName();
            SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(null, "Unexpected error:\n" + message,
                            "Error", JOptionPane.ERROR_MESSAGE));
        } catch (Throwable ignored) {
        }
    }
}
