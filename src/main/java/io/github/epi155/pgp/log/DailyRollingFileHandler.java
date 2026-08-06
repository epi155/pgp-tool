package io.github.epi155.pgp.log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;

public class DailyRollingFileHandler extends Handler {

    static final String LOG_FILE_NAME = "pgp-tools.log";
    static final String LOG_FILE_PATTERN = "pgp-tools-%s.log";
    static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final int RETENTION_DAYS = 7;

    private final File dir;
    private PrintWriter writer;
    private LocalDate today;

    public DailyRollingFileHandler() throws IOException {
        String home = System.getProperty("user.home");
        this.dir = new File(home, "logs");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Cannot create log directory: " + dir.getAbsolutePath());
        }
        setFormatter(new SimpleFormatter());
        this.today = LocalDate.now();
        open();
        prune();
    }

    private File currentFile() {
        return new File(dir, LOG_FILE_NAME);
    }

    private void open() throws IOException {
        writer = new PrintWriter(new FileWriter(currentFile(), true), true);
    }

    private void roll() {
        try {
            writer.flush();
            writer.close();
            File archive = new File(dir, String.format(LOG_FILE_PATTERN, today.format(DATE_FORMAT)));
            File current = currentFile();
            if (current.exists() && !archive.exists()) {
                current.renameTo(archive);
            }
            today = LocalDate.now();
            open();
            prune();
        } catch (IOException e) {
            reportError("Error rotating log file", e, 0);
        }
    }

    private void prune() {
        LocalDate cutoff = LocalDate.now().minusDays(RETENTION_DAYS);
        File[] files = dir.listFiles((d, name) -> name.matches(String.format(LOG_FILE_PATTERN, "\\d{4}-\\d{2}-\\d{2}")));
        if (files == null) return;
        for (File f : files) {
            String datePart = f.getName().replace(LOG_FILE_NAME, "").replace(".log", "").replace("pgp-tools-", "");
            try {
                LocalDate fileDate = LocalDate.parse(datePart, DATE_FORMAT);
                if (fileDate.isBefore(cutoff)) {
                    f.delete();
                }
            } catch (Exception ignored) {
            }
        }
    }

    @Override
    public synchronized void publish(LogRecord record) {
        if (record == null || writer == null) return;
        LocalDate recordDate = LocalDate.now();
        if (!recordDate.equals(today)) {
            roll();
        }
        try {
            writer.print(getFormatter().format(record));
            writer.flush();
        } catch (Exception e) {
            reportError("Error writing log record", e, 0);
        }
    }

    @Override
    public synchronized void flush() {
        if (writer != null) {
            writer.flush();
        }
    }

    @Override
    public synchronized void close() throws SecurityException {
        if (writer != null) {
            writer.flush();
            writer.close();
            writer = null;
        }
    }
}
