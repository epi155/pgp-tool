package io.github.epi155.pgp.model;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

public class TarArchive {

    private final TarEntry root;
    private String plainText;
    private String baseName;

    public TarArchive() {
        this.root = TarEntry.createDirectory("");
        this.baseName = "archive";
    }

    public TarArchive(String baseName) {
        this.root = TarEntry.createDirectory("");
        this.baseName = baseName != null && !baseName.isEmpty() ? baseName : "archive";
    }

    public static TarArchive empty() {
        return new TarArchive();
    }

    public static TarArchive fromPlainText(String plainText, String baseName) {
        TarArchive archive = new TarArchive(baseName);
        archive.plainText = plainText;
        return archive;
    }

    public TarEntry getRoot() {
        return root;
    }

    public List<TarEntry> getEntries() {
        List<TarEntry> result = new ArrayList<>();
        collectEntries(root, result);
        return result;
    }

    private void collectEntries(TarEntry entry, List<TarEntry> result) {
        for (TarEntry child : entry.getChildren()) {
            result.add(child);
            if (child.isDirectory()) {
                collectEntries(child, result);
            }
        }
    }

    public List<TarEntry> getFlatEntries() {
        List<TarEntry> result = new ArrayList<>();
        for (TarEntry child : root.getChildren()) {
            if (!child.isDirectory()) {
                result.add(child);
            } else {
                collectFlatEntries(child, result);
            }
        }
        return result;
    }

    private void collectFlatEntries(TarEntry entry, List<TarEntry> result) {
        for (TarEntry child : entry.getChildren()) {
            if (!child.isDirectory()) {
                result.add(child);
            } else {
                collectFlatEntries(child, result);
            }
        }
    }

    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }

    public String getPlainText() {
        return plainText;
    }

    public String getBaseName() {
        return baseName;
    }

    public void setBaseName(String baseName) {
        this.baseName = baseName;
    }

    public String getTarFileName() {
        return baseName + ".tar";
    }

    public boolean hasAttachments() {
        return !root.getChildren().isEmpty();
    }

    public void addEntry(TarEntry entry) {
        root.addChild(entry);
    }

    public void addEntry(String path, TarEntry entry) {
        TarEntry parent = findOrCreatePath(path);
        parent.addChild(entry);
    }

    public TarEntry findOrCreatePath(String path) {
        if (path == null || path.isEmpty() || "/".equals(path)) {
            return root;
        }
        String[] parts = path.split("/");
        TarEntry current = root;
        for (String part : parts) {
            if (part.isEmpty()) continue;
            TarEntry child = findChild(current, part);
            if (child == null) {
                child = TarEntry.createDirectory(part);
                current.addChild(child);
            }
            current = child;
        }
        return current;
    }

    private TarEntry findChild(TarEntry parent, String name) {
        for (TarEntry child : parent.getChildren()) {
            if (child.getName().equals(name)) {
                return child;
            }
        }
        return null;
    }

    public TarEntry findEntry(String path) {
        if (path == null || path.isEmpty()) return root;
        String[] parts = path.split("/");
        TarEntry current = root;
        for (String part : parts) {
            if (part.isEmpty()) continue;
            boolean found = false;
            for (TarEntry child : current.getChildren()) {
                if (child.getName().equals(part)) {
                    current = child;
                    found = true;
                    break;
                }
            }
            if (!found) return null;
        }
        return current;
    }

    public void removeEntry(TarEntry entry) {
        if (entry.getParent() != null) {
            entry.getParent().removeChild(entry);
        }
    }

    public void writeTo(OutputStream out) throws IOException {
        try (TarArchiveOutputStream tarOut = new TarArchiveOutputStream(out)) {
            tarOut.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            writeEntry(root, tarOut);
            tarOut.finish();
        }
    }

    private void writeEntry(TarEntry entry, TarArchiveOutputStream tarOut) throws IOException {
        if (!entry.isDirectory() || entry != root) {
            tarOut.putArchiveEntry(entry.getEntry());
            if (!entry.isDirectory()) {
                try (InputStream in = entry.getInputStream()) {
                    if (in != null) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) >= 0) {
                            tarOut.write(buf, 0, n);
                        }
                    }
                }
            tarOut.closeArchiveEntry();
        }
        for (TarEntry child : entry.getChildren()) {
            writeEntry(child, tarOut);
        }
    }
    }

    public void writeTo(OutputStream out, Consumer<Long> progressCallback) throws IOException {
        try (TarArchiveOutputStream tarOut = new TarArchiveOutputStream(out)) {
            tarOut.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            long written = 0;
            for (TarEntry entry : getFlatEntries()) {
                tarOut.putArchiveEntry(entry.getEntry());
                if (entry.getInputStream() != null) {
                    try (InputStream in = entry.getInputStream()) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) >= 0) {
                            tarOut.write(buf, 0, n);
                            written += n;
                            if (progressCallback != null) progressCallback.accept(written);
                        }
                    }
                }
                tarOut.closeArchiveEntry();
            }
            tarOut.finish();
        }
    }

    public void extractTo(Path targetDir) throws IOException {
        Files.createDirectories(targetDir);
        for (TarEntry entry : getFlatEntries()) {
            Path target = targetDir.resolve(entry.getName());
            Files.createDirectories(target.getParent());
            try (InputStream in = entry.getInputStream()) {
                if (in != null) {
                    Files.copy(in, target);
                }
            }
            if (entry.getModificationTime() > 0) {
                Files.setLastModifiedTime(targetDir.resolve(entry.getName()), FileTime.fromMillis(entry.getModificationTime()));
            }
        }
    }

    public int getEntryCount() {
        return getEntries().size();
    }

    public long getTotalSize() {
        return getFlatEntries().stream().mapToLong(TarEntry::getSize).sum();
    }
}