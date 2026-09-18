package io.github.epi155.pgp.model;

import io.github.epi155.pgp.log.AppLog;
import io.github.epi155.pgp.service.SecureTempFile;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public class TarArchive {

    private final TarEntry root;
    private String plainText;
    private String baseName;
    /** Session-encrypted staging files backing large entries; wiped on {@link #dispose()}. */
    private final List<SecureTempFile> stagingTemps = new ArrayList<>();

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

    /**
     * Registers a session-encrypted staging file owned by this archive.
     * It is wiped when {@link #dispose()} is called.
     */
    public void addStagingTemp(SecureTempFile temp) {
        if (temp != null) stagingTemps.add(temp);
    }

    /**
     * Wipes the session-encrypted staging files backing large entries.
     * Safe to call multiple times. In-memory content is unaffected.
     */
    public void dispose() {
        for (SecureTempFile temp : stagingTemps) {
            try { temp.wipeAndDelete(); } catch (Exception ignored) {}
        }
        stagingTemps.clear();
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
        if (entry != root) {
            tarOut.putArchiveEntry(entry.getEntry());
            if (entry.isSymbolicLink()) {
                String linkTarget = entry.getLinkName();
                if (linkTarget != null) {
                    tarOut.write(linkTarget.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            } else if (!entry.isDirectory()) {
                try (InputStream in = entry.getInputStream()) {
                    if (in != null) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) >= 0) {
                            tarOut.write(buf, 0, n);
                        }
                    }
                }
            }
            tarOut.closeArchiveEntry();
        }
        for (TarEntry child : entry.getChildren()) {
            writeEntry(child, tarOut);
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

    public List<String> extractTo(Path targetDir) throws IOException {
        Files.createDirectories(targetDir);
        List<String> warnings = new ArrayList<>();
        for (TarEntry entry : getFlatEntries()) {
            String name = entry.getName();
            if (name == null || name.isEmpty() || ".".equals(name) || "..".equals(name)) continue;
            Path target = targetDir.resolve(name).normalize();
            if (!target.startsWith(targetDir)) continue;
            Files.createDirectories(target.getParent());
            if (entry.isSymbolicLink() && entry.getLinkName() != null) {
                Files.deleteIfExists(target);
                Files.createSymbolicLink(target, Path.of(entry.getLinkName()));
            } else {
                boolean hasContent = false;
                try (InputStream in = entry.getInputStream()) {
                    if (in != null) {
                        Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
                        hasContent = true;
                    }
                }
                if (!hasContent && entry.getSize() > 0) {
                    warnings.add("No content available for " + entry.getName()
                            + ": entry too large to keep in memory");
                }
                if (entry.getModificationTime() > 0) {
                    Files.setLastModifiedTime(target, FileTime.fromMillis(entry.getModificationTime()));
                }
                int mode = entry.getMode();
                if (mode != 0 && target.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                    try {
                        Set<PosixFilePermission> perms = modeToPermissions(mode);
                        Files.setPosixFilePermissions(target, perms);
                    } catch (Exception ignored) {}
                }
                restoreOwnership(target, entry, warnings);
            }
        }
        return warnings;
    }

    private void restoreOwnership(Path target, TarEntry entry, List<String> warnings) {
        if (!target.getFileSystem().supportedFileAttributeViews().contains("posix")) return;
        PosixFileAttributeView posixView = Files.getFileAttributeView(target, PosixFileAttributeView.class);
        if (posixView == null) return;
        String userName = entry.getUserName();
        if (userName != null && !userName.isEmpty()) {
            try {
                UserPrincipal owner = target.getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByName(userName);
                posixView.setOwner(owner);
            } catch (Exception e) {
                AppLog.error("Failed to restore owner for " + entry.getName(), e);
                warnings.add("Could not restore owner for " + entry.getName() + ": " + e.getMessage());
            }
        }
        String groupName = entry.getGroupName();
        if (groupName != null && !groupName.isEmpty()) {
            try {
                GroupPrincipal group = target.getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByGroupName(groupName);
                posixView.setGroup(group);
            } catch (Exception e) {
                AppLog.error("Failed to restore group for " + entry.getName(), e);
                warnings.add("Could not restore group for " + entry.getName() + ": " + e.getMessage());
            }
        }
    }

    private static Set<PosixFilePermission> modeToPermissions(int mode) {
        Set<PosixFilePermission> perms = new HashSet<>();
        if ((mode & 0400) != 0) perms.add(PosixFilePermission.OWNER_READ);
        if ((mode & 0200) != 0) perms.add(PosixFilePermission.OWNER_WRITE);
        if ((mode & 0100) != 0) perms.add(PosixFilePermission.OWNER_EXECUTE);
        if ((mode & 0040) != 0) perms.add(PosixFilePermission.GROUP_READ);
        if ((mode & 0020) != 0) perms.add(PosixFilePermission.GROUP_WRITE);
        if ((mode & 0010) != 0) perms.add(PosixFilePermission.GROUP_EXECUTE);
        if ((mode & 0004) != 0) perms.add(PosixFilePermission.OTHERS_READ);
        if ((mode & 0002) != 0) perms.add(PosixFilePermission.OTHERS_WRITE);
        if ((mode & 0001) != 0) perms.add(PosixFilePermission.OTHERS_EXECUTE);
        return perms;
    }

    public int getEntryCount() {
        return getEntries().size();
    }

    public long getTotalSize() {
        return getFlatEntries().stream().mapToLong(TarEntry::getSize).sum();
    }
}