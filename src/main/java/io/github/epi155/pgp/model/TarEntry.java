package io.github.epi155.pgp.model;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class TarEntry {

    private final TarArchiveEntry entry;
    private final List<TarEntry> children = new ArrayList<>();
    private TarEntry parent;
    private Path sourcePath;

    public TarEntry(String name) {
        this.entry = new TarArchiveEntry(name);
    }

    public TarEntry(String name, byte[] content, long modificationTime) {
        this.entry = new TarArchiveEntry(name);
        this.entry.setSize(content.length);
        this.entry.setModTime(new java.util.Date(modificationTime));
        this.cachedContent = content;
    }

    public TarEntry(TarArchiveEntry entry) {
        this.entry = entry;
    }

    private byte[] cachedContent;

    public static TarEntry createDirectory(String name) {
        TarEntry entry = new TarEntry(name.endsWith("/") ? name : name + "/");
        entry.entry.setMode(040755); // S_IFDIR | 0755
        entry.entry.setSize(0);
        return entry;
    }

    public static TarEntry createFile(String name, long size) {
        TarEntry entry = new TarEntry(name);
        entry.entry.setMode(0100644); // S_IFREG | 0644
        entry.entry.setSize(size);
        return entry;
    }

    public static TarEntry fromPath(Path path, String nameInArchive) throws IOException {
        TarArchiveEntry entry = new TarArchiveEntry(path.toFile(), nameInArchive);
        TarEntry tarEntry = new TarEntry(entry);
        tarEntry.sourcePath = path;
        if (Files.isSymbolicLink(path)) {
            String target = Files.readSymbolicLink(path).toString();
            tarEntry.entry.setLinkName(target);
            tarEntry.entry.setMode(0120777);
            tarEntry.entry.setSize(target.length());
            setLinkFlag(tarEntry.entry, (byte) 0x32);
        } else if (Files.isDirectory(path)) {
            tarEntry.entry.setMode(040755);
        } else {
            if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                try {
                    Set<PosixFilePermission> perms = Files.readAttributes(path, PosixFileAttributes.class).permissions();
                    tarEntry.entry.setMode(permissionsToMode(perms, true));
                } catch (Exception ignored) {
                    tarEntry.entry.setMode(0100644);
                }
            } else {
                tarEntry.entry.setMode(0100644);
            }
        }
        return tarEntry;
    }

    private static void setLinkFlag(TarArchiveEntry entry, byte flag) {
        try {
            java.lang.reflect.Field f = TarArchiveEntry.class.getDeclaredField("linkFlag");
            f.setAccessible(true);
            f.setByte(entry, flag);
        } catch (Exception ignored) {}
    }

    private static int permissionsToMode(Set<PosixFilePermission> perms, boolean isFile) {
        int mode = isFile ? 0100000 : 0040000;
        if (perms.contains(PosixFilePermission.OWNER_READ))    mode |= 0400;
        if (perms.contains(PosixFilePermission.OWNER_WRITE))   mode |= 0200;
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE)) mode |= 0100;
        if (perms.contains(PosixFilePermission.GROUP_READ))    mode |= 0040;
        if (perms.contains(PosixFilePermission.GROUP_WRITE))   mode |= 0020;
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE)) mode |= 0010;
        if (perms.contains(PosixFilePermission.OTHERS_READ))   mode |= 0004;
        if (perms.contains(PosixFilePermission.OTHERS_WRITE))  mode |= 0002;
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE))mode |= 0001;
        return mode;
    }

    public TarArchiveEntry getEntry() {
        return entry;
    }

    public String getName() {
        return entry.getName();
    }

    public void setName(String name) {
        entry.setName(name);
    }

    public long getSize() {
        return entry.getSize();
    }

    public void setSize(long size) {
        entry.setSize(size);
    }

    public int getMode() {
        return entry.getMode();
    }

    public void setMode(int mode) {
        entry.setMode(mode);
    }

    public long getModificationTime() {
        return entry.getModTime().getTime();
    }

    public void setModificationTime(long millis) {
        entry.setModTime(new java.util.Date(millis));
    }

    public String getLinkName() {
        return entry.getLinkName();
    }

    public void setLinkName(String linkName) {
        entry.setLinkName(linkName);
    }

    public byte getTypeFlag() {
        return (byte) (entry.getMode() >> 12 & 0xF);
    }

    public boolean isDirectory() {
        return entry.isDirectory();
    }

    public boolean isFile() {
        return entry.isFile();
    }

    public boolean isSymbolicLink() {
        int mode = getMode();
        return (mode & 0170000) == 0120000;
    }

    public TarEntry getParent() {
        return parent;
    }

    public void setParent(TarEntry parent) {
        this.parent = parent;
    }

    public List<TarEntry> getChildren() {
        return children;
    }

    public void addChild(TarEntry child) {
        child.setParent(this);
        children.add(child);
    }

    public void removeChild(TarEntry child) {
        children.remove(child);
        child.setParent(null);
    }

    public Path getSourcePath() {
        return sourcePath;
    }

    public void setSourcePath(Path sourcePath) {
        this.sourcePath = sourcePath;
    }

    public InputStream getInputStream() throws IOException {
        if (cachedContent != null) {
            return new ByteArrayInputStream(cachedContent);
        }
        if (sourcePath != null && Files.exists(sourcePath)) {
            return Files.newInputStream(sourcePath);
        }
        return null;
    }

    public byte[] getContent() throws IOException {
        if (cachedContent != null) {
            return cachedContent;
        }
        if (sourcePath != null && Files.exists(sourcePath)) {
            return Files.readAllBytes(sourcePath);
        }
        return new byte[0];
    }

    public void writeTo(OutputStream out) throws IOException {
        if (cachedContent != null) {
            out.write(cachedContent);
        } else if (sourcePath != null && Files.exists(sourcePath)) {
            Files.copy(sourcePath, out);
        }
    }

    public String getRelativePath() {
        if (parent == null) {
            return getName();
        }
        return parent.getRelativePath() + getName();
    }

    @Override
    public String toString() {
        return getName() + (isDirectory() ? "/" : "");
    }
}