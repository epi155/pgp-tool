package io.github.epi155.pgp.model;

import org.apache.commons.compress.archivers.zip.AsiExtraField;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.FileTime;
import java.util.function.Consumer;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * Streaming conversion of a {@link TarArchive} to ZIP.
 *
 * <p>Entries are written one at a time (8 KiB copy buffer) with sizes declared
 * upfront, so conversion never buffers the whole archive: peak memory is one
 * entry's in-memory content at a time (entries already materialize their bytes
 * in the {@link TarArchive} model, ≤50 MB each).</p>
 *
 * <p>Preserved per entry: full path, POSIX mode (permissions + file type),
 * modification time, numeric uid/gid (via {@code AsiExtraField}, best-effort),
 * symlinks (Info-ZIP convention: link target as entry content, {@code S_IFLNK}
 * mode). User/group <i>names</i> have no portable ZIP field and are not stored.
 * Compression is DEFLATED at default level; directories and symlinks are STORED.</p>
 *
 * <p>Limitation (shared with tar export): decoded entries larger than 50 MB hold
 * no content in the model ({@link TarEntry#getInputStream()} returns null) and
 * are written as empty entries.</p>
 */
public class ZipCodec {

    private ZipCodec() {}

    public static void convert(TarArchive archive, OutputStream out) throws IOException {
        convert(archive, out, null);
    }

    public static void convert(TarArchive archive, OutputStream out,
                               Consumer<Long> progressCallback) throws IOException {
        try (ZipArchiveOutputStream zipOut = new ZipArchiveOutputStream(out)) {
            zipOut.setEncoding("UTF-8");
            zipOut.setUseLanguageEncodingFlag(true);
            zipOut.setCreateUnicodeExtraFields(
                    ZipArchiveOutputStream.UnicodeExtraFieldPolicy.ALWAYS);
            zipOut.setLevel(Deflater.DEFAULT_COMPRESSION);

            long written = 0;
            for (TarEntry entry : archive.getEntries()) {
                String name = entry.getName();
                if (name == null || name.isEmpty()) continue;
                if (entry.isDirectory() && !name.endsWith("/")) {
                    name += "/";
                }

                ZipArchiveEntry zipEntry = new ZipArchiveEntry(name);
                int mode = entry.getMode();
                if (mode != 0) {
                    zipEntry.setUnixMode(mode);
                }
                if (entry.getModificationTime() > 0) {
                    zipEntry.setLastModifiedTime(
                            FileTime.fromMillis(entry.getModificationTime()));
                }
                addOwnership(zipEntry, entry, mode);

                if (entry.isDirectory()) {
                    zipEntry.setMethod(ZipArchiveEntry.STORED);
                    zipEntry.setSize(0);
                    zipEntry.setCrc(0); // empty content; required up-front for STORED streaming
                    zipOut.putArchiveEntry(zipEntry);
                    zipOut.closeArchiveEntry();
                } else if (entry.isSymbolicLink() && entry.getLinkName() != null) {
                    byte[] target = entry.getLinkName().getBytes(StandardCharsets.UTF_8);
                    zipEntry.setMethod(ZipArchiveEntry.STORED);
                    zipEntry.setSize(target.length);
                    CRC32 crc = new CRC32();
                    crc.update(target);
                    zipEntry.setCrc(crc.getValue());
                    zipOut.putArchiveEntry(zipEntry);
                    zipOut.write(target);
                    zipOut.closeArchiveEntry();
                    written += target.length;
                    if (progressCallback != null) progressCallback.accept(written);
                } else {
                    zipEntry.setMethod(ZipArchiveEntry.DEFLATED);
                    long size = Math.max(0, entry.getSize());
                    zipEntry.setSize(size);
                    zipOut.putArchiveEntry(zipEntry);
                    try (InputStream in = entry.getInputStream()) {
                        if (in != null) {
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = in.read(buf)) >= 0) {
                                zipOut.write(buf, 0, n);
                                written += n;
                                if (progressCallback != null) progressCallback.accept(written);
                            }
                        }
                    }
                    zipOut.closeArchiveEntry();
                }
            }
            zipOut.finish();
        }
    }

    /** Numeric uid/gid via the Info-ZIP ASi Unix extra field (best-effort). */
    private static void addOwnership(ZipArchiveEntry zipEntry, TarEntry entry, int mode) {
        try {
            long uid = entry.getUserId();
            long gid = entry.getGroupId();
            if (uid < 0 || uid > Integer.MAX_VALUE || gid < 0 || gid > Integer.MAX_VALUE) {
                return;
            }
            if (uid == 0 && gid == 0) {
                return;
            }
            AsiExtraField asi = new AsiExtraField();
            asi.setMode(mode);
            asi.setUserId((int) uid);
            asi.setGroupId((int) gid);
            if (entry.isDirectory()) asi.setDirectory(true);
            if (entry.isSymbolicLink() && entry.getLinkName() != null) {
                asi.setLinkedFile(entry.getLinkName());
            }
            zipEntry.addExtraField(asi);
        } catch (Exception ignored) {}
    }
}
