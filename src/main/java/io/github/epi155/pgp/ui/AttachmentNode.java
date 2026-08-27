package io.github.epi155.pgp.ui;

import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.TarEntry;

import javax.swing.tree.DefaultMutableTreeNode;
import java.io.File;

public class AttachmentNode extends DefaultMutableTreeNode {

    public enum Kind { ROOT, FILE, DIRECTORY, TAR_ENTRY, COMPOUND_ENTRY }

    private final Kind kind;
    private final String displayName;
    private File file;
    private TarEntry tarEntry;
    private CompoundMessage.Attachment compoundAtt;

    private AttachmentNode(Kind kind, String displayName) {
        super(displayName);
        this.kind = kind;
        this.displayName = displayName;
    }

    public static AttachmentNode root(String name) {
        return new AttachmentNode(Kind.ROOT, name);
    }

    public static AttachmentNode directory(String name) {
        AttachmentNode n = new AttachmentNode(Kind.DIRECTORY, name);
        return n;
    }

    public static AttachmentNode ofFile(File file) {
        AttachmentNode n = new AttachmentNode(Kind.FILE, file.getName());
        n.file = file;
        return n;
    }

    public static AttachmentNode ofTarEntry(TarEntry entry) {
        String name = entry.getName();
        int lastSlash = name.lastIndexOf('/');
        String display = lastSlash >= 0 ? name.substring(lastSlash + 1) : name;
        AttachmentNode n = new AttachmentNode(Kind.TAR_ENTRY, display);
        n.tarEntry = entry;
        return n;
    }

    public static AttachmentNode ofCompound(CompoundMessage.Attachment att) {
        AttachmentNode n = new AttachmentNode(Kind.COMPOUND_ENTRY, att.getFilename());
        n.compoundAtt = att;
        return n;
    }

    public Kind getKind() { return kind; }
    public String getDisplayName() { return displayName; }
    public File getFile() { return file; }
    public TarEntry getTarEntry() { return tarEntry; }
    public CompoundMessage.Attachment getCompoundAtt() { return compoundAtt; }

    public boolean isDirectory() { return kind == Kind.DIRECTORY || kind == Kind.ROOT; }

    public long getModificationTime() {
        if (tarEntry != null) return tarEntry.getModificationTime();
        if (compoundAtt != null) return compoundAtt.getModificationTime();
        if (file != null) {
            try { return file.lastModified(); } catch (Exception e) { return 0; }
        }
        return 0;
    }

    @Override
    public String toString() {
        if (kind == Kind.ROOT || kind == Kind.DIRECTORY) return displayName + "/";
        return displayName;
    }
}
