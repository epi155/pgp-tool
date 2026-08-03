package io.github.epi155.pgp.cli;

import io.github.epi155.pgp.model.KeyBundle;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.KeyringLoader;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.File;
import java.util.*;

public final class KeySelector {

    public static final class Source {
        public final File file;
        public final List<String> ids;

        Source(File file, List<String> ids) {
            this.file = file;
            this.ids = ids;
        }
    }

    private KeySelector() {}

    public static Source parseSource(String token, String what) throws CliException {
        int hash = token.indexOf('#');
        String filePart;
        String idPart = null;
        if (hash >= 0) {
            filePart = token.substring(0, hash);
            idPart = token.substring(hash + 1);
            if (idPart.isEmpty()) throw new CliException(what + " has an empty ID list in '" + token + "'", true);
        } else {
            filePart = token;
        }
        if (filePart.isEmpty()) throw new CliException(what + " has an empty keyring path in '" + token + "'", true);
        List<String> ids = new ArrayList<>();
        if (idPart != null) {
            for (String id : idPart.split(",")) {
                if (id.trim().isEmpty()) throw new CliException(what + " has an empty ID in '" + token + "'", true);
                ids.add(id.trim());
            }
        }
        return new Source(new File(filePart), ids);
    }

    public static List<PGPKeyInfo> select(Source source, boolean secret,
                                          boolean requireEncrypt, boolean requireSign) throws CliException {
        if (!source.file.isFile()) {
            throw new CliException(source.file + ": no such file", true);
        }
        try {
            KeyBundle bundle = secret
                    ? KeyringLoader.loadSecretKeys(source.file)
                    : KeyringLoader.loadPublicKeys(source.file);
            List<PGPKeyInfo> all = flatten(bundle.getKeys());
            List<PGPKeyInfo> selected = new ArrayList<>();
            Set<Long> seen = new HashSet<>();

            if (source.ids.isEmpty()) {
                for (PGPKeyInfo info : all) {
                    if (!capable(info, requireEncrypt, requireSign)) continue;
                    if (!usable(info)) continue;
                    if (!seen.add(info.getKeyId())) continue;
                    selected.add(info);
                }
                if (selected.isEmpty()) {
                    throw new CliException("No usable " + capability(requireEncrypt, requireSign)
                            + " key in " + source.file + " (found: " + describe(all) + ")", true);
                }
            } else {
                for (String id : source.ids) {
                    List<PGPKeyInfo> matches = match(all, id);
                    if (matches.isEmpty()) {
                        throw new CliException("Key " + id + " not found in " + source.file
                                + " (found: " + describe(all) + ")", true);
                    }
                    if (matches.size() > 1) {
                        StringBuilder sb = new StringBuilder("Short key ID " + id + " is ambiguous in "
                                + source.file + ":");
                        for (PGPKeyInfo m : matches) {
                            sb.append(" 0x").append(String.format("%016X", m.getKeyId()));
                        }
                        sb.append(" - use a full key ID");
                        throw new CliException(sb.toString(), true);
                    }
                    PGPKeyInfo info = matches.get(0);
                    if (!capable(info, requireEncrypt, requireSign)) {
                        throw new CliException("Key 0x" + String.format("%016X", info.getKeyId())
                                + " in " + source.file + " cannot be used for "
                                + capability(requireEncrypt, requireSign)
                                + " (available: " + describe(all) + ")", true);
                    }
                    if (!usable(info)) {
                        throw new CliException("Key 0x" + String.format("%016X", info.getKeyId())
                                + " in " + source.file + " is revoked or expired", true);
                    }
                    if (seen.add(info.getKeyId())) selected.add(info);
                }
            }
            return selected;
        } catch (CliException e) {
            throw e;
        } catch (Exception e) {
            throw new CliException("Failed to load " + source.file + ": " + e.getMessage());
        }
    }

    public static List<PGPPublicKey> publicKeys(String token, boolean requireEncrypt) throws CliException {
        Source source = parseSource(token, "key source");
        List<PGPKeyInfo> infos = select(source, false, requireEncrypt, !requireEncrypt);
        List<PGPPublicKey> keys = new ArrayList<>();
        for (PGPKeyInfo info : infos) keys.add(info.getBcKey(PGPPublicKey.class));
        return keys;
    }

    public static List<PGPSecretKey> secretKeys(String token) throws CliException {
        Source source = parseSource(token, "secret key source");
        List<PGPKeyInfo> infos = select(source, true, false, false);
        List<PGPSecretKey> keys = new ArrayList<>();
        for (PGPKeyInfo info : infos) keys.add(info.getBcKey(PGPSecretKey.class));
        return keys;
    }

    private static List<PGPKeyInfo> flatten(List<PGPKeyInfo> masters) {
        List<PGPKeyInfo> all = new ArrayList<>();
        for (PGPKeyInfo m : masters) {
            all.add(m);
            all.addAll(m.getSubKeys());
        }
        return all;
    }

    private static boolean capable(PGPKeyInfo info, boolean requireEncrypt, boolean requireSign) {
        if (requireEncrypt && requireSign) return info.canEncrypt() && info.canSign();
        if (requireEncrypt) return info.canEncrypt();
        if (requireSign) return info.canSign();
        return true;
    }

    private static boolean usable(PGPKeyInfo info) {
        Object bc = info.getBcKey(Object.class);
        PGPPublicKey pk;
        if (bc instanceof PGPPublicKey) {
            pk = (PGPPublicKey) bc;
        } else if (bc instanceof PGPSecretKey) {
            pk = ((PGPSecretKey) bc).getPublicKey();
        } else {
            return true;
        }
        if (pk.isRevoked()) return false;
        long valid = pk.getValidSeconds();
        if (valid > 0) {
            long expiresAt = pk.getCreationTime().getTime() + valid * 1000L;
            if (expiresAt < System.currentTimeMillis()) return false;
        }
        return true;
    }

    private static List<PGPKeyInfo> match(List<PGPKeyInfo> all, String id) throws CliException {
        String norm = id.trim().toUpperCase(Locale.ROOT);
        if (norm.startsWith("0X")) norm = norm.substring(2);
        if (norm.isEmpty() || !norm.matches("[0-9A-F]+")) {
            throw new CliException("Invalid key ID: '" + id + "' (hex expected)", true);
        }
        List<PGPKeyInfo> out = new ArrayList<>();
        switch (norm.length()) {
            case 8: {
                long low = Long.parseUnsignedLong(norm, 16);
                for (PGPKeyInfo i : all) {
                    if ((i.getKeyId() & 0xFFFFFFFFL) == low) out.add(i);
                }
                break;
            }
            case 16: {
                long full = Long.parseUnsignedLong(norm, 16);
                for (PGPKeyInfo i : all) {
                    if (i.getKeyId() == full) out.add(i);
                }
                break;
            }
            case 32: {
                for (PGPKeyInfo i : all) {
                    if (i.getFingerprint().equalsIgnoreCase(norm)) out.add(i);
                }
                break;
            }
            default:
                throw new CliException("Invalid key ID format: '" + id + "' (use 8, 16 or 32 hex digits)", true);
        }
        return out;
    }

    private static String capability(boolean encrypt, boolean sign) {
        if (encrypt) return "encryption";
        if (sign) return "signing";
        return "usable";
    }

    private static String describe(List<PGPKeyInfo> all) {
        StringBuilder sb = new StringBuilder();
        for (PGPKeyInfo i : all) {
            if (sb.length() > 0) sb.append(", ");
            sb.append("0x").append(String.format("%016X", i.getKeyId()));
            sb.append(i.canSign() ? "S" : "").append(i.canEncrypt() ? "E" : "");
        }
        return sb.toString();
    }
}
