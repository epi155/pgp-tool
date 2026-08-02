package io.github.epi155.pgp.cli;

import java.util.ArrayList;
import java.util.List;

public class Args {

    private final String[] args;
    private int i;

    public Args(String[] args) {
        this.args = args;
    }

    public boolean hasNext() {
        return i < args.length;
    }

    public String peek() throws CliException {
        if (!hasNext()) throw new CliException("Unexpected end of arguments", true);
        return args[i];
    }

    public String next() throws CliException {
        if (!hasNext()) throw new CliException("Unexpected end of arguments", true);
        return args[i++];
    }

    public String value(String flag) throws CliException {
        if (!hasNext()) throw new CliException("Missing value for " + flag, true);
        String tok = args[i];
        if (tok.equals(flag)) {
            i++;
            if (!hasNext()) throw new CliException("Missing value for " + flag, true);
            return args[i++];
        }
        if (tok.startsWith(flag + "=")) {
            i++;
            String v = tok.substring(flag.length() + 1);
            if (v.isEmpty()) throw new CliException("Missing value for " + flag, true);
            return v;
        }
        throw new CliException("Expected " + flag + ", got " + tok, true);
    }

    public String optValue(String flag, String def) throws CliException {
        if (!hasNext()) return def;
        String tok = args[i];
        if (tok.equals(flag)) {
            if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                i += 2;
                return args[i - 1];
            }
            throw new CliException("Missing value for " + flag, true);
        }
        if (tok.startsWith(flag + "=")) {
            i++;
            return tok.substring(flag.length() + 1);
        }
        return def;
    }

    public List<String> multi(String flag) throws CliException {
        List<String> out = new ArrayList<>();
        while (hasNext()) {
            String tok = args[i];
            if (tok.equals(flag)) {
                i++;
                if (!hasNext()) throw new CliException("Missing value for " + flag, true);
                out.add(args[i++]);
            } else if (tok.startsWith(flag + "=")) {
                i++;
                String v = tok.substring(flag.length() + 1);
                if (v.isEmpty()) throw new CliException("Missing value for " + flag, true);
                out.add(v);
            } else {
                break;
            }
        }
        return out;
    }

    public boolean flag(String name) throws CliException {
        if (!hasNext()) return false;
        String tok = args[i];
        if (tok.equals(name)) {
            i++;
            return true;
        }
        if (tok.startsWith(name + "=")) {
            throw new CliException("Flag " + name + " does not take a value", true);
        }
        return false;
    }

    public List<String> remaining() throws CliException {
        List<String> out = new ArrayList<>();
        while (hasNext()) out.add(next());
        return out;
    }
}
