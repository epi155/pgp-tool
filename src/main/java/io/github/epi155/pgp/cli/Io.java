package io.github.epi155.pgp.cli;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Io {

    private static final BufferedReader STDIN =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    private Io() {}

    public static byte[] readAll(String name) throws CliException {
        if ("-".equals(name)) {
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                StringBuilder sb = new StringBuilder();
                char[] buf = new char[8192];
                int n;
                while ((n = STDIN.read(buf)) >= 0) {
                    sb.append(buf, 0, n);
                }
                out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                return out.toByteArray();
            } catch (IOException e) {
                throw new CliException("Failed to read stdin: " + e.getMessage());
            }
        }
        Path path = Path.of(name);
        if (!Files.isRegularFile(path)) {
            throw new CliException(name + ": no such file", true);
        }
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new CliException("Failed to read " + name + ": " + e.getMessage());
        }
    }

    public static String readOneLineFromStdin() throws CliException {
        try {
            String line = STDIN.readLine();
            return line == null ? "" : line;
        } catch (IOException e) {
            throw new CliException("Failed to read stdin: " + e.getMessage());
        }
    }

    public static List<String> readLinesFromStdin() throws CliException {
        try {
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = STDIN.readLine()) != null) {
                if (!line.isEmpty()) lines.add(line);
            }
            return lines;
        } catch (IOException e) {
            throw new CliException("Failed to read stdin: " + e.getMessage());
        }
    }

    public static List<String> readLinesFromFile(String name) throws CliException {
        if ("-".equals(name)) {
            return readLinesFromStdin();
        }
        Path path = Path.of(name);
        if (!Files.isRegularFile(path)) {
            throw new CliException(name + ": no such file", true);
        }
        try {
            List<String> lines = new ArrayList<>();
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                if (!line.isEmpty()) lines.add(line);
            }
            return lines;
        } catch (IOException e) {
            throw new CliException("Failed to read " + name + ": " + e.getMessage());
        }
    }

    public static char[] toChars(String s) {
        return s.toCharArray();
    }

    public static List<char[]> toCharArrays(List<String> strings) {
        List<char[]> out = new ArrayList<>();
        for (String s : strings) out.add(s.toCharArray());
        return out;
    }
}
