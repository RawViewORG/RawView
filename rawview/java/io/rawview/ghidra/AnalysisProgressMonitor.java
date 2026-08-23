package io.rawview.ghidra;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.function.Supplier;

import ghidra.util.task.TaskMonitorAdapter;

/**
 * Writes analysis status to {@code .rawview_analysis_progress.json} for the Qt UI (see {@code main_window.py}).
 */
public class AnalysisProgressMonitor extends TaskMonitorAdapter {

    private final File progressFile;
    /** Called from flush only (Ghidra-driven cadence) -  reads active command {@code getStatusMsg()} etc. */
    private final Supplier<String> activeCommandSummary;
    private String lastWrittenJson = "";

    public AnalysisProgressMonitor(File progressFile, Supplier<String> activeCommandSummary) {
        // Cancellable: GhidraBridge.cancelAnalysis() stops a long auto-analysis run from the UI/agent.
        super(true);
        this.progressFile = progressFile;
        this.activeCommandSummary = activeCommandSummary;
    }

    @Override
    public void initialize(long max) {
        super.initialize(max);
        flush();
    }

    @Override
    public void setMaximum(long max) {
        super.setMaximum(max);
        flush();
    }

    @Override
    public void setProgress(long value) {
        super.setProgress(value);
        flush();
    }

    @Override
    public void setIndeterminate(boolean indeterminate) {
        super.setIndeterminate(indeterminate);
        flush();
    }

    @Override
    public void setMessage(String message) {
        super.setMessage(message);
        flush();
    }

    @Override
    public void incrementProgress(long incrementAmount) {
        super.incrementProgress(incrementAmount);
        flush();
    }

    @Override
    public void cancel() {
        super.cancel();
        flush();
    }

    private synchronized void flush() {
        try {
            String detail = getMessage();
            if (detail == null) {
                detail = "";
            }
            String cmd = activeCommandSummary == null ? null : activeCommandSummary.get();
            String msg = composeStatusLine(cmd == null ? "" : cmd, detail);
            StringBuilder sb = new StringBuilder(96 + msg.length() * 2);
            sb.append("{\"message\":\"").append(escapeJson(msg)).append("\"");
            String analyzer = analyzerTitle(cmd, msg);
            if (!analyzer.isEmpty()) {
                sb.append(",\"analyzer\":\"").append(escapeJson(analyzer)).append("\"");
            }
            if (isIndeterminate()) {
                sb.append(",\"indeterminate\":true");
            } else {
                long max = getMaximum();
                long prog = getProgress();
                if (max <= 0) {
                    // Range not yet initialized — show bouncing bar rather than a misleading 0%
                    sb.append(",\"indeterminate\":true");
                } else {
                    int pct = (int) Math.min(100L, Math.max(0L, (prog * 100L) / max));
                    sb.append(",\"indeterminate\":false,\"percent\":").append(pct);
                }
            }
            if (isCancelled()) {
                sb.append(",\"cancelled\":true");
            }
            sb.append('}');
            String json = sb.toString();
            if (json.equals(lastWrittenJson)) {
                return;
            }
            lastWrittenJson = json;
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            Path target = progressFile.toPath();
            Path parent = target.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = target.resolveSibling(progressFile.getName() + ".tmp");
            Files.write(tmp, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception ignored) {
            // best-effort progress for UI
        }
    }

    private static String composeStatusLine(String task, String detail) {
        String d = detail.trim();
        String t = task == null ? "" : task.trim();
        if (t.isEmpty()) {
            return d;
        }
        if (d.isEmpty() || "Analyzing...".equalsIgnoreCase(d) || "Waiting for auto-analysis...".equalsIgnoreCase(d)) {
            return t;
        }
        if (d.contains(t)) {
            return d;
        }
        return t + " \u2014 " + d;
    }

    private static String analyzerTitle(String cmd, String composedMessage) {
        if (cmd != null && !cmd.isBlank()) {
            String c = cmd.trim();
            int sep = c.indexOf('\u2014');
            if (sep > 0) {
                return c.substring(0, sep).trim();
            }
            sep = c.indexOf(" - ");
            if (sep > 0) {
                return c.substring(0, sep).trim();
            }
            if (c.length() <= 64) {
                return c;
            }
            return c.substring(0, 61).trim() + "...";
        }
        String m = composedMessage == null ? "" : composedMessage.trim();
        if (m.length() > 64) {
            return m.substring(0, 61).trim() + "...";
        }
        return m;
    }

    private static String escapeJson(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    b.append("\\\\");
                    break;
                case '"':
                    b.append("\\\"");
                    break;
                case '\n':
                    b.append("\\n");
                    break;
                case '\r':
                    b.append("\\r");
                    break;
                case '\t':
                    b.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                    break;
            }
        }
        return b.toString();
    }

    public void clearFile() {
        lastWrittenJson = "";
        try {
            if (progressFile.isFile() && !progressFile.delete()) {
                progressFile.deleteOnExit();
            }
            Path tmp = progressFile.toPath().resolveSibling(progressFile.getName() + ".tmp");
            Files.deleteIfExists(tmp);
        } catch (Exception ignored) {
        }
    }
}
