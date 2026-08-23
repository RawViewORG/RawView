package io.rawview.ghidra;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Locale;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.base.project.GhidraProject;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Py4J entry-point object: import/analyze binaries and answer listing/decompiler queries.
 */
@SuppressWarnings("unused")
public class GhidraBridge {

    private final String projectBaseDir;
    private GhidraProject ghidraProject;
    private Program program;
    private DecompInterface decompiler;
    private final DecompileOptions decompileOptions = new DecompileOptions();
    /** Folder name under {@link #projectBaseDir} for the active Ghidra project (e.g. {@code rawview_…}). */
    private String currentProjectName;
    /** Absolute path of the binary last passed to {@link #openFile}; empty after {@link #openSavedProject}. */
    private String lastOpenedBinaryPath = "";
    /**
     * Set after a successful {@link #openFile} until the first {@link #flushProgramToDisk} finishes a
     * {@link GhidraProject#saveAs}. {@code importProgram} can leave a program without a real project file
     * on disk; {@link DomainFile#canSave()} may still be true, so we do not rely on it alone.
     */
    private boolean needsInitialProjectSaveAs;
    /**
     * Decompiler output cache keyed by {@code entryPoint@modificationNumber}. Ghidra bumps the program's
     * modification number on every database change, so any rename/comment/signature edit invalidates the
     * whole cache instead of serving stale C. Bounded LRU; decompiling a large function costs seconds.
     */
    private final Map<String, String> decompileCache = new LinkedHashMap<>(32, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > DECOMPILE_CACHE_ENTRIES;
        }
    };
    private static final int DECOMPILE_CACHE_ENTRIES = 64;
    /** Default decompiler budget per function, in seconds. */
    private static final int DECOMPILE_TIMEOUT_S = 120;
    /**
     * Monitor of the analysis run in flight, so {@link #cancelAnalysis()} can stop it. Volatile and read
     * from an unsynchronized method: {@link #runAutoAnalysis()} holds the monitor lock for its whole run.
     */
    private volatile AnalysisProgressMonitor activeAnalysisMonitor;

    public GhidraBridge(String projectBaseDir) {
        this.projectBaseDir = projectBaseDir;
    }

    /** Health check from Python. */
    public String ping() {
        return "pong";
    }

    public synchronized String openFile(String path) throws Exception {
        closeCurrentProgramAndProject();
        File bin = new File(path);
        if (!bin.isFile()) {
            throw new IllegalArgumentException("Not a file: " + path);
        }
        String projectName = "rawview_" + System.currentTimeMillis();
        ensureProjectBaseDir();
        ghidraProject = GhidraProject.createProject(projectBaseDir, projectName, false);
        try {
            program = ghidraProject.importProgram(bin);
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        if (program == null) {
            throw new IllegalStateException("importProgram returned null");
        }
        attachDecompiler();
        currentProjectName = projectName;
        lastOpenedBinaryPath = bin.getAbsolutePath();
        needsInitialProjectSaveAs = true;
        return program.getName();
    }

    /**
     * Opens an existing on-disk Ghidra project (e.g. restored from a RawView RE session archive).
     *
     * @param projectsParentDir same semantics as {@link GhidraProject#createProject} first arg
     * @param projectFolderName directory name of the project under that parent
     * @param programFolderPath folder path inside the project (usually {@code "/"})
     * @param programDomainName domain file name of the program (see {@link #getReSessionMetaJson})
     */
    public synchronized String openSavedProject(String projectsParentDir, String projectFolderName,
            String programFolderPath, String programDomainName) throws Exception {
        closeCurrentProgramAndProject();
        try {
            ghidraProject = GhidraProject.openProject(projectsParentDir, projectFolderName, false);
        } catch (Exception e) {
            throw new IOException("openProject failed: " + e.getMessage(), e);
        }
        String folder = programFolderPath == null || programFolderPath.isEmpty() ? "/" : programFolderPath;
        program = null;
        IOException lastIo = null;
        for (String tryFolder : new String[] {folder, "/".equals(folder) ? "" : null}) {
            if (tryFolder == null) {
                continue;
            }
            try {
                program = ghidraProject.openProgram(tryFolder, programDomainName, false);
                lastIo = null;
                break;
            } catch (IOException e) {
                lastIo = e;
            }
        }
        if (program == null) {
            if (lastIo != null) {
                throw lastIo;
            }
            throw new IllegalStateException("openProgram returned null");
        }
        attachDecompiler();
        currentProjectName = projectFolderName;
        lastOpenedBinaryPath = "";
        needsInitialProjectSaveAs = false;
        return program.getName();
    }

    /** Checkpoint + save so the project folder on disk is safe to copy (RE session export). */
    public synchronized void flushProgramToDisk() throws Exception {
        ensureProgram();
        if (ghidraProject == null) {
            return;
        }
        ghidraProject.checkPoint(program);
        /*
         * importProgram() can leave a Program whose DomainFile has no on-disk location yet;
         * GhidraProject.save() then throws ReadOnlyException ("Location does not exist for a save
         * operation!"). Some Ghidra builds report canSave()==true anyway, so after openFile we always
         * saveAs once, then use save() / canSave checks thereafter.
         */
        if (needsInitialProjectSaveAs) {
            ghidraProject.saveAs(program, "/", safeProgramDomainName(program), true);
            needsInitialProjectSaveAs = false;
            return;
        }
        DomainFile df = program.getDomainFile();
        if (df == null || !df.canSave()) {
            ghidraProject.saveAs(program, "/", safeProgramDomainName(program), true);
            return;
        }
        try {
            ghidraProject.save(program);
        } catch (Exception e) {
            if (isMissingDomainSaveLocation(e)) {
                ghidraProject.saveAs(program, "/", safeProgramDomainName(program), true);
            } else {
                throw e;
            }
        }
    }

    /** Sanitized name for {@link GhidraProject#saveAs} under the project root folder. */
    private static String safeProgramDomainName(Program p) {
        String n = p.getName();
        if (n == null) {
            n = "";
        }
        n = n.trim();
        if (n.isEmpty()) {
            n = "program";
        }
        StringBuilder sb = new StringBuilder(n.length());
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            if (c <= ' ' || c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"'
                    || c == '<' || c == '>' || c == '|') {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        String out = sb.toString();
        if (out.length() > 200) {
            out = out.substring(0, 200);
        }
        return out;
    }

    private static boolean isMissingDomainSaveLocation(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            String msg = t.getMessage();
            if (msg != null && msg.contains("Location does not exist")) {
                return true;
            }
        }
        return false;
    }

    /** JSON for Python RE session pack: project folder, domain path, original binary path, Ghidra parent dir. */
    public synchronized String getReSessionMetaJson() throws Exception {
        if (program == null || currentProjectName == null || currentProjectName.isEmpty()) {
            return "{}";
        }
        DomainFile df = program.getDomainFile();
        ghidra.framework.model.DomainFolder parent = df.getParent();
        String folderPath = "/";
        if (parent != null) {
            String pn = parent.getPathname();
            if (pn != null && !pn.isEmpty()) {
                folderPath = pn.startsWith("/") ? pn : "/" + pn;
            }
        }
        /*
         * Python must zip the real on-disk project directory. Ghidra may not materialize
         * projectBaseDir/projectName until saveAs; ProjectLocator is authoritative once the
         * project exists (and matches what flushProgramToDisk wrote).
         */
        String projectFolderOnDisk = "";
        try {
            if (ghidraProject != null) {
                Project pj = ghidraProject.getProject();
                if (pj != null) {
                    ProjectLocator loc = pj.getProjectLocator();
                    if (loc != null) {
                        File pd = loc.getProjectDir();
                        if (pd != null) {
                            projectFolderOnDisk = pd.getAbsolutePath();
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        if (projectFolderOnDisk.isEmpty()) {
            projectFolderOnDisk = new File(projectBaseDir, currentProjectName).getAbsolutePath();
        }
        return "{\"projectName\":\"" + escapeJson(currentProjectName) + "\",\"projectsParent\":\""
                + escapeJson(projectBaseDir) + "\",\"projectFolderOnDisk\":\""
                + escapeJson(projectFolderOnDisk) + "\",\"programFolder\":\"" + escapeJson(folderPath)
                + "\",\"programDomainName\":\"" + escapeJson(df.getName()) + "\",\"originalBinary\":\""
                + escapeJson(lastOpenedBinaryPath != null ? lastOpenedBinaryPath : "") + "\"}";
    }

    /**
     * Runs Ghidra auto-analysis to completion, returning {@code {"ok":…,"cancelled":…,"seconds":…}}.
     *
     * <p>The monitor is cancellable and published in {@link #activeAnalysisMonitor} so
     * {@link #cancelAnalysis()} can stop a run that is taking too long; a cancelled run keeps whatever
     * analysis completed but does not mark the program as analyzed, so it can be resumed later.
     */
    public synchronized String runAutoAnalysis() throws Exception {
        ensureProgram();
        /*
         * GhidraProject.importProgram() leaves an open "Batch Processing" transaction; commit it
         * before analysis (Headless uses ProgramLoader + DefaultProject instead).
         */
        if (ghidraProject != null) {
            ghidraProject.checkPoint(program);
        }
        /*
         * Mirror HeadlessAnalyzer.analyzeProgram(): explicit "Analysis" transaction, then dispose
         * the manager (GhidraProject.analyze() does not do either).
         */
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();
        int txId = program.startTransaction("Analysis");
        File progressFile = new File(projectBaseDir, ".rawview_analysis_progress.json");
        AnalysisProgressMonitor analysisMonitor =
                new AnalysisProgressMonitor(progressFile, () -> readActiveCommandDetail(mgr));
        activeAnalysisMonitor = analysisMonitor;
        long startedAt = System.currentTimeMillis();
        boolean cancelled = false;
        try {
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(analysisMonitor);
            cancelled = analysisMonitor.isCancelled();
            if (!cancelled) {
                GhidraProgramUtilities.markProgramAnalyzed(program);
            }
        } finally {
            activeAnalysisMonitor = null;
            program.endTransaction(txId, true);
            analysisMonitor.clearFile();
            decompileCache.clear();
        }
        mgr.dispose();
        long seconds = (System.currentTimeMillis() - startedAt) / 1000L;
        return "{\"ok\":true,\"cancelled\":" + cancelled + ",\"seconds\":" + seconds + ",\"functions\":"
                + program.getFunctionManager().getFunctionCount() + "}";
    }

    /**
     * Asks the in-flight auto-analysis to stop at the next cancellation check.
     *
     * <p>Deliberately not {@code synchronized}: {@link #runAutoAnalysis()} holds this object's monitor for
     * its entire run, so a synchronized cancel could never be delivered while analysis is what needs
     * cancelling. It only sets a flag on the monitor, which is safe to touch from another thread.
     */
    public String cancelAnalysis() {
        AnalysisProgressMonitor m = activeAnalysisMonitor;
        if (m == null) {
            return "{\"ok\":false,\"reason\":\"no_analysis_running\"}";
        }
        m.cancel();
        return "{\"ok\":true,\"cancelling\":true}";
    }

    /** True while an auto-analysis run is in flight; safe to call during analysis. */
    public boolean isAnalysisRunning() {
        return activeAnalysisMonitor != null;
    }

    /**
     * Reads the active {@link BackgroundCommand}'s {@code getName()} / {@code getStatusMsg()} via the same
     * private fields Ghidra's UI uses. {@code getStatusMsg()} is where many analyzers put the current function
     * or address. Invoked only from {@link AnalysisProgressMonitor#flush} (Ghidra-driven), not on a timer.
     */
    private static String readActiveCommandDetail(AutoAnalysisManager mgr) {
        try {
            Field af = AutoAnalysisManager.class.getDeclaredField("activeTask");
            af.setAccessible(true);
            Object wrapper = af.get(mgr);
            if (wrapper == null) {
                return null;
            }
            Field tf = wrapper.getClass().getDeclaredField("task");
            tf.setAccessible(true);
            Object cmd = tf.get(wrapper);
            if (!(cmd instanceof BackgroundCommand)) {
                return null;
            }
            BackgroundCommand<?> bc = (BackgroundCommand<?>) cmd;
            String name = bc.getName();
            if (name == null) {
                name = "";
            }
            String st = bc.getStatusMsg();
            if (st != null) {
                st = st.trim();
            } else {
                st = "";
            }
            if (!st.isEmpty()) {
                if (!name.isEmpty() && !st.contains(name)) {
                    return name + " \u2014 " + st;
                }
                return st;
            }
            return name.isEmpty() ? null : name;
        } catch (ReflectiveOperationException | ClassCastException ignored) {
        }
        return null;
    }

    /** JSON array of objects {@code {name,address}} for stable Py4J transfer. */
    public synchronized String listFunctionsJson() throws Exception {
        ensureProgram();
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        while (it.hasNext()) {
            Function f = it.next();
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append("{\"name\":\"").append(escapeJson(f.getName())).append("\",");
            sb.append("\"address\":\"").append(escapeJson(f.getEntryPoint().toString())).append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }

    /**
     * Page of the function list as {@code {total,offset,count,truncated,rows:[…]}}.
     *
     * <p>Rows carry size / thunk / external flags and the current signature, and the filtering and
     * windowing happen in the JVM. {@link #listFunctionsJson()} has to marshal every function in the
     * program through Py4J as one string before the caller can drop 99% of it — which is what both the
     * agent's {@code limit} and the UI's symbol list were doing on binaries with 100k functions.
     *
     * @param offset first row to return (clamped at 0)
     * @param limit maximum rows (1..50000)
     * @param nameFilter case-insensitive substring; empty matches everything
     */
    public synchronized String listFunctionsPageJson(int offset, int limit, String nameFilter)
            throws Exception {
        ensureProgram();
        String needle = nameFilter == null ? "" : nameFilter.trim().toLowerCase(Locale.US);
        int off = Math.max(0, offset);
        int cap = Math.max(1, Math.min(limit, 50000));
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        StringBuilder rows = new StringBuilder();
        int matched = 0;
        int emitted = 0;
        while (it.hasNext()) {
            Function f = it.next();
            String name = f.getName();
            if (!needle.isEmpty() && !name.toLowerCase(Locale.US).contains(needle)) {
                continue;
            }
            matched++;
            if (matched <= off || emitted >= cap) {
                continue;
            }
            if (emitted > 0) {
                rows.append(',');
            }
            emitted++;
            rows.append("{\"name\":\"").append(escapeJson(name)).append("\",");
            rows.append("\"address\":\"").append(escapeJson(f.getEntryPoint().toString())).append("\",");
            rows.append("\"size\":").append(f.getBody() != null ? f.getBody().getNumAddresses() : 0)
                    .append(',');
            rows.append("\"is_thunk\":").append(f.isThunk()).append(',');
            rows.append("\"is_external\":").append(f.isExternal()).append(',');
            rows.append("\"signature\":\"")
                    .append(escapeJson(f.getSignature().getPrototypeString())).append("\"}");
        }
        return "{\"total\":" + matched + ",\"offset\":" + off + ",\"count\":" + emitted + ",\"truncated\":"
                + (matched > off + emitted) + ",\"rows\":[" + rows + "]}";
    }

    /**
     * Page of defined strings as {@code {total,offset,count,truncated,rows:[…]}}, filtered in the JVM.
     *
     * @param minLength drop strings shorter than this (0 keeps all)
     */
    public synchronized String getStringsPageJson(int offset, int limit, int minLength) throws Exception {
        ensureProgram();
        int off = Math.max(0, offset);
        int cap = Math.max(1, Math.min(limit, 50000));
        int minLen = Math.max(0, minLength);
        DataIterator dit = program.getListing().getDefinedData(true);
        StringBuilder rows = new StringBuilder();
        int matched = 0;
        int emitted = 0;
        while (dit.hasNext()) {
            Data d = dit.next();
            if (!d.hasStringValue()) {
                continue;
            }
            String val = d.getDefaultValueRepresentation();
            if (val == null) {
                continue;
            }
            if (minLen > 0 && val.length() < minLen) {
                continue;
            }
            matched++;
            if (matched <= off || emitted >= cap) {
                continue;
            }
            if (emitted > 0) {
                rows.append(',');
            }
            emitted++;
            rows.append("{\"address\":\"").append(escapeJson(d.getAddressString(true, false))).append("\",");
            rows.append("\"value\":\"").append(escapeJson(val)).append("\",");
            rows.append("\"length\":").append(d.getLength()).append('}');
        }
        return "{\"total\":" + matched + ",\"offset\":" + off + ",\"count\":" + emitted + ",\"truncated\":"
                + (matched > off + emitted) + ",\"rows\":[" + rows + "]}";
    }

    /** Page of non-external symbols as {@code {total,offset,count,truncated,rows:[…]}}. */
    public synchronized String getSymbolsPageJson(int offset, int limit, String nameFilter)
            throws Exception {
        ensureProgram();
        String needle = nameFilter == null ? "" : nameFilter.trim().toLowerCase(Locale.US);
        int off = Math.max(0, offset);
        int cap = Math.max(1, Math.min(limit, 50000));
        SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
        StringBuilder rows = new StringBuilder();
        int matched = 0;
        int emitted = 0;
        while (it.hasNext()) {
            Symbol sym = it.next();
            if (sym.isExternal()) {
                continue;
            }
            String name = sym.getName();
            if (!needle.isEmpty() && !name.toLowerCase(Locale.US).contains(needle)) {
                continue;
            }
            matched++;
            if (matched <= off || emitted >= cap) {
                continue;
            }
            if (emitted > 0) {
                rows.append(',');
            }
            emitted++;
            rows.append("{\"name\":\"").append(escapeJson(name)).append("\",");
            rows.append("\"address\":\"").append(escapeJson(sym.getAddress().toString())).append("\",");
            rows.append("\"type\":\"").append(escapeJson(sym.getSymbolType().toString())).append("\"}");
        }
        return "{\"total\":" + matched + ",\"offset\":" + off + ",\"count\":" + emitted + ",\"truncated\":"
                + (matched > off + emitted) + ",\"rows\":[" + rows + "]}";
    }

    public synchronized String decompileFunction(String addressText) throws Exception {
        return decompileFunctionWithTimeout(addressText, DECOMPILE_TIMEOUT_S);
    }

    /**
     * Decompiles one function to C, caching the result until the program changes.
     *
     * <p>The UI re-decompiles on every navigation and the agent commonly asks for the same function
     * repeatedly while reasoning about it; a big function costs seconds each time. The cache key carries
     * the program's modification number, so any edit (rename, retype, comment) still yields fresh output.
     *
     * @param timeoutSeconds decompiler budget for this function (1..600)
     */
    public synchronized String decompileFunctionWithTimeout(String addressText, int timeoutSeconds)
            throws Exception {
        ensureProgram();
        Function f = resolveFunction(addressText);
        if (f == null) {
            return "// No function at " + addressText;
        }
        int budget = Math.max(1, Math.min(timeoutSeconds, 600));
        String key = f.getEntryPoint().toString() + "@" + program.getModificationNumber();
        String hit = decompileCache.get(key);
        if (hit != null) {
            return hit;
        }
        DecompileResults results = decompiler.decompileFunction(f, budget, TaskMonitor.DUMMY);
        if (results == null || !results.decompileCompleted()) {
            String err = results != null ? results.getErrorMessage() : "null results";
            return "// Decompile failed: " + err;
        }
        if (results.getDecompiledFunction() == null) {
            return "// No decompiled output";
        }
        String c = results.getDecompiledFunction().getC();
        decompileCache.put(key, c);
        return c;
    }

    public synchronized String getDisassembly(String addressText, int maxInstructions) throws Exception {
        ensureProgram();
        Address start = parseAddress(addressText);
        if (start == null) {
            return "Invalid address: " + addressText;
        }
        int cap = Math.max(1, Math.min(maxInstructions, 5000));
        Listing listing = program.getListing();
        StringBuilder sb = new StringBuilder();
        InstructionIterator ii = listing.getInstructions(start, true);
        int n = 0;
        while (ii.hasNext() && n < cap) {
            Instruction ins = ii.next();
            sb.append(ins.getAddressString(true, false)).append('\t').append(ins.toString()).append('\n');
            n++;
        }
        return sb.toString();
    }

    /**
     * Tab-separated hex dump for UI: {@code address TAB hex-spaces TAB ascii} per row; lines starting with
     * {@code #} are metadata / column headers. Mapped bytes only.
     *
     * @param maxBytes capped (1..65536)
     * @param bytesPerLine columns (1..64), with an extra gap after the first half when ≥ 8
     */
    public synchronized String getHexDumpText(String addressText, int maxBytes, int bytesPerLine) throws Exception {
        ensureProgram();
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return "Invalid address: " + addressText;
        }
        int bpl = Math.max(1, Math.min(bytesPerLine, 64));
        int cap = Math.max(1, Math.min(maxBytes, 65536));
        Memory mem = program.getMemory();
        byte[] data = new byte[cap];
        /*
         * Read what is actually mapped rather than all-or-nothing: a fixed 4K window straddles the end of
         * a section for any address near a block boundary, and Memory.getBytes throws for the whole range.
         */
        int got = readBytesBestEffort(mem, addr, data);
        if (got <= 0) {
            return "(no bytes read at " + addr + " - unmapped or protected?)";
        }
        StringBuilder out = new StringBuilder(Math.min(got, cap) * 5 + 128);
        out.append("# base\t").append(addr.toString()).append("\tbytes=").append(got).append("\tcolumns=").append(bpl)
                .append("\n");
        out.append("#\n");
        StringBuilder hexIdx = new StringBuilder();
        for (int c = 0; c < bpl; c++) {
            if (c == bpl / 2 && bpl >= 8) {
                hexIdx.append("  ");
            }
            hexIdx.append(String.format(Locale.US, "%02X", c));
            if (c + 1 < bpl) {
                hexIdx.append(' ');
            }
        }
        StringBuilder asciiIdx = new StringBuilder(bpl);
        for (int c = 0; c < bpl; c++) {
            int v = c % 16;
            asciiIdx.append(v < 10 ? (char) ('0' + v) : (char) ('A' + v - 10));
        }
        out.append("# offset\t").append(hexIdx).append("\t").append(asciiIdx).append("\n");
        for (int off = 0; off < got; off += bpl) {
            int n = Math.min(bpl, got - off);
            Address rowAddr = addr.addWrap(off);
            out.append(rowAddr.toString()).append('\t');
            for (int i = 0; i < n; i++) {
                if (i == bpl / 2 && bpl >= 8) {
                    out.append("  ");
                }
                int b = data[off + i] & 0xff;
                out.append(String.format(Locale.US, "%02X", b));
                if (i + 1 < n) {
                    out.append(' ');
                }
            }
            for (int i = n; i < bpl; i++) {
                if (i == bpl / 2 && bpl >= 8) {
                    out.append("  ");
                }
                out.append("  ");
                if (i + 1 < bpl) {
                    out.append(' ');
                }
            }
            out.append('\t');
            for (int i = 0; i < n; i++) {
                int b = data[off + i] & 0xff;
                char ch = (b >= 32 && b < 127) ? (char) b : '.';
                out.append(ch);
            }
            for (int i = n; i < bpl; i++) {
                out.append(' ');
            }
            out.append('\n');
        }
        return out.toString();
    }

    /** Move {@code addressText} forward/back in the default space (wrap). Empty string if invalid. */
    public synchronized String advanceProgramAddress(String addressText, long deltaBytes) throws Exception {
        ensureProgram();
        Address a = parseAddress(addressText);
        if (a == null) {
            return "";
        }
        Address n = a.addWrap(deltaBytes);
        return n != null ? n.toString() : "";
    }

    /** JSON array of {@code {address,value}} for defined string data. */
    public synchronized String getStringsJson() throws Exception {
        ensureProgram();
        Listing listing = program.getListing();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        DataIterator dit = listing.getDefinedData(true);
        while (dit.hasNext()) {
            Data d = dit.next();
            if (!d.hasStringValue()) {
                continue;
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            String val = d.getDefaultValueRepresentation();
            sb.append("{\"address\":\"").append(escapeJson(d.getAddressString(true, false))).append("\",");
            sb.append("\"value\":\"").append(escapeJson(val)).append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }

    /** JSON array of {@code {library,name,address}} for external symbols. */
    public synchronized String getImportsJson() throws Exception {
        ensureProgram();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!s.isExternal()) {
                continue;
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            String lib = s.getParentNamespace() != null ? s.getParentNamespace().getName() : "";
            sb.append("{\"library\":\"").append(escapeJson(lib)).append("\",");
            sb.append("\"name\":\"").append(escapeJson(s.getName())).append("\",");
            sb.append("\"address\":\"").append(escapeJson(s.getAddress().toString())).append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }

    /**
     * JSON array of {@code {name,address,type}} for the program's exported symbols.
     *
     * <p>Exports are Ghidra's external entry points — what a PE's export directory or an ELF's dynamic
     * symbol table publishes. The previous implementation listed the first 2000 primary symbols of any
     * kind, so the Exports pane filled up with string labels and section headers instead.
     */
    public synchronized String getExportsJson() throws Exception {
        ensureProgram();
        SymbolTable st = program.getSymbolTable();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        AddressIterator it = st.getExternalEntryPointIterator();
        while (it != null && it.hasNext() && count < 5000) {
            Address a = it.next();
            if (a == null) {
                continue;
            }
            Symbol sym = st.getPrimarySymbol(a);
            Function fn = program.getFunctionManager().getFunctionAt(a);
            String name = sym != null ? sym.getName() : (fn != null ? fn.getName() : "");
            if (name.isEmpty()) {
                continue;
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            count++;
            sb.append("{\"name\":\"").append(escapeJson(name)).append("\",");
            sb.append("\"address\":\"").append(escapeJson(a.toString())).append("\",");
            sb.append("\"type\":\"").append(fn != null ? "function" : "data").append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }

    /**
     * JSON array of {@code {name,address}} for defined non-external symbols (includes labels;
     * broader than {@link #getExportsJson()} which keeps primary symbols only). Capped for UI transfer.
     */
    public synchronized String getSymbolsJson() throws Exception {
        ensureProgram();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        SymbolIterator it = program.getSymbolTable().getAllSymbols(true);
        int cap = 0;
        while (it.hasNext() && cap < 5000) {
            Symbol s = it.next();
            if (s.isExternal()) {
                continue;
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            cap++;
            sb.append("{\"name\":\"").append(escapeJson(s.getName())).append("\",");
            sb.append("\"address\":\"").append(escapeJson(s.getAddress().toString())).append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }

    /**
     * JSON array of {@code {address,name,type}} for the program's execution entry points.
     *
     * <p>Prefers loader-named entries ({@code entry}, {@code _start}, {@code main}, {@code DllMain}, …)
     * among the external entry points, then any external entry point that is a function, and finally the
     * image base. The previous implementation only looked for a primary symbol exactly at the image base,
     * which for an ordinary ELF or PE is a header address with no symbol — so this returned {@code []}
     * for most binaries, including for the agent's orientation step.
     */
    public synchronized String getEntryPointsJson() throws Exception {
        ensureProgram();
        SymbolTable st = program.getSymbolTable();
        FunctionManager fm = program.getFunctionManager();
        List<String> named = new ArrayList<>();
        List<String> functions = new ArrayList<>();
        AddressIterator it = st.getExternalEntryPointIterator();
        int scanned = 0;
        while (it != null && it.hasNext() && scanned < 20000) {
            Address a = it.next();
            scanned++;
            if (a == null) {
                continue;
            }
            Symbol sym = st.getPrimarySymbol(a);
            Function fn = fm.getFunctionAt(a);
            String name = sym != null ? sym.getName() : (fn != null ? fn.getName() : "");
            if (name.isEmpty()) {
                continue;
            }
            String row = "{\"address\":\"" + escapeJson(a.toString()) + "\",\"name\":\"" + escapeJson(name)
                    + "\",\"type\":\"" + (fn != null ? "function" : "data") + "\"}";
            if (isEntryPointName(name)) {
                named.add(row);
            } else if (fn != null) {
                functions.add(row);
            }
        }
        List<String> rows = !named.isEmpty() ? named : functions;
        if (rows.size() > 256) {
            rows = rows.subList(0, 256);
        }
        if (rows.isEmpty()) {
            Address base = program.getImageBase();
            if (base != null) {
                Symbol sym = st.getPrimarySymbol(base);
                rows = new ArrayList<>();
                rows.add("{\"address\":\"" + escapeJson(base.toString()) + "\",\"name\":\""
                        + escapeJson(sym != null ? sym.getName() : "image_base") + "\",\"type\":\"data\"}");
            }
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(rows.get(i));
        }
        return sb.append(']').toString();
    }

    /** Names loaders give to the place execution starts, across PE/ELF/Mach-O. */
    private static boolean isEntryPointName(String name) {
        String n = name.toLowerCase(Locale.US);
        switch (n) {
            case "entry":
            case "_entry":
            case "start":
            case "_start":
            case "main":
            case "_main":
            case "wmain":
            case "winmain":
            case "wwinmain":
            case "dllmain":
            case "_dllmaincrtstartup":
            case "dllmaincrtstartup":
            case "maincrtstartup":
            case "wmaincrtstartup":
            case "wwinmaincrtstartup":
            case "winmaincrtstartup":
                return true;
            default:
                return false;
        }
    }

    /** JSON array of {@code {fromAddress,toAddress,type}} references to {@code addressText}. */
    public synchronized String getXrefsToJson(String addressText) throws Exception {
        ensureProgram();
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return "[]";
        }
        ReferenceManager rm = program.getReferenceManager();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        ReferenceIterator toIt = rm.getReferencesTo(addr);
        while (toIt != null && toIt.hasNext()) {
            Reference ref = toIt.next();
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append("{\"fromAddress\":\"").append(escapeJson(ref.getFromAddress().toString())).append("\",");
            sb.append("\"toAddress\":\"").append(escapeJson(ref.getToAddress().toString())).append("\",");
            sb.append("\"type\":\"").append(escapeJson(ref.getReferenceType().toString())).append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }

    /** JSON array of {@code {fromAddress,toAddress,type}} references from {@code addressText}. */
    public synchronized String getXrefsFromJson(String addressText) throws Exception {
        ensureProgram();
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return "[]";
        }
        ReferenceManager rm = program.getReferenceManager();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        Reference[] fromRefs = rm.getReferencesFrom(addr);
        if (fromRefs != null) {
            for (Reference ref : fromRefs) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append("{\"fromAddress\":\"").append(escapeJson(ref.getFromAddress().toString())).append("\",");
                sb.append("\"toAddress\":\"").append(escapeJson(ref.getToAddress().toString())).append("\",");
                sb.append("\"type\":\"").append(escapeJson(ref.getReferenceType().toString())).append("\"}");
            }
        }
        sb.append(']');
        return sb.toString();
    }

    /**
     * Renames the function at {@code addressText}; falls back to the primary symbol (label / data) there,
     * so the agent can also name globals and jump tables rather than failing with {@code no_function}.
     */
    public synchronized String renameFunction(String addressText, String newName) throws Exception {
        ensureProgram();
        String name = newName == null ? "" : newName.trim();
        if (name.isEmpty()) {
            return "{\"error\":\"empty_name\"}";
        }
        Function f = resolveFunction(addressText);
        if (f != null) {
            String previous = f.getName();
            return inTransaction("Rename function", () -> {
                f.setName(name, SourceType.USER_DEFINED);
                return "{\"ok\":true,\"kind\":\"function\",\"address\":\""
                        + escapeJson(f.getEntryPoint().toString()) + "\",\"name\":\"" + escapeJson(name)
                        + "\",\"previous_name\":\"" + escapeJson(previous) + "\"}";
            });
        }
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return "{\"error\":\"invalid_address\"}";
        }
        Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
        if (sym == null) {
            return "{\"error\":\"no_function_at_address\",\"hint\":\"no function and no symbol at "
                    + escapeJson(addr.toString()) + "\"}";
        }
        String previous = sym.getName();
        return inTransaction("Rename symbol", () -> {
            sym.setName(name, SourceType.USER_DEFINED);
            return "{\"ok\":true,\"kind\":\"label\",\"address\":\"" + escapeJson(addr.toString())
                    + "\",\"name\":\"" + escapeJson(name) + "\",\"previous_name\":\""
                    + escapeJson(previous) + "\"}";
        });
    }

    public synchronized String setComment(String addressText, String text) throws Exception {
        return setCommentOfType(addressText, text, "EOL");
    }

    /**
     * Sets one comment on an address.
     *
     * @param commentType {@code EOL}, {@code PRE}, {@code POST}, {@code PLATE} or {@code REPEATABLE}
     *     (case-insensitive); {@code PLATE} is the block comment shown above a function.
     */
    public synchronized String setCommentOfType(String addressText, String text, String commentType)
            throws Exception {
        ensureProgram();
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return "{\"error\":\"invalid_address\"}";
        }
        CommentType type;
        switch (commentType == null ? "EOL" : commentType.trim().toUpperCase(Locale.US)) {
            case "PRE":
                type = CommentType.PRE;
                break;
            case "POST":
                type = CommentType.POST;
                break;
            case "PLATE":
                type = CommentType.PLATE;
                break;
            case "REPEATABLE":
                type = CommentType.REPEATABLE;
                break;
            case "":
            case "EOL":
                type = CommentType.EOL;
                break;
            default:
                return "{\"error\":\"invalid_comment_type\",\"hint\":\"one of EOL, PRE, POST, PLATE, REPEATABLE\"}";
        }
        return inTransaction("Set comment", () -> {
            program.getListing().setComment(addr, type, text);
            return "{\"ok\":true,\"address\":\"" + escapeJson(addr.toString()) + "\",\"type\":\""
                    + escapeJson(type.name()) + "\"}";
        });
    }

    /** Byte-pattern search with the default match limit; see {@link #searchBytesLimitJson}. */
    public synchronized String searchBytesJson(String hexPattern) throws Exception {
        return searchBytesLimitJson(hexPattern, 64);
    }

    /**
     * Searches program memory for a byte pattern and returns every match, not just the first.
     *
     * <p>The pattern is hex bytes, with or without separators ({@code "48 89 E5"} or {@code "4889e5"}), and
     * {@code ??} / {@code ..} stand for "any byte" — the wildcard form signatures are normally written in.
     * Each match reports the containing function when there is one, so a hit is directly actionable.
     *
     * @param maxMatches match cap (1..1000)
     */
    public synchronized String searchBytesLimitJson(String hexPattern, int maxMatches) throws Exception {
        ensureProgram();
        byte[] pat;
        byte[] mask;
        try {
            byte[][] parsed = parseBytePattern(hexPattern);
            pat = parsed[0];
            mask = parsed[1];
        } catch (IllegalArgumentException e) {
            return "{\"error\":\"invalid_pattern\",\"message\":\"" + escapeJson(e.getMessage())
                    + "\",\"matches\":[]}";
        }
        if (pat.length == 0) {
            return "{\"error\":\"empty_pattern\",\"matches\":[]}";
        }
        int cap = Math.max(1, Math.min(maxMatches, 1000));
        boolean masked = false;
        for (byte m : mask) {
            if (m != (byte) 0xff) {
                masked = true;
                break;
            }
        }
        Memory mem = program.getMemory();
        FunctionManager fm = program.getFunctionManager();
        StringBuilder sb = new StringBuilder("{\"matches\":[");
        int found = 0;
        boolean truncated = false;
        Address cursor = program.getMinAddress();
        while (cursor != null && found < cap) {
            Address hit = mem.findBytes(cursor, pat, masked ? mask : null, true, TaskMonitor.DUMMY);
            if (hit == null) {
                break;
            }
            if (found > 0) {
                sb.append(',');
            }
            found++;
            sb.append("{\"address\":\"").append(escapeJson(hit.toString())).append('"');
            Function fn = fm.getFunctionContaining(hit);
            if (fn != null) {
                sb.append(",\"function\":\"").append(escapeJson(fn.getName())).append('"');
                sb.append(",\"function_address\":\"")
                        .append(escapeJson(fn.getEntryPoint().toString())).append('"');
            }
            MemoryBlock block = mem.getBlock(hit);
            if (block != null) {
                sb.append(",\"block\":\"").append(escapeJson(block.getName())).append('"');
            }
            sb.append('}');
            try {
                cursor = hit.addNoWrap(1);
            } catch (Exception e) {
                cursor = null;
            }
            if (found >= cap) {
                truncated = cursor != null && mem.findBytes(cursor, pat, masked ? mask : null, true,
                        TaskMonitor.DUMMY) != null;
            }
        }
        sb.append("],\"count\":").append(found).append(",\"truncated\":").append(truncated);
        sb.append(",\"wildcards\":").append(masked).append('}');
        return sb.toString();
    }

    /**
     * Parses a byte pattern into {@code {bytes, mask}}. Accepts whitespace- or comma-separated hex pairs,
     * an unseparated hex run, a {@code 0x}/{@code \\x} prefix per byte, and {@code ??} / {@code ..} / {@code *}
     * wildcards (mask byte 0).
     */
    private static byte[][] parseBytePattern(String pattern) {
        String p = pattern == null ? "" : pattern.trim();
        if (p.isEmpty()) {
            return new byte[][] {new byte[0], new byte[0]};
        }
        p = p.replace("\\x", " ").replace("0x", " ").replace("0X", " ").replace(",", " ");
        List<Byte> bytes = new ArrayList<>();
        List<Byte> mask = new ArrayList<>();
        String[] tokens = p.trim().split("\\s+");
        for (String token : tokens) {
            if (token.isEmpty()) {
                continue;
            }
            if (isWildcardToken(token)) {
                bytes.add((byte) 0);
                mask.add((byte) 0);
                continue;
            }
            if (token.length() % 2 != 0) {
                throw new IllegalArgumentException(
                        "hex token must have an even number of digits: '" + token + "'");
            }
            for (int i = 0; i < token.length(); i += 2) {
                String pair = token.substring(i, i + 2);
                if (isWildcardToken(pair)) {
                    bytes.add((byte) 0);
                    mask.add((byte) 0);
                    continue;
                }
                int v;
                try {
                    v = Integer.parseInt(pair, 16);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("not a hex byte: '" + pair + "'");
                }
                bytes.add((byte) v);
                mask.add((byte) 0xff);
            }
        }
        byte[] outBytes = new byte[bytes.size()];
        byte[] outMask = new byte[mask.size()];
        for (int i = 0; i < outBytes.length; i++) {
            outBytes[i] = bytes.get(i);
            outMask[i] = mask.get(i);
        }
        return new byte[][] {outBytes, outMask};
    }

    private static boolean isWildcardToken(String token) {
        return "??".equals(token) || "?".equals(token) || "..".equals(token) || ".".equals(token)
                || "*".equals(token) || "xx".equalsIgnoreCase(token);
    }

    /** JSON object describing bytes or instruction at address (MVP). */
    public synchronized String getDataAtJson(String addressText) throws Exception {
        ensureProgram();
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return "{\"error\":\"invalid_address\"}";
        }
        Listing listing = program.getListing();
        Data d = listing.getDefinedDataAt(addr);
        if (d != null) {
            return "{\"kind\":\"data\",\"address\":\"" + escapeJson(addr.toString()) + "\",\"representation\":\""
                    + escapeJson(d.getDefaultValueRepresentation()) + "\"}";
        }
        Instruction ins = listing.getInstructionAt(addr);
        if (ins != null) {
            return "{\"kind\":\"instruction\",\"address\":\"" + escapeJson(addr.toString()) + "\",\"mnemonic\":\""
                    + escapeJson(ins.getMnemonicString()) + "\"}";
        }
        return "{\"kind\":\"unknown\",\"address\":\"" + escapeJson(addr.toString()) + "\"}";
    }

    /** Real CFG using BasicBlockModel — returns nodes (basic blocks) + edges (control flow) as JSON. */
    public synchronized String getControlFlowGraphJson(String addressText) throws Exception {
        ensureProgram();
        Function f = resolveFunction(addressText);
        if (f == null) {
            return "{\"error\":\"no_function\",\"nodes\":[],\"edges\":[]}";
        }

        BasicBlockModel bbModel = new BasicBlockModel(program);
        Listing listing = program.getListing();

        // Collect all basic blocks within this function's address set
        List<CodeBlock> blocks = new ArrayList<>();
        Set<String> blockIds = new HashSet<>();
        CodeBlockIterator blockIt = bbModel.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
        final int MAX_BLOCKS = 256;
        while (blockIt.hasNext() && blocks.size() < MAX_BLOCKS) {
            CodeBlock block = blockIt.next();
            String id = block.getMinAddress().toString();
            if (blockIds.contains(id)) {
                continue;
            }
            blockIds.add(id);
            blocks.add(block);
        }
        boolean truncated = blocks.size() >= MAX_BLOCKS;

        StringBuilder sb = new StringBuilder();
        sb.append("{\"function\":\"").append(escapeJson(f.getName()))
          .append("\",\"entry\":\"").append(escapeJson(f.getEntryPoint().toString()))
          .append("\",\"truncated\":").append(truncated)
          .append(",\"nodes\":[");

        final int MAX_INSNS_PER_BLOCK = 20;

        for (int i = 0; i < blocks.size(); i++) {
            CodeBlock block = blocks.get(i);
            if (i > 0) {
                sb.append(',');
            }

            // Count total instructions (for the "+ N more" indicator)
            int totalInsns = 0;
            InstructionIterator countIt = listing.getInstructions(block, true);
            while (countIt.hasNext()) {
                countIt.next();
                totalInsns++;
            }

            sb.append("{\"id\":\"").append(escapeJson(block.getMinAddress().toString())).append('"')
              .append(",\"start\":\"").append(escapeJson(block.getMinAddress().toString())).append('"')
              .append(",\"end\":\"").append(escapeJson(block.getMaxAddress().toString())).append('"')
              .append(",\"total_insns\":").append(totalInsns)
              .append(",\"instructions\":[");

            InstructionIterator insIt = listing.getInstructions(block, true);
            boolean firstIns = true;
            int insnCount = 0;
            while (insIt.hasNext() && insnCount < MAX_INSNS_PER_BLOCK) {
                Instruction ins = insIt.next();
                if (!firstIns) {
                    sb.append(',');
                }
                firstIns = false;
                sb.append("{\"addr\":\"").append(escapeJson(ins.getAddressString(false, false))).append('"')
                  .append(",\"text\":\"").append(escapeJson(ins.toString())).append("\"}");
                insnCount++;
            }
            sb.append("]}");
        }

        sb.append("],\"edges\":[");

        // Edges: destinations within function body only; skip call edges
        Set<String> edgeSet = new HashSet<>();
        boolean firstEdge = true;
        for (CodeBlock block : blocks) {
            CodeBlockReferenceIterator destIt = null;
            try {
                destIt = block.getDestinations(TaskMonitor.DUMMY);
            } catch (Exception ignored) {
                continue;
            }
            while (destIt != null && destIt.hasNext()) {
                CodeBlockReference ref = destIt.next();
                Address destAddr = ref.getDestinationAddress();
                if (destAddr == null) {
                    continue;
                }
                String destId = destAddr.toString();
                if (!blockIds.contains(destId)) {
                    continue;
                }
                if (ref.getFlowType() != null && ref.getFlowType().isCall()) {
                    continue;
                }
                String edgeKey = block.getMinAddress().toString() + "->" + destId;
                if (!edgeSet.add(edgeKey)) {
                    continue;
                }
                String flowType = ref.getFlowType() != null ? ref.getFlowType().toString() : "FLOW";
                if (!firstEdge) {
                    sb.append(',');
                }
                firstEdge = false;
                sb.append("{\"from\":\"").append(escapeJson(block.getMinAddress().toString())).append('"')
                  .append(",\"to\":\"").append(escapeJson(destId)).append('"')
                  .append(",\"type\":\"").append(escapeJson(flowType)).append("\"}");
            }
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Renames a local or parameter of one function.
     *
     * <p>Tries the decompiler's view first ({@link HighSymbol} via {@link HighFunctionDBUtil}), which is
     * what the user actually sees in the pseudocode pane and covers stack/register locals that have no
     * listing-level variable yet. Falls back to the listing's own {@link Variable} objects.
     */
    public synchronized String renameVariable(String functionAddress, String oldName, String newName)
            throws Exception {
        ensureProgram();
        String from = oldName == null ? "" : oldName.trim();
        String to = newName == null ? "" : newName.trim();
        if (from.isEmpty() || to.isEmpty()) {
            return "{\"error\":\"empty_name\"}";
        }
        Function f = resolveFunction(functionAddress);
        if (f == null) {
            return "{\"error\":\"no_function_at_address\"}";
        }
        DecompileResults results = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT_S, TaskMonitor.DUMMY);
        HighFunction high = results != null ? results.getHighFunction() : null;
        if (high != null) {
            HighSymbol match = null;
            LocalSymbolMap locals = high.getLocalSymbolMap();
            Iterator<HighSymbol> it = locals.getSymbols();
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                if (from.equals(sym.getName())) {
                    match = sym;
                    break;
                }
            }
            if (match == null) {
                for (int i = 0; i < locals.getNumParams(); i++) {
                    HighSymbol psym = locals.getParamSymbol(i);
                    if (psym != null && from.equals(psym.getName())) {
                        match = psym;
                        break;
                    }
                }
            }
            if (match != null) {
                final HighSymbol target = match;
                return inTransaction("Rename variable", () -> {
                    HighFunctionDBUtil.updateDBVariable(target, to, null, SourceType.USER_DEFINED);
                    return "{\"ok\":true,\"scope\":\"decompiler\",\"function\":\""
                            + escapeJson(f.getName()) + "\",\"old_name\":\"" + escapeJson(from)
                            + "\",\"new_name\":\"" + escapeJson(to) + "\"}";
                });
            }
        }
        Variable listingVar = null;
        for (Variable v : f.getAllVariables()) {
            if (v != null && from.equals(v.getName())) {
                listingVar = v;
                break;
            }
        }
        if (listingVar == null) {
            return "{\"error\":\"no_such_variable\",\"function\":\"" + escapeJson(f.getName())
                    + "\",\"old_name\":\"" + escapeJson(from) + "\",\"available\":"
                    + variableNamesJson(f, high) + "}";
        }
        final Variable target = listingVar;
        return inTransaction("Rename variable", () -> {
            target.setName(to, SourceType.USER_DEFINED);
            return "{\"ok\":true,\"scope\":\"listing\",\"function\":\"" + escapeJson(f.getName())
                    + "\",\"old_name\":\"" + escapeJson(from) + "\",\"new_name\":\"" + escapeJson(to) + "\"}";
        });
    }

    /** JSON array of the variable names this function has, so a failed rename can say what does exist. */
    private static String variableNamesJson(Function f, HighFunction high) {
        Set<String> names = new java.util.LinkedHashSet<>();
        if (high != null) {
            Iterator<HighSymbol> it = high.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol sym = it.next();
                if (sym != null && sym.getName() != null) {
                    names.add(sym.getName());
                }
            }
        }
        for (Variable v : f.getAllVariables()) {
            if (v != null && v.getName() != null) {
                names.add(v.getName());
            }
        }
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String n : names) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escapeJson(n)).append('"');
        }
        return sb.append(']').toString();
    }

    /**
     * Parses C type text and, when {@code addressText} names a valid address, lays the resulting type down
     * there.
     *
     * <p>Accepts anything Ghidra's C parser understands — {@code struct Foo { int a; char *b; };},
     * a {@code typedef}, an {@code enum} — and resolves field types against the program's own
     * {@link ghidra.program.model.data.DataTypeManager}, so built-ins and types recovered by analysis
     * both work. Pass an empty address to only define the type without applying it.
     */
    public synchronized String createStruct(String addressText, String structDefinition) throws Exception {
        ensureProgram();
        String text = structDefinition == null ? "" : structDefinition.trim();
        if (text.isEmpty()) {
            return "{\"error\":\"empty_definition\"}";
        }
        if (!text.endsWith(";") && !text.endsWith("}")) {
            text = text + ";";
        }
        final String source = text;
        Address addr = parseAddress(addressText);
        return inTransaction("Create data type", () -> {
            DataType parsed;
            try {
                CParser parser = new CParser(program.getDataTypeManager(), true, null);
                parsed = parser.parse(source);
                if (parsed == null) {
                    Map<String, DataType> composites = parser.getComposites();
                    if (composites != null && !composites.isEmpty()) {
                        parsed = composites.values().iterator().next();
                    }
                }
            } catch (Exception e) {
                return "{\"error\":\"parse_failed\",\"message\":\"" + escapeJson(shortMessage(e)) + "\"}";
            }
            if (parsed == null) {
                return "{\"error\":\"parse_failed\",\"message\":\"no data type produced\"}";
            }
            DataType stored = program.getDataTypeManager().addDataType(parsed, null);
            int size = stored.getLength();
            boolean applied = false;
            String applyError = "";
            if (addr != null && size > 0) {
                try {
                    Listing listing = program.getListing();
                    listing.clearCodeUnits(addr, addr.add(size - 1L), false);
                    listing.createData(addr, stored);
                    applied = true;
                } catch (Exception e) {
                    applyError = shortMessage(e);
                }
            }
            StringBuilder sb = new StringBuilder("{\"ok\":true,\"name\":\"");
            sb.append(escapeJson(stored.getName())).append("\",\"size\":").append(size);
            sb.append(",\"kind\":\"").append(stored instanceof Structure ? "struct" : "type").append('"');
            sb.append(",\"applied\":").append(applied);
            if (addr != null) {
                sb.append(",\"address\":\"").append(escapeJson(addr.toString())).append('"');
            }
            if (!applyError.isEmpty()) {
                sb.append(",\"apply_error\":\"").append(escapeJson(applyError)).append('"');
            }
            return sb.append('}').toString();
        });
    }

    /**
     * Applies a C prototype to the function at {@code addressText}, e.g.
     * {@code int __fastcall parse(char *buf, size_t len)}.
     *
     * <p>Uses the same parser and command the Ghidra UI's "Edit Function Signature" uses, so return type,
     * parameter names/types, calling convention and varargs all take effect in the decompiler.
     */
    public synchronized String setFunctionSignature(String addressText, String signature) throws Exception {
        ensureProgram();
        String text = signature == null ? "" : signature.trim();
        if (text.isEmpty()) {
            return "{\"error\":\"empty_signature\"}";
        }
        Function f = resolveFunction(addressText);
        if (f == null) {
            return "{\"error\":\"no_function_at_address\"}";
        }
        if (text.endsWith(";")) {
            text = text.substring(0, text.length() - 1).trim();
        }
        final String proto = text;
        return inTransaction("Set function signature", () -> {
            FunctionDefinitionDataType def;
            try {
                FunctionSignatureParser parser =
                        new FunctionSignatureParser(program.getDataTypeManager(), null);
                def = parser.parse(f.getSignature(), proto);
            } catch (Exception e) {
                return "{\"error\":\"parse_failed\",\"message\":\"" + escapeJson(shortMessage(e)) + "\"}";
            }
            if (def == null) {
                return "{\"error\":\"parse_failed\",\"message\":\"no signature produced\"}";
            }
            /*
             * RENAME_IF_DEFAULT: a prototype written over FUN_00401000 names the function too (what the
             * caller means by giving it a name), while a function the user already named keeps that name.
             * preserveCallingConvention=false so an explicit __fastcall / __stdcall in the text takes effect.
             */
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), def,
                    SourceType.USER_DEFINED, false, FunctionRenameOption.RENAME_IF_DEFAULT);
            if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                return "{\"error\":\"apply_failed\",\"message\":\"" + escapeJson(cmd.getStatusMsg()) + "\"}";
            }
            return "{\"ok\":true,\"address\":\"" + escapeJson(f.getEntryPoint().toString())
                    + "\",\"name\":\"" + escapeJson(f.getName()) + "\",\"signature\":\""
                    + escapeJson(f.getSignature().getPrototypeString()) + "\"}";
        });
    }

    /** First line of an exception message (parser errors are multi-line), for compact JSON payloads. */
    private static String shortMessage(Throwable e) {
        String m = e.getMessage();
        if (m == null || m.isBlank()) {
            m = e.getClass().getSimpleName();
        }
        m = m.trim();
        int nl = m.indexOf('\n');
        if (nl > 0) {
            m = m.substring(0, nl).trim();
        }
        return m.length() > 400 ? m.substring(0, 400) : m;
    }

    public synchronized void closeAll() {
        closeCurrentProgramAndProject();
    }

    /** Image base address string for navigation when no functions/exports are listed yet. */
    public synchronized String getImageBaseAddress() throws Exception {
        ensureProgram();
        Address b = program.getImageBase();
        return b != null ? b.toString() : "";
    }

    // -------------------------------------------------------------------------

    /**
     * Creates the projects parent directory if it is missing.
     *
     * <p>{@code GhidraProject.createProject} does not create its parent and fails with a bare
     * {@code FileNotFoundException}; only the Qt controller was creating the directory, so every other
     * entry point (the smoke test, a custom {@code RAWVIEW_PROJECT_DIR}, a first run whose data dir was
     * cleaned) hit that on the first {@link #openFile}.
     */
    private void ensureProjectBaseDir() throws IOException {
        File dir = new File(projectBaseDir);
        if (dir.isDirectory()) {
            return;
        }
        if (!dir.mkdirs() && !dir.isDirectory()) {
            throw new IOException("Could not create Ghidra project directory: " + dir.getAbsolutePath());
        }
    }

    private void ensureProgram() {
        if (program == null) {
            throw new IllegalStateException("No program loaded; call openFile first");
        }
    }

    /** Work that mutates the program database; run only inside {@link #inTransaction}. */
    @FunctionalInterface
    private interface ProgramEdit<T> {
        T apply() throws Exception;
    }

    /**
     * Runs {@code edit} inside its own named Ghidra transaction and commits only on success.
     *
     * <p>Every write to a {@link Program} has to be inside a transaction. RawView used to write without
     * opening one and got away with it only because {@code GhidraProject.importProgram} leaves a
     * "Batch Processing" transaction open — which is absent after {@link #openSavedProject}, gives the
     * user a single undo step for the whole session, and rolls edits back wholesale if it is ever aborted.
     * A per-edit transaction also makes each rename/comment/retype separately undoable in Ghidra.
     */
    private <T> T inTransaction(String name, ProgramEdit<T> edit) throws Exception {
        ensureProgram();
        int txId = program.startTransaction(name);
        boolean commit = false;
        try {
            T out = edit.apply();
            commit = true;
            return out;
        } finally {
            program.endTransaction(txId, commit);
            if (commit) {
                decompileCache.clear();
            }
        }
    }

    /** Fresh {@link DecompInterface} for {@link #program}, with the program's own decompiler options. */
    private void attachDecompiler() {
        if (decompiler != null) {
            try {
                decompiler.dispose();
            } catch (Exception ignored) {
                // disposing a dead decompiler process must not fail the open
            }
        }
        decompileCache.clear();
        decompiler = new DecompInterface();
        /*
         * Pick up per-program decompiler settings (eliminate unreachable code, respect the program's
         * analysis options, …) instead of library defaults; this is what the Ghidra UI decompiler does.
         */
        decompileOptions.grabFromProgram(program);
        decompiler.setOptions(decompileOptions);
        // "decompile" is the full simplification style; without it the C output keeps low-level artifacts.
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(program)) {
            throw new IllegalStateException(
                    "Decompiler could not open the program: " + decompiler.getLastMessage());
        }
    }

    /**
     * Reads up to {@code out.length} bytes at {@code addr}, returning however many are actually mapped.
     *
     * <p>{@link Memory#getBytes} throws as soon as the range runs off the end of a memory block, so a
     * single read of a fixed window fails outright near every section boundary. Clamp to the containing
     * block first, then binary-search the readable prefix if the block is itself sparsely initialized.
     */
    private static int readBytesBestEffort(Memory mem, Address addr, byte[] out) {
        int want = out.length;
        MemoryBlock block = mem.getBlock(addr);
        if (block != null) {
            long room = block.getEnd().subtract(addr) + 1;
            if (room > 0 && room < want) {
                want = (int) room;
            }
        }
        while (want > 0) {
            try {
                int got = mem.getBytes(addr, out, 0, want);
                if (got > 0) {
                    return got;
                }
                return 0;
            } catch (Exception e) {
                // Largest readable prefix is somewhere below `want`; halve and retry (<= 17 tries at 64K).
                want /= 2;
            }
        }
        return 0;
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
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

    /**
     * Parses an address the way a user or the agent writes one: plain hex ({@code 004012a0}), a
     * {@code 0x} prefix, a {@code space:offset} form, or the name of a function/label in the program.
     *
     * <p>{@link ghidra.program.model.address.AddressFactory#getAddress(String)} accepts only the last two
     * forms, so a {@code 0x…} argument used to come back as "invalid address" from every tool.
     */
    private Address parseAddress(String addressText) {
        if (addressText == null) {
            return null;
        }
        String t = addressText.trim();
        if (t.isEmpty()) {
            return null;
        }
        try {
            Address a = program.getAddressFactory().getAddress(t);
            if (a != null) {
                return a;
            }
        } catch (Exception ignored) {
            // fall through to the lenient forms below
        }
        String bare = t;
        /*
         * getStringsJson and getDisassembly render addresses block-qualified (".rodata:00104f60"), so the
         * agent and the UI hand those strings straight back to address-taking calls; keep the offset.
         */
        int colon = bare.lastIndexOf(':');
        if (colon >= 0 && colon + 1 < bare.length()) {
            bare = bare.substring(colon + 1);
        }
        if (bare.regionMatches(true, 0, "0x", 0, 2)) {
            bare = bare.substring(2);
        }
        bare = bare.replace("_", "");
        try {
            return program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseUnsignedLong(bare, 16));
        } catch (Exception ignored) {
            // not hex either; try it as a symbol name
        }
        SymbolIterator named = program.getSymbolTable().getSymbols(t);
        if (named != null && named.hasNext()) {
            Symbol s = named.next();
            if (s != null) {
                return s.getAddress();
            }
        }
        return null;
    }

    private Function resolveFunction(String addressText) {
        Address addr = parseAddress(addressText);
        if (addr == null) {
            return null;
        }
        FunctionManager fm = program.getFunctionManager();
        Function f = fm.getFunctionAt(addr);
        if (f != null) {
            return f;
        }
        return fm.getFunctionContaining(addr);
    }

    private void closeCurrentProgramAndProject() {
        needsInitialProjectSaveAs = false;
        if (decompiler != null) {
            try {
                decompiler.dispose();
            } catch (Exception ignored) {
            }
            decompiler = null;
        }
        if (ghidraProject != null) {
            try {
                ghidraProject.close();
            } catch (Exception ignored) {
            }
            ghidraProject = null;
        }
        program = null;
        currentProjectName = null;
    }
}
