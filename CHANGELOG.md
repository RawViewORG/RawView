# Changelog

## 1.3.2

### Fixes a broken 1.3.1

**RawView 1.3.1 does not start.** Every package it shipped - `.deb`, `.rpm`,
`.AppImage`, `.msi` - crashes at import before the window opens:

```
rawview/qt_ui/app.py -> main_window.py -> controller.py -> brain.py
  -> agent/providers/__init__.py:14
ModuleNotFoundError: No module named 'httpx'
```

`rawview.agent.providers` imports `httpx` directly, but `httpx` was never declared in
`pyproject.toml` - it only ever arrived as a dependency of `anthropic`. The `anthropic`
1.0 release switched from `httpx` to `httpx2`, and since the pin was an open
`anthropic>=0.40.0`, the build resolved 1.0 and `httpx` silently disappeared from the
bundle. `httpx` is now a declared dependency, because the code imports it.

Auditing the SDK bump turned up a second break in the same release. The `anthropic` 1.0
`messages.create` and `messages.stream` no longer accept `temperature` and take no
`**kwargs`, so every request for a model that still accepts sampling params - Haiku 4.5,
Opus 4.1, Sonnet 4.5 - would raise `TypeError`. `anthropic` is capped below 1.0 until
that migration is done deliberately.

Users on 1.3.0 were never affected; that bundle was built while `anthropic` still
depended on `httpx`.

### Release pipeline

The release workflow built and published a bundle that could not start, because nothing
in it ever imported the application. Both the Linux and Windows jobs now walk the app's
real startup import chain before packaging, and fail the release if it breaks.

## 1.3.1

### Ghidra engine

The Java bridge is where RawView actually talks to Ghidra, and several of its answers
were placeholders. This pass makes them real, verified against Ghidra 12.0.4 on live
binaries.

**Tools that did nothing now work.** `rename_variable`, `create_struct` and
`set_function_signature` returned `not_implemented` while still being advertised to the
agent. They are implemented against the same APIs Ghidra's own UI uses - decompiler
variables through `HighFunctionDBUtil`, C types through Ghidra's C parser, prototypes
through `ApplyFunctionSignatureCmd` - so applying a signature or naming a local
immediately changes the decompiled output. A prototype written over a default
`FUN_00401000` name also renames the function; a name you chose is kept.

**Edits are transactional.** Every database write now opens its own named Ghidra
transaction and commits only on success. Previously RawView wrote with no transaction
of its own and worked only because the importer happened to leave one open - which is
absent after restoring a saved session, and gave the whole session a single undo step.
Each rename, comment and retype is now separately undoable.

**Answers that were wrong:**

- **Exports** listed the first 2000 primary symbols of any kind, so the pane filled with
  string labels and section headers. It now reports the image's actual exports.
- **Entry points** looked for a symbol exactly at the image base and returned nothing for
  an ordinary ELF or PE. It now finds `entry` / `_start` / `main` / `DllMain`, falling
  back to entry-point functions and then the image base.
- **The hex view** failed outright whenever its window ran past the end of a memory
  block - near every section boundary - because the whole range was read at once. It now
  returns the bytes that are actually mapped.
- **Byte search** returned only the first match and rejected wildcards. It returns every
  match, each with its containing function and memory block, and accepts `??` wildcards
  and unseparated hex, so signatures work as written.
- **Addresses** written as `0x00401000`, as a symbol name, or block-qualified
  (`.rodata:00104f60`, the form `get_strings` itself returns) were rejected as invalid.
  All three are accepted now.
- **Project directory**: the JVM never created its own project folder, so any entry point
  other than the Qt window failed on first open with a bare `FileNotFoundException`.

**Faster on real targets.** Decompiled C is cached until the program changes (1011 ms to
43 ms on a large function, and any edit invalidates it). Function, string and symbol
listings are filtered and windowed inside the JVM instead of marshalling the entire
program through Py4J so the caller can throw most of it away - the symbols pane was
transferring every symbol to show 500.

**Auto-analysis can be cancelled.** `cancel_analysis()` stops a run in flight (the
monitor was constructed non-cancellable); the run keeps the analysis it completed and
does not mark the program analyzed, so it can be resumed. The cancel is delivered
out-of-band around the Py4J mutex, which the analysis call holds for its whole run.

Also: comments can be written to any slot (`EOL`, `PRE`, `POST`, `PLATE`, `REPEATABLE`),
`rename_function` falls back to renaming the label when the address holds data,
`decompile_function` takes a per-call timeout, the decompiler is configured from the
program's own options, and `python -m rawview.scripts.smoke_bridge_test` now checks all
of the above against a real binary.

Rebuild the bridge to pick this up: `python -m rawview.scripts.compile_java`. Older
compiled bridges keep working - the Python layer falls back to the previous calls.

## 1.3.0

### Use any model: local or cloud

The agent is no longer tied to one vendor. A **Provider** setting picks the backend,
and everything else in RawView works the same way regardless of what answers.

**Local models** run with no API key and no network at all:

| Preset | Default endpoint |
| --- | --- |
| Ollama | `http://localhost:11434/v1` |
| LM Studio | `http://localhost:1234/v1` |
| llama.cpp server | `http://localhost:8080/v1` |
| vLLM | `http://localhost:8000/v1` |

**Cloud** presets ship for OpenAI, Google Gemini and OpenRouter, plus a **Custom**
entry for anything else exposing `/v1/chat/completions` - Groq, Together, DeepSeek,
Mistral and friends need only a base URL.

Practical notes:

- **Refresh** next to the model box asks the endpoint which models it actually serves,
  so you pick a real id instead of guessing at one. Works against local runners and
  hosted APIs alike.
- Reverse engineering is tool-driven: the agent reads the binary through Ghidra tools,
  so a model that cannot emit tool calls will be chat-only. Untick **Model can call
  tools** for those and expect a conversation, not analysis. When choosing a local
  model, prefer one whose chat template supports tool calling.
- Reasoning text is displayed when a backend sends it (`reasoning_content`, as used by
  DeepSeek, Qwen and others). Anthropic's extended-thinking and effort controls stay
  Anthropic-only, because that is where they exist.
- Existing setups are untouched. The provider defaults to Anthropic and keeps using
  `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL`; saved `.rvre` sessions keep loading.

Known limitation: reasoning blocks are not portable between vendors, so switching
provider mid-conversation drops earlier reasoning from the replayed history. Text and
tool calls carry over intact.

### Keeping smaller models in the agent loop

Local models lose the plot in two specific ways, and both used to end the run:

- **The tool call never reaches the API field.** Whether a model's call arrives as
  `tool_calls` depends on the server's chat template and tool-call parser, so the same
  GGUF that calls tools under Ollama emits `<tool_call>{...}</tool_call>` as chat text
  under a bare llama.cpp server. RawView now recovers calls written as plain text -
  Hermes/Qwen tags, Mistral `[TOOL_CALLS]`, Llama `<function=…>` and pythonic
  `[fn(arg=…)]`, fenced or bare JSON - runs them, and strips the raw JSON from the
  feed. Only names from the real tool list are recovered, and you get a one-time note
  telling you the endpoint is missing a parser for that model.
- **The model forgets it is the agent** and ends its turn with "run this and paste the
  tool output so I can keep working". Nobody was ever going to paste anything: the
  host runs every call and feeds the result straight back. The loop now spots that
  hand-off (and a turn that returns nothing at all), tells the model who is driving,
  and lets it try again - at most twice per message, so a confused model cannot spend
  your tokens in a loop.

The system prompt states the same thing up front for every backend: the host executes
tool calls automatically, and the user has nothing to paste.

### Internals

Vendor specifics now live behind a provider interface; `AgentBrain` owns the tool loop
and transcript and no longer knows which API replied. Adding a backend is one adapter.
The OpenAI-compatible adapter speaks HTTP directly rather than pulling the `openai`
SDK, whose vendored httpx/aiohttp stack conflicts with distro packages inside the
PyInstaller bundle. It also heals the common endpoint quirks from the server's own
error message: `max_tokens` → `max_completion_tokens` on GPT-5/o-series, and dropping
`temperature` where a model rejects it.

## 1.2.5

### Claude Opus 5 support

Opus 5 could not be used at all before this release. It matched none of the model
tables, so it fell through to generic handling and the agent sent both `temperature`
and `thinking.budget_tokens` - each rejected with HTTP 400 - while capping output at
8192 tokens instead of 128k.

- Opus 5 added to the max-output table (128k), the no-sampling-params set, the
  xhigh-effort set, and adaptive thinking.
- Thinking is on by default on Opus 5, Sonnet 5 and Fable/Mythos 5, so omitting the
  parameter no longer turns it off. The **extended thinking** toggle was silently a
  no-op on those models; RawView now disables thinking explicitly where the model
  accepts that, and omits the parameter for models that reject an explicit disable.
- Effort is clamped to `high` when thinking is off on Opus 5, since pairing a disable
  with `xhigh`/`max` is another 400.
- The default model moves from `claude-opus-4-6` to `claude-opus-5`.
- The thinking-budget control now derives its enabled state from the shared
  capability helper instead of a duplicated model-name check - the duplicate is what
  let the tables drift apart in the first place.
- Fixed: an explicit thinking disable no longer suppresses the fallback from
  streaming to non-streaming requests.
