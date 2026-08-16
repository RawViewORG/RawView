# Changelog

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
