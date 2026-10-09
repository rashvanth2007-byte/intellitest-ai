import Anthropic from '@anthropic-ai/sdk';

export const CLAUDE_MODELS = [
  { id: 'claude-opus-5-5', label: 'Claude Opus 5.5 — most thorough' },
  { id: 'claude-sonnet-5-5', label: 'Claude Sonnet 5.5 — balanced' },
  { id: 'claude-haiku-5-5', label: 'Claude Haiku 5.5 — fastest / lowest cost' },
];
export const GEMINI_MODELS = [
  { id: 'gemini-3.5-flash-lite', label: 'Gemini 3.5 Flash-Lite' },
  { id: 'gemini-3.5-flash', label: 'Gemini 3.5 Flash' },
  { id: 'gemini-3.5-pro', label: 'Gemini 3.5 Pro' },
];

/** JSON schema every agent must answer with. */
export const FINDINGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['vulnerabilities', 'summary'],
  properties: {
    summary: { type: 'string' },
    vulnerabilities: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['severity', 'title', 'category', 'file', 'line', 'description', 'impact', 'recommendation', 'cwe', 'cvss', 'confidence'],
        properties: {
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          title: { type: 'string' },
          category: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          description: { type: 'string' },
          impact: { type: 'string' },
          recommendation: { type: 'string' },
          cwe: { type: 'string' },
          cvss: { type: 'number' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
      },
    },
  },
};

/**
 * retryable: worth trying the same call again (rate limit, network, 5xx, malformed output).
 * declined:  the model refused this chunk.
 * fatal:     configuration problem (bad key, no access, unknown model) — every further call would fail too,
 *            so the scan's AI stage should stop instead of hammering the API.
 */
export class AiError extends Error {
  constructor(message, { retryable = false, declined = false, fatal = false } = {}) {
    super(message);
    this.name = 'AiError';
    this.retryable = retryable;
    this.declined = declined;
    this.fatal = fatal;
  }
}

/** End index (exclusive) of the balanced JSON object starting at `start`, or -1 if it never closes. */
function balancedEnd(s, start) {
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return i + 1;
  }
  return -1;
}

/** Parse the first balanced top-level JSON object out of model text (skipping prose like "{x}" before it). */
export function extractJson(raw) {
  const text = String(raw ?? '').trim();
  try { const j = JSON.parse(text); if (j && typeof j === 'object' && !Array.isArray(j)) return j; } catch { /* fall through */ }
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const bodies = fence ? [fence[1], text] : [text];
  let sawOpen = false;
  for (const body of bodies) {
    for (let start = body.indexOf('{'); start >= 0; start = body.indexOf('{', start + 1)) {
      sawOpen = true;
      const end = balancedEnd(body, start);
      if (end < 0) break; // unterminated from here on — later starts are nested inside it
      try { const j = JSON.parse(body.slice(start, end)); if (j && typeof j === 'object') return j; } catch { /* try next "{" */ }
    }
  }
  throw new AiError(sawOpen ? 'Model returned malformed JSON' : 'Model returned no JSON', { retryable: true });
}

/**
 * Recover the complete findings from a response cut off by the output-token limit:
 * {"summary": "...", "vulnerabilities": [ {..}, {..}, {..   ← truncated
 * Returns null when nothing usable is present.
 */
export function salvageTruncated(raw) {
  const text = String(raw ?? '');
  const arr = text.match(/"vulnerabilities"\s*:\s*\[/);
  if (!arr) return null;
  const items = [];
  let i = arr.index + arr[0].length;
  for (;;) {
    while (i < text.length && /[\s,]/.test(text[i])) i++;
    if (text[i] !== '{') break;
    const end = balancedEnd(text, i);
    if (end < 0) break;
    try { items.push(JSON.parse(text.slice(i, end))); } catch { break; }
    i = end;
  }
  const summary = text.match(/"summary"\s*:\s*"((?:[^"\\]|\\.)*)"/)?.[1];
  let s = '';
  try { s = summary ? JSON.parse(`"${summary}"`) : ''; } catch { /* ignore */ }
  return items.length || s ? { summary: s, vulnerabilities: items, truncated: true } : null;
}

/** Map Anthropic SDK errors to AiError with a clean, user-facing message (never the raw JSON body). */
export function classifyAnthropicError(e, model) {
  if (e instanceof AiError) return e;
  if (e instanceof Anthropic.AuthenticationError) return new AiError('The Anthropic API key is invalid.', { fatal: true });
  if (e instanceof Anthropic.PermissionDeniedError) return new AiError('The Anthropic API key does not have permission to use this model.', { fatal: true });
  if (e instanceof Anthropic.NotFoundError) return new AiError(model ? `Model ${model} is not available for this API key.` : 'The requested Claude model is not available for this API key.', { fatal: true });
  if (e instanceof Anthropic.RateLimitError) return new AiError('Anthropic rate limit reached — try again shortly or lower the AI depth.', { retryable: true });
  if (e instanceof Anthropic.BadRequestError) {
    const msg = e.error?.error?.message || e.message || '';
    // A per-chunk problem (prompt too long) shouldn't stop other chunks; anything else (billing, bad params) is global.
    const perChunk = /too long|too many tokens|context (?:window|length)/i.test(msg);
    return new AiError(`Anthropic rejected the request: ${msg.replace(/^\d{3}\s*/, '').slice(0, 200)}`, { fatal: !perChunk });
  }
  if (e instanceof Anthropic.APIConnectionError) return new AiError('Could not reach the Anthropic API (offline?).', { retryable: true });
  if (e instanceof Anthropic.InternalServerError || (e instanceof Anthropic.APIError && (e.status === 529 || e.status >= 500))) {
    return new AiError('The Anthropic API is temporarily unavailable or overloaded.', { retryable: true });
  }
  if (e instanceof Anthropic.APIError && e.status) return new AiError(`Anthropic API error ${e.status}.`, { retryable: e.status === 408 || e.status === 409 });
  return e;
}

/* ─────────────────────────── Claude ─────────────────────────── */
const clients = new Map();
function claudeClient(apiKey) {
  if (!clients.has(apiKey)) clients.set(apiKey, new Anthropic({ apiKey, maxRetries: 3, timeout: 10 * 60 * 1000 }));
  return clients.get(apiKey);
}

/**
 * system: stable instructions; code: the (cached) code block; task: agent-specific instructions.
 * The code block carries cache_control so the 5 agents analysing the same chunk reuse it.
 */
export async function callClaude({ apiKey, model, system, code, task, signal }) {
  const client = claudeClient(apiKey);
  const supportsFallback = /^claude-(?:opus|sonnet)-5-5$/.test(model);
  const params = {
    model,
    max_tokens: 16000,
    system,
    output_config: {
      effort: model.startsWith('claude-haiku') ? 'medium' : 'low',
      format: { type: 'json_schema', schema: FINDINGS_SCHEMA },
    },
    messages: [{
      role: 'user',
      content: [
        { type: 'text', text: code, cache_control: { type: 'ephemeral' } },
        { type: 'text', text: task },
      ],
    }],
  };
  let resp;
  try {
    resp = supportsFallback
      ? await client.beta.messages.create({ ...params, betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' }, { signal })
      : await client.messages.create(params, { signal });
  } catch (e) {
    if (e?.name === 'AbortError' || signal?.aborted) throw e;
    throw classifyAnthropicError(e, model);
  }
  return parseClaudeResponse(resp);
}

/** Turn a Messages API response into { json, usage, truncated? } — exported for tests. */
export function parseClaudeResponse(resp) {
  if (resp?.stop_reason === 'refusal') throw new AiError('Claude declined to analyse this chunk.', { declined: true });
  const text = (resp?.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
  const usage = resp?.usage;
  if (resp?.stop_reason === 'max_tokens') {
    // Structured output cut off mid-array: keep the findings that were completed.
    try { return { json: extractJson(text), usage }; } catch { /* fall through */ }
    const partial = salvageTruncated(text);
    if (partial) return { json: partial, usage, truncated: true };
    throw withUsage(new AiError('Response was cut off (max_tokens) before any complete finding.', { retryable: true }), usage);
  }
  if (!text) throw withUsage(new AiError('Empty response from Claude.', { retryable: true }), usage);
  try { return { json: extractJson(text), usage }; } catch (e) { throw withUsage(e, usage); }
}

/** Failed-but-billed calls still carry their token usage so the scan's cost accounting stays honest. */
const withUsage = (err, usage) => { if (usage && err && typeof err === 'object') err.usage = usage; return err; };

/* ─────────────────────────── Gemini ─────────────────────────── */
function toGeminiSchema(s) {
  // Gemini's responseSchema is an OpenAPI subset: no additionalProperties.
  if (Array.isArray(s)) return s.map(toGeminiSchema);
  if (!s || typeof s !== 'object') return s;
  const out = {};
  for (const [k, v] of Object.entries(s)) if (k !== 'additionalProperties') out[k] = toGeminiSchema(v);
  return out;
}

export async function callGemini({ apiKey, model, system, code, task, signal }) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  let resp;
  try {
    resp = await fetch(url, {
      method: 'POST',
      // Key goes in a header, never in the URL (URLs end up in logs and proxies).
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: code }, { text: task }] }],
        generationConfig: { temperature: 0.1, responseMimeType: 'application/json', responseSchema: toGeminiSchema(FINDINGS_SCHEMA), maxOutputTokens: 16000 },
      }),
      signal,
    });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new AiError('Could not reach the Gemini API (offline?).', { retryable: true });
  }
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw geminiHttpError(resp.status, body, model);
  }
  let d;
  try { d = await resp.json(); } catch { throw new AiError('Gemini returned an unreadable response.', { retryable: true }); }
  return parseGeminiResponse(d);
}

/** Clean message for a Gemini HTTP error; the raw body is only summarised (it may echo request details). */
export function geminiHttpError(status, body = '', model) {
  let msg = '';
  try { msg = JSON.parse(body)?.error?.message || ''; } catch { msg = String(body).slice(0, 200); }
  if ((status === 400 && /API key/i.test(msg || body)) || status === 401) return new AiError('The Gemini API key is invalid.', { fatal: true });
  if (status === 403) return new AiError('The Gemini API key does not have permission for this model (or the Generative Language API is not enabled).', { fatal: true });
  if (status === 404) return new AiError(`Gemini model ${model} not found.`, { fatal: true });
  if (status === 429) return new AiError('Gemini rate limit reached — try again shortly.', { retryable: true });
  if (status >= 500) return new AiError(`Gemini API is temporarily unavailable (HTTP ${status}).`, { retryable: true });
  return new AiError(`Gemini API error ${status}${msg ? `: ${msg.slice(0, 200)}` : ''}`);
}

const GEMINI_DECLINED = new Set(['SAFETY', 'RECITATION', 'BLOCKLIST', 'PROHIBITED_CONTENT', 'SPII', 'IMAGE_SAFETY']);

/** Turn a generateContent response into { json, usage } — exported for tests. */
export function parseGeminiResponse(d) {
  const usage = d?.usageMetadata;
  const cand = d?.candidates?.[0];
  if (!cand || GEMINI_DECLINED.has(cand.finishReason) || d?.promptFeedback?.blockReason) throw withUsage(new AiError('Gemini declined to analyse this chunk.', { declined: true }), usage);
  const text = (cand.content?.parts || []).filter((p) => !p.thought).map((p) => p.text || '').join('');
  if (cand.finishReason === 'MAX_TOKENS') {
    try { return { json: extractJson(text), usage }; } catch { /* fall through */ }
    const partial = salvageTruncated(text);
    if (partial) return { json: partial, usage, truncated: true };
    throw withUsage(new AiError('Gemini response was cut off (max tokens) before any complete finding.', { retryable: true }), usage);
  }
  if (!text) throw withUsage(new AiError('Empty response from Gemini.', { retryable: true }), usage);
  try { return { json: extractJson(text), usage }; } catch (e) { throw withUsage(e, usage); }
}

/**
 * Verify a credential. Throws AiError with a short, user-facing message — never the provider's raw
 * JSON error body. `fetchImpl` / `anthropicClient` are injectable for tests.
 */
export async function testKey(provider, apiKey, model, { fetchImpl = fetch, anthropicClient } = {}) {
  if (provider === 'anthropic') {
    const c = anthropicClient || new Anthropic({ apiKey, maxRetries: 0, timeout: 20000 });
    try {
      await c.models.retrieve(model || 'claude-haiku-5-5');
    } catch (e) {
      if (e instanceof Anthropic.AuthenticationError) throw new AiError('The API key is invalid.', { fatal: true });
      if (e instanceof Anthropic.PermissionDeniedError) throw new AiError('The API key does not have permission to use this model.', { fatal: true });
      if (e instanceof Anthropic.NotFoundError) throw new AiError(`Model ${model || 'claude-haiku-5-5'} is not available for this API key.`, { fatal: true });
      if (e instanceof Anthropic.RateLimitError) throw new AiError('Anthropic rate limit reached — the key looks valid; try again shortly.', { retryable: true });
      if (e instanceof Anthropic.APIConnectionError) throw new AiError('Could not reach Anthropic (offline?).', { retryable: true });
      if (e instanceof Anthropic.APIError && e.status) throw new AiError(`Anthropic returned HTTP ${e.status} while checking the key.`, { retryable: e.status >= 500 });
      throw new AiError('Could not verify the Anthropic API key.');
    }
    return true;
  }
  const httpCheck = async (url, headers, name, what) => {
    let r;
    try { r = await fetchImpl(url, { headers, signal: AbortSignal.timeout(20000) }); } catch { throw new AiError(`Could not reach ${name} (offline?).`, { retryable: true }); }
    if (r.ok) return true;
    if (r.status === 401 || (r.status === 400 && name === 'Gemini')) throw new AiError(`The ${what} is invalid.`, { fatal: true });
    if (r.status === 403) throw new AiError(`The ${what} was rejected (missing permission or API not enabled).`, { fatal: true });
    if (r.status === 429) throw new AiError(`${name} rate limit reached — try again shortly.`, { retryable: true });
    throw new AiError(`${name} returned HTTP ${r.status} while checking the ${what}.`, { retryable: r.status >= 500 });
  };
  if (provider === 'gemini') return httpCheck('https://generativelanguage.googleapis.com/v1beta/models?pageSize=1', { 'x-goog-api-key': apiKey }, 'Gemini', 'API key');
  if (provider === 'github') return httpCheck('https://api.github.com/user', { Authorization: `Bearer ${apiKey}`, 'User-Agent': 'IntelliTest-AI' }, 'GitHub', 'token');
  throw new AiError('Unknown provider');
}
