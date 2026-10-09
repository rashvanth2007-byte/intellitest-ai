import { Router } from 'express';
import { requireAuth } from '../auth/session.js';
import { ah, HttpError, str } from '../util/http.js';
import { getSettings, saveSettings, sanitizeSettings, setApiKey, keyStatus, PROVIDERS, resolveApiKey } from './service.js';
import { CLAUDE_MODELS, GEMINI_MODELS, testKey } from '../engines/ai/providers.js';
import { DEPTHS } from '../engines/ai/chunker.js';
import { AGENTS } from '../engines/ai/agents.js';
import { githubOAuthStatus, saveGithubOAuth, removeGithubOAuth } from './appConfig.js';

export const settingsRouter = Router();
settingsRouter.use(requireAuth);

settingsRouter.get('/', ah(async (req, res) => {
  res.json({
    settings: await getSettings(req.user.id),
    keys: await keyStatus(req.user.id),
    options: {
      claudeModels: CLAUDE_MODELS,
      geminiModels: GEMINI_MODELS,
      depths: Object.entries(DEPTHS).map(([id, d]) => ({ id, label: d.label })),
      agents: AGENTS.map(({ id, name, role }) => ({ id, name, role })),
    },
    githubOAuth: githubOAuthStatus(),
  });
}));

/* GitHub OAuth app for "Sign in with GitHub" (local / desktop installs only). */
settingsRouter.put('/github-oauth', ah(async (req, res) => {
  await saveGithubOAuth(req.body?.clientId, req.body?.clientSecret);
  res.json({ githubOAuth: githubOAuthStatus() });
}));

settingsRouter.delete('/github-oauth', ah(async (req, res) => {
  await removeGithubOAuth();
  res.json({ githubOAuth: githubOAuthStatus() });
}));

settingsRouter.put('/', ah(async (req, res) => {
  const next = sanitizeSettings(req.body || {}, await getSettings(req.user.id));
  await saveSettings(req.user.id, next);
  res.json({ settings: next });
}));

settingsRouter.put('/keys/:provider', ah(async (req, res) => {
  const provider = req.params.provider;
  if (!PROVIDERS.includes(provider)) throw new HttpError(400, 'Unknown provider');
  const key = str(req.body?.key, { min: 10, max: 400, name: 'Key' });
  if (/\s/.test(key)) throw new HttpError(400, 'Key must not contain spaces.');
  if (req.body?.verify !== false) {
    try { await testKey(provider, key); } catch (e) { throw new HttpError(400, `Key check failed: ${e.message}`); }
  }
  await setApiKey(req.user.id, provider, key);
  res.json({ keys: await keyStatus(req.user.id) });
}));

settingsRouter.delete('/keys/:provider', ah(async (req, res) => {
  if (!PROVIDERS.includes(req.params.provider)) throw new HttpError(400, 'Unknown provider');
  await setApiKey(req.user.id, req.params.provider, null);
  res.json({ keys: await keyStatus(req.user.id) });
}));

settingsRouter.post('/keys/:provider/test', ah(async (req, res) => {
  const key = await resolveApiKey(req.user.id, req.params.provider);
  if (!key) throw new HttpError(400, 'No key configured.');
  try { await testKey(req.params.provider, key); } catch (e) { throw new HttpError(400, e.message); }
  res.json({ ok: true });
}));
