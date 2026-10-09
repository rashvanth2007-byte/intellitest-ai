// Wraps electron-builder.yml and adds the GitHub Releases update feed only when
// GH_OWNER and GH_REPO are set, so plain local builds work without them.
const fs = require('node:fs');
const path = require('node:path');
const { load } = require('js-yaml');

const config = load(fs.readFileSync(path.join(__dirname, 'electron-builder.yml'), 'utf8'));
const { GH_OWNER, GH_REPO } = process.env;
if (GH_OWNER && GH_REPO) {
  config.publish = { provider: 'github', owner: GH_OWNER, repo: GH_REPO, releaseType: 'release' };
} else if (process.argv.includes('always')) {
  throw new Error('Set GH_OWNER, GH_REPO and GH_TOKEN before running "npm run release:win" (see DEPLOY.md).');
} else {
  console.log('  • GH_OWNER / GH_REPO not set: building without the auto-update feed');
}
module.exports = config;
