import { startServer } from './app.js';
import { config } from './config.js';
import { getDb } from './db/index.js';

const { server, url } = await startServer();
console.log(`IntelliTest AI listening on ${url}`);
console.log(`  database: ${config.databaseUrl ? 'PostgreSQL' : config.sqliteFile}`);
console.log(`  app URL:  ${config.appUrl}`);
if (!config.github.clientId) console.log('  GitHub sign-in disabled (set GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET to enable)');
if (config.isProd && !config.databaseUrl) {
  console.warn('  WARNING: production without DATABASE_URL uses SQLite on local disk. On hosts with ephemeral disks (Render free, etc.) data is lost on redeploy — use PostgreSQL.');
}

let stopping = false;
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    if (stopping) return;
    stopping = true;
    console.log(`\n${sig} received, shutting down`);
    server.close();
    Promise.resolve(getDb().close()).finally(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
