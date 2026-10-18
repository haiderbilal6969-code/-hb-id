import serverless from 'serverless-http';

// Do this before importing the Express server, which has top-level DB initialization.
process.env.HB_ID_SERVERLESS = 'true';
const { default: app } = await import('../../src/server.mjs');

// Preserve the incoming URL for OpenID Connect discovery, login, and consent flows.
export const handler = serverless(app);
