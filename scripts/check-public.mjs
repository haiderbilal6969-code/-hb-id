// Read-only checks: no sign-ins, email sends, account creation, or credentials.
import assert from 'node:assert/strict';
const issuer = (process.env.HB_ID_CHECK_ISSUER || 'https://hb-id.vercel.app').replace(/\/$/, '');
const origin = new URL(issuer);
assert.equal(origin.protocol, 'https:', 'Use the HTTPS production issuer');
assert.equal(origin.origin, issuer, 'Use an issuer origin without a path');
async function get(path) {
  const url = new URL(path, issuer);
  assert.equal(url.origin, issuer, 'Discovery endpoints must stay on the issuer');
  const response = await fetch(url, {redirect:'manual', signal:AbortSignal.timeout(15000)});
  assert.equal(response.status, 200, `${url.pathname}: HTTP ${response.status}`);
  return response;
}
try {
  for (const path of ['/', '/portal/login', '/about', '/privacy', '/security']) {
    const response = await get(path);
    assert.match(response.headers.get('content-type') || '', /text\/html/);
    const csp = response.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("frame-ancestors 'none'"), `${path}: missing framing protection`);
    assert.ok(!csp.includes('unsafe-inline'), `${path}: unsafe inline policy`);
    assert.ok(response.headers.get('strict-transport-security'), `${path}: missing HSTS`);
    if (path.startsWith('/portal')) assert.match(response.headers.get('cache-control') || '', /no-store/);
    console.log(`PASS ${path}: HTML and security headers`);
  }
  const health = await (await get('/healthz')).json();
  assert.equal(health.ok, true);
  const ready = await get('/readyz');
  assert.equal((await ready.json()).ready, true);
  console.log('PASS health and database readiness');
  const discovery = await (await get('/.well-known/openid-configuration')).json();
  assert.equal(discovery.issuer, issuer);
  assert.ok(discovery.response_types_supported.includes('code'));
  assert.ok(discovery.code_challenge_methods_supported.includes('S256'));
  for (const field of ['authorization_endpoint','token_endpoint','userinfo_endpoint','jwks_uri']) {
    assert.equal(new URL(discovery[field]).origin, issuer, `${field}: unexpected origin`);
  }
  const jwks = await (await get(discovery.jwks_uri)).json();
  assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0);
  for (const key of jwks.keys) {
    assert.equal(key.kty, 'RSA');
    assert.equal(key.alg, 'RS256');
    for (const field of ['d','p','q','dp','dq','qi','oth','k']) assert.ok(!(field in key), 'JWKS must contain public keys only');
  }
  console.log('PASS OIDC discovery and public signing keys');
  console.log('Read-only checks passed. Authenticated flows and Google clearance are not tested here.');
} catch (error) {
  // Assertions contain only public paths/statuses, never bodies or cookies.
  console.error(`Public check failed: ${error.message}`);
  process.exitCode = 1;
}
