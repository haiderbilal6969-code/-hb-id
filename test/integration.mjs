// Run only against an isolated, empty PostgreSQL test branch.
// Supply {"databaseUrl":"...","confirmation":"isolated-test-database"} via stdin.
// Credentials are never accepted in command arguments or printed.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { once } from 'node:events';
import {testAuthenticator} from './authenticator.mjs';

const input = process.env.HB_ID_TEST_DATABASE_URL ? null : await new Promise(resolve => {
  let value = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => {
    value += chunk;
    if (value.includes('\n')) { process.stdin.pause(); resolve(value.split('\n')[0]); }
  });
});
const config = input === null ? {databaseUrl:process.env.HB_ID_TEST_DATABASE_URL,confirmation:'isolated-test-database'} : JSON.parse(input);
assert.equal(config.confirmation, 'isolated-test-database', 'Explicit test-database confirmation required');
process.env.DATABASE_URL = config.databaseUrl;
process.env.HB_ID_SERVERLESS = 'true';
delete process.env.BOOTSTRAP_ADMIN_EMAIL;
delete process.env.BOOTSTRAP_ADMIN_PASSWORD;
delete process.env.VERCEL;
let app;
const server = createServer((req, res) => app(req, res));
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const issuer = `http://127.0.0.1:${server.address().port}`;
process.env.ISSUER = issuer;
const jar = new Map();
let db;
async function request(path, { method='GET', form, json, headers={}, browser=true }={}) {
  const url = new URL(path, issuer);
  if (browser) headers.Cookie = [...jar.values()].filter(c => url.pathname.startsWith(c.path)).map(c => c.pair).join('; ');
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    if(browser) headers.Origin = issuer;
  }
  if(json){headers['Content-Type']='application/json';if(browser)headers.Origin=issuer;}
  const response = await fetch(url, { method, headers, body:json?JSON.stringify(json):form?new URLSearchParams(form):undefined, redirect:'manual' });
  if (browser) for (const line of response.headers.getSetCookie()) {
    const [pair,...attrs] = line.split(';').map(s => s.trim());
    const name = pair.slice(0, pair.indexOf('='));
    const path = attrs.find(a => a.toLowerCase().startsWith('path='))?.slice(5) || '/';
    const key = `${name}:${path}`;
    const expired = attrs.some(a => /^max-age=0$/i.test(a) || /^expires=/i.test(a) && new Date(a.slice(8)).getTime() < Date.now());
    if (expired) jar.delete(key); else jar.set(key, {pair,path});
  }
  return {status:response.status,headers:response.headers,text:await response.text()};
}
async function follow(result) {
  for (let i=0;i<15 && [302,303].includes(result.status);i++) {
    const destination = new URL(result.headers.get('location'), issuer);
    if (destination.origin !== issuer) return {callback:destination};
    result = await request(destination.href);
  }
  return result;
}
try {
  db = await import('../src/db.mjs');
  // Optional local PGlite compatibility; real PostgreSQL uses the normal pool.
  if(process.env.HB_ID_TEST_SINGLE_CONNECTION === 'true') db.pool.options.max=1;
  assert.equal((await db.query('SELECT to_regclass(\'public.users\') AS table_name')).rows[0].table_name, null, 'Test branch must start empty');
  app = (await import('../src/server.mjs?pending')).default;
  assert.equal((await request('/')).status,200);
  assert.equal(JSON.parse((await request('/healthz')).text).ready,false);
  assert.equal((await request('/readyz')).status,503);
  assert.equal((await request('/portal/login')).status,503);
  assert.equal((await request('/setup',{method:'POST',form:{email:'intruder@example.invalid'}})).status,503);
  console.log('PASS: missing owner keeps sign-in and public setup closed');

  const password = randomBytes(32).toString('base64url');
  process.env.BOOTSTRAP_ADMIN_EMAIL = 'owner@example.invalid';
  process.env.BOOTSTRAP_ADMIN_PASSWORD = password;
  assert.deepEqual(await Promise.all([db.initDatabase(),db.initDatabase()]),[true,true]);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM users WHERE is_admin=true')).rows[0].n,1);
  delete process.env.BOOTSTRAP_ADMIN_EMAIL;
  delete process.env.BOOTSTRAP_ADMIN_PASSWORD;
  app = (await import('../src/server.mjs?ready')).default;
  assert.equal((await request('/readyz')).status,200);
  const discovery = JSON.parse((await request('/.well-known/openid-configuration')).text);
  assert.equal(discovery.issuer,issuer);
  const keysBefore = JSON.parse((await request(discovery.jwks_uri)).text);
  const loginPage = await request('/portal/login');
  assert.equal(loginPage.status,200);
  // no-referrer makes browsers send Origin: null on normal HTML form posts.
  // Keep the origin available inside HB ID without sending referrers elsewhere.
  assert.equal(loginPage.headers.get('referrer-policy'),'same-origin','Browser form submissions must preserve the HB ID origin');
  assert.equal((await request('/portal/login',{method:'POST',form:{email:'owner@example.invalid',password}})).status,303);
  for (const origin of ['https://untrusted.example','null',undefined]) {
    const headers={'Content-Type':'application/x-www-form-urlencoded'};
    if(origin!==undefined)headers.Origin=origin;
    const hostile = await fetch(`${issuer}/portal/login`,{method:'POST',headers,body:new URLSearchParams({email:'owner@example.invalid',password}),redirect:'manual'});
    assert.equal(hostile.status,403,'Untrusted, null and missing origins remain blocked');
    assert.equal(hostile.headers.get('set-cookie'),null,'Rejected submissions must not establish a session');
    await hostile.text();
  }
  const portal = await request('/portal');
  assert.equal(portal.status,200);
  let csrf=portal.text.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf,'Portal supplies a CSRF token');
  assert.equal((await request('/portal/apps',{method:'POST',form:{name:'Test site',redirect_uri:'http://localhost:4000/callback'}})).status,403);
  const registration=await request('/portal/apps',{method:'POST',form:{_csrf:csrf,name:'Test site',redirect_uri:'http://localhost:4000/callback'}});
  assert.equal(registration.status,200);
  const client=(await db.query("SELECT payload FROM oidc_objects WHERE model='Client'")).rows[0].payload;
  assert.ok(client.client_secret,'Confidential client registered');
  console.log('PASS: owner bootstrap is idempotent; origin checks, CSRF and client registration');
  for(const path of ['/portal/security','/portal/apps','/portal/members','/portal/connections','/portal/profile']){
    const page=await request(path);assert.equal(page.status,200);assert.equal(page.headers.get('cache-control'),'no-store');
  }

  const walletEntry=await request('/wallet/login');
  assert.equal(walletEntry.status,303);
  assert.equal(walletEntry.headers.get('location'),'/portal');
  const copiedEntry=await request('/wallet/login?token=not-a-login-credential',{browser:false});
  assert.equal(copiedEntry.headers.get('location'),'/portal/login');
  const wallet=await request('/portal/wallet');
  assert.equal(wallet.status,200);
  assert.ok(wallet.text.includes('Card issuance needs setup'));
  assert.equal((await request('/portal/wallet/create',{method:'POST',form:{}})).status,403);
  const unconfigured=await request('/portal/wallet/create',{method:'POST',form:{_csrf:csrf}});
  assert.equal(unconfigured.headers.get('location'),'/portal/wallet?result=unavailable');
  const owner=await db.findByEmail('owner@example.invalid');
  assert.equal(await db.getWalletPass(owner.id),null);
  assert.equal(await db.claimWalletPass(owner.id),true);
  assert.equal(await db.claimWalletPass(owner.id),false);
  await db.completeWalletPass(owner.id,{serialNumber:'test-pass',googleSaveUrl:'https://pay.google.com/gp/v/save/test-owner-only',shareUrl:null});
  assert.equal(await db.claimWalletPass(owner.id),false);
  assert.ok((await request('/portal/wallet')).text.includes('Add to Google Wallet'));
  const member=await db.createUser('Another member','member@example.invalid',randomBytes(32).toString('base64url'));
  assert.equal(await db.getWalletPass(member.id),null);
  assert.equal(await db.claimWalletPass(member.id),true);
  await db.failWalletPass(member.id,'creation_uncertain',true);
  assert.equal(await db.claimWalletPass(member.id),false);
  assert.equal((await db.getWalletPass(member.id)).google_save_url,null);
  console.log('PASS: Wallet shortcut requires a session; pass creation needs CSRF; saved and uncertain requests cannot issue duplicates');

  const authenticator=testAuthenticator(issuer);
  const registrationBody={_csrf:csrf,name:'My test phone',password};
  assert.equal((await request('/portal/passkeys/register/options',{method:'POST',json:{...registrationBody,_csrf:'wrong'}})).status,403);
  assert.equal((await request('/portal/passkeys/register/options',{method:'POST',json:{...registrationBody,password:'incorrect-test-password'}})).status,401);
  let options=JSON.parse((await request('/portal/passkeys/register/options',{method:'POST',json:registrationBody})).text);
  assert.equal(options.authenticatorSelection.userVerification,'required');
  assert.equal(options.authenticatorSelection.residentKey,'required');
  assert.equal((await request('/portal/passkeys/register/verify',{method:'POST',json:{_csrf:csrf,credential:authenticator.register(options,{wrongOrigin:true})}})).status,400);
  assert.equal((await db.listPasskeys(owner.id)).length,0);
  options=JSON.parse((await request('/portal/passkeys/register/options',{method:'POST',json:registrationBody})).text);
  const registrationCredential=authenticator.register(options);
  assert.equal((await request('/portal/passkeys/register/verify',{method:'POST',json:{_csrf:csrf,credential:registrationCredential}})).status,200);
  assert.equal((await request('/portal/passkeys/register/verify',{method:'POST',json:{_csrf:csrf,credential:registrationCredential}})).status,400,'Registration challenge cannot be replayed');
  assert.equal((await db.listPasskeys(owner.id)).length,1);
  for(const attack of [{badSignature:true},{wrongOrigin:true},{unverified:true}]){
    options=JSON.parse((await request('/portal/passkeys/login/options',{method:'POST',json:{}})).text);
    assert.equal((await request('/portal/passkeys/login/verify',{method:'POST',json:{credential:authenticator.authenticate(options,attack)}})).status,400);
  }
  options=JSON.parse((await request('/portal/passkeys/login/options',{method:'POST',json:{}})).text);
  const signedCredential=authenticator.authenticate(options);
  assert.equal((await request('/portal/passkeys/login/verify',{method:'POST',json:{credential:signedCredential}})).status,200);
  assert.equal((await request('/portal/passkeys/login/verify',{method:'POST',json:{credential:signedCredential}})).status,400,'Authentication challenge cannot be replayed');
  options=JSON.parse((await request('/portal/passkeys/login/options',{method:'POST',json:{}})).text);
  assert.equal((await request('/portal/passkeys/login/verify',{method:'POST',json:{credential:authenticator.authenticate(options,{counter:1})}})).status,400,'Non-increasing credential counters are rejected');
  csrf=(await request('/portal')).text.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf);
  const memberToken=await db.createDashboardSession(member.id,'Firefox/100 Android');
  const memberHeaders={Cookie:`hb_portal=${memberToken}`,Origin:issuer};
  const memberSecurity=await request('/portal/security',{browser:false,headers:{...memberHeaders}});
  assert.equal(memberSecurity.status,200);assert.ok(!memberSecurity.text.includes('My test phone'));
  const memberCsrf=memberSecurity.text.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.equal((await request('/portal/members',{browser:false,headers:{...memberHeaders}})).status,403);
  assert.equal((await request('/portal/apps',{method:'POST',form:{_csrf:memberCsrf,name:'Unapproved website',redirect_uri:'https://untrusted.example/callback'},browser:false,headers:{...memberHeaders}})).status,403);
  assert.ok(!(await request('/portal',{browser:false,headers:{...memberHeaders}})).text.includes('owner@example.invalid'),'Member overview does not expose the directory');
  const ownerSession=(await db.listPortalSessions(owner.id,'')).find(s=>!s.is_current);
  await request('/portal/sessions/revoke',{method:'POST',form:{_csrf:memberCsrf,session_id:ownerSession.session_id},browser:false,headers:{...memberHeaders}});
  assert.equal((await request('/portal')).status,200,'A member cannot revoke another account’s session');
  console.log('PASS: real signed passkey registration/login; bad signatures, origins, UV, counters and challenge replay rejected; member data isolated');

  const verifier=randomBytes(32).toString('base64url');
  const state=randomBytes(16).toString('base64url');
  const nonce=randomBytes(16).toString('base64url');
  const params={client_id:client.client_id,redirect_uri:client.redirect_uris[0],response_type:'code',scope:'openid profile email',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'};
  const rejected=await request(`${discovery.authorization_endpoint}?${new URLSearchParams({...params,redirect_uri:'https://untrusted.example/callback'})}`);
  assert.equal(rejected.status,400);
  assert.equal(rejected.headers.get('location'),null);
  let result=await follow(await request(`${discovery.authorization_endpoint}?${new URLSearchParams(params)}`));
  assert.equal(result.status,200);
  assert.equal(result.headers.get('referrer-policy'),'same-origin','OIDC login form preserves the origin too');
  const loginAction=result.text.match(/action="(\/interaction\/[^\"]+\/login)"/)?.[1];
  assert.ok(loginAction,'Authorization shows HB ID login');
  result=await follow(await request(loginAction,{method:'POST',form:{email:'owner@example.invalid',password}}));
  assert.equal(result.status,200);
  assert.equal(result.headers.get('referrer-policy'),'same-origin','OIDC consent form preserves the origin too');
  const consentAction=result.text.match(/action="(\/interaction\/[^\"]+\/confirm)"/)?.[1];
  assert.ok(consentAction,'Client access requires consent');
  result=await follow(await request(consentAction,{method:'POST',form:{}}));
  assert.ok(result.callback,'Authorization returns to the approved website');
  assert.equal(result.callback.searchParams.get('state'),state);
  const code=result.callback.searchParams.get('code');
  assert.ok(code,'Authorization code issued');
  const tokenForm={grant_type:'authorization_code',redirect_uri:client.redirect_uris[0],code,code_verifier:verifier};
  const basic={Authorization:`Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}`};
  const exchange=await request(discovery.token_endpoint,{method:'POST',form:tokenForm,headers:basic,browser:false});
  assert.equal(exchange.status,200,'Code exchange should succeed');
  const token=JSON.parse(exchange.text);
  assert.ok(token.access_token && token.id_token,'Both OIDC tokens returned');
  const [headerPart,payloadPart,signature]=token.id_token.split('.');
  const header=JSON.parse(Buffer.from(headerPart,'base64url'));
  const claims=JSON.parse(Buffer.from(payloadPart,'base64url'));
  assert.equal(header.alg,'RS256');
  const jwk=keysBefore.keys.find(k=>k.kid===header.kid);
  assert.ok(verify('RSA-SHA256',Buffer.from(`${headerPart}.${payloadPart}`),createPublicKey({key:jwk,format:'jwk'}),Buffer.from(signature,'base64url')),'ID token signature validates');
  assert.equal(claims.iss,issuer); assert.equal(claims.aud,client.client_id); assert.equal(claims.nonce,nonce);
  assert.ok(claims.exp>Date.now()/1000);
  const info=await request(discovery.userinfo_endpoint,{headers:{Authorization:`Bearer ${token.access_token}`},browser:false});
  assert.equal(info.status,200);
  const userinfo=JSON.parse(info.text);
  assert.equal(userinfo.sub,claims.sub); assert.equal(userinfo.name,'HB ID Owner');
  assert.equal(userinfo.email,undefined); assert.equal(userinfo.email_verified,false);
  console.log('PASS: Authorization Code + PKCE, consent, signed ID token and UserInfo');

  result=await follow(await request(`${discovery.authorization_endpoint}?${new URLSearchParams({...params,prompt:'login',state:randomBytes(16).toString('base64url')})}`));
  const passkeyBase=result.text.match(/data-base="(\/interaction\/[^\"]+\/passkeys)"/)?.[1];
  assert.ok(passkeyBase,'OIDC sign-in offers passkeys');
  options=JSON.parse((await request(passkeyBase+'/options',{method:'POST',json:{}})).text);
  const passkeyResult=await request(passkeyBase+'/verify',{method:'POST',json:{credential:authenticator.authenticate(options,{counter:2})}});
  assert.equal(passkeyResult.status,200);
  result=await follow(await request(JSON.parse(passkeyResult.text).redirect));
  assert.ok(result.callback?.searchParams.get('code'),'Passkey login completes the OIDC redirect flow');
  assert.ok((await db.listAuthorizedApps(owner.id)).some(a=>a.id===client.client_id));
  console.log('PASS: passkey sign-in works inside an OIDC website interaction');

  const newAuthorization=()=>request(`${discovery.authorization_endpoint}?${new URLSearchParams({...params,state:randomBytes(16).toString('base64url')})}`);
  result=await follow(await newAuthorization());
  assert.ok(result.callback?.searchParams.get('code'),'Existing identity session supports SSO');
  app=(await import('../src/server.mjs?restart')).default;
  assert.deepEqual(JSON.parse((await request(discovery.jwks_uri)).text),keysBefore);
  assert.equal((await request('/portal')).status,200);
  result=await follow(await newAuthorization());
  assert.ok(result.callback?.searchParams.get('code'),'OIDC session survives a new provider instance');
  console.log('PASS: signing keys, portal session and SSO persist across provider restarts');
  const wrongVerifier=await request(discovery.token_endpoint,{method:'POST',form:{...tokenForm,code:result.callback.searchParams.get('code'),code_verifier:randomBytes(32).toString('base64url')},headers:basic,browser:false});
  assert.equal(wrongVerifier.status,400); assert.equal(JSON.parse(wrongVerifier.text).error,'invalid_grant');
  const replay=await request(discovery.token_endpoint,{method:'POST',form:tokenForm,headers:basic,browser:false});
  assert.equal(replay.status,400); assert.equal(JSON.parse(replay.text).error,'invalid_grant');
  console.log('PASS: wrong PKCE and authorization code replay rejected');
  assert.equal((await request('/portal/profile',{method:'POST',form:{_csrf:csrf,name:'Updated owner'}})).status,303);
  assert.ok((await request('/portal/profile')).text.includes('Updated owner'));
  const otherToken=await db.createDashboardSession(owner.id,'Chrome/130 Android');
  const otherSession=(await db.listPortalSessions(owner.id,otherToken)).find(s=>s.is_current);
  assert.equal((await request('/portal/sessions/revoke',{method:'POST',form:{_csrf:csrf,session_id:otherSession.session_id}})).status,303);
  assert.equal(await db.getDashboardSession(otherToken),null);
  const ownerGrantId='test-owner-revoke',memberGrantId='test-member-keep';
  await new db.PostgresOidcAdapter('Grant').upsert(ownerGrantId,{accountId:String(owner.id),clientId:client.client_id},300);
  await new db.PostgresOidcAdapter('Grant').upsert(memberGrantId,{accountId:String(member.id),clientId:client.client_id},300);
  await new db.PostgresOidcAdapter('AccessToken').upsert('test-revoked-access',{grantId:ownerGrantId,accountId:String(owner.id)},300);
  assert.equal((await db.listAuthorizedApps(owner.id)).length,1);
  await request('/portal/connections/revoke',{method:'POST',form:{_csrf:csrf,client_id:client.client_id}});
  assert.equal((await db.listAuthorizedApps(owner.id)).length,0);
  assert.equal((await db.listAuthorizedApps(member.id)).length,1,'Disconnect affects only the signed-in member');
  assert.equal(await new db.PostgresOidcAdapter('AccessToken').find('test-revoked-access'),undefined);
  assert.equal((await request('/portal/passkeys/remove',{method:'POST',form:{_csrf:csrf,id:authenticator.id,password}})).status,303);
  assert.equal((await db.listPasskeys(owner.id)).length,0);
  console.log('PASS: profile updates, session sign-out, connection revocation and passkey removal persist');
  console.log('HB ID integration checks passed.');
} catch(error) {
  console.error(`HB ID integration failed: ${error.message}`);
  console.error(error.stack?.split('\n').find(line=>line.includes('test/integration.mjs'))||'');
  process.exitCode=1;
} finally {
  server.closeAllConnections();
  await new Promise(resolve=>server.close(resolve));
  await db?.pool.end();
}
