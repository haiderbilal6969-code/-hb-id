// Independent demo website: real OIDC Authorization Code flow + PKCE + state + nonce.
// Deploy separately from HB ID. Prototype sessions are in memory; replace them for production.
import express from 'express';
import { randomBytes, createHash } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const ISSUER=(process.env.HB_ID_ISSUER||'').replace(/\/$/,'');
const CLIENT_ID=process.env.HB_ID_CLIENT_ID;
const CLIENT_SECRET=process.env.HB_ID_CLIENT_SECRET;
const BASE=(process.env.CLIENT_BASE_URL||'http://localhost:4000').replace(/\/$/,'');
const REDIRECT=`${BASE}/auth/callback`;
if(!ISSUER||!CLIENT_ID||!CLIENT_SECRET) throw new Error('Set HB_ID_ISSUER, HB_ID_CLIENT_ID and HB_ID_CLIENT_SECRET');
const metadataResponse=await fetch(`${ISSUER}/.well-known/openid-configuration`);
if(!metadataResponse.ok)throw new Error('OIDC discovery failed');
const metadata=await metadataResponse.json();
if(metadata.issuer!==ISSUER)throw new Error('Issuer mismatch');
const jwks=createRemoteJWKSet(new URL(metadata.jwks_uri));
const app=express();app.disable('x-powered-by');app.set('trust proxy',1);
const sessions=new Map();
const rand=()=>randomBytes(32).toString('base64url');
const hash=x=>createHash('sha256').update(x).digest('base64url');
const htmlEscape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const secure=BASE.startsWith('https:');
function sid(req){return (req.headers.cookie||'').split(';').map(c=>c.trim()).find(c=>c.startsWith('site_sid='))?.slice(9);}
function getSession(req){const id=sid(req);return id&&sessions.get(id);}
function page(content){return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>My Connected Website</title><style>body{background:#101a29;color:#ecf6fe;font-family:Tahoma,Arial,sans-serif;margin:0;padding:25px;display:grid;place-items:center;min-height:90vh}.panel{background:#17283a;border:1px solid #3c5265;border-radius:22px;max-width:400px;width:100%;padding:30px}a{display:block;background:#a4f5ce;padding:14px;border-radius:11px;color:#08372f;text-align:center;font-weight:bold;text-decoration:none;margin-top:25px}p{color:#adc0cf;line-height:1.8;font-size:13px}</style></head><body><div class="panel"><h2>Sample Partner Website</h2>${content}</div></body></html>`;}
app.get('/',(req,res)=>{const user=getSession(req)?.user;res.set('Cache-Control','no-store');res.send(page(user?`<h1>Signed in ✓</h1><p>Hello, ${htmlEscape(user.name||user.sub)}. Authenticated by HB ID with verified OIDC ID token.</p><p>Subject ID: ${htmlEscape(user.sub)}</p><a href="/logout">Sign out of this website</a>`:`<h1>Welcome</h1><p>This is a separate website that uses your HB ID provider to authenticate users. It never receives the HB ID password.</p><a href="/login">◈ Continue with HB ID →</a>`));});
app.get('/login',(req,res)=>{
  const id=rand(); const state=rand(); const verifier=rand(); const nonce=rand();
  sessions.set(id,{state,verifier,nonce,created:Date.now()});
  res.cookie('site_sid',id,{httpOnly:true,secure,sameSite:'lax',maxAge:15*60*1000});
  const u=new URL(metadata.authorization_endpoint);
  u.searchParams.set('response_type','code');u.searchParams.set('client_id',CLIENT_ID);
  u.searchParams.set('redirect_uri',REDIRECT);u.searchParams.set('scope','openid profile email');
  u.searchParams.set('state',state);u.searchParams.set('nonce',nonce);
  u.searchParams.set('code_challenge_method','S256');u.searchParams.set('code_challenge',hash(verifier));
  res.redirect(u.toString());
});
app.get('/auth/callback',async(req,res)=>{
  const id=sid(req);const sess=getSession(req);
  if(!sess||Date.now()-sess.created>15*60*1000||!req.query.state||req.query.state!==sess.state||typeof req.query.code!=='string')return res.status(400).send(page('<p>Invalid, expired or cancelled sign-in. Return home and retry.</p><a href="/">Home</a>'));
  try{
    // One-time callback state; block code replay attempts through the browser session.
    delete sess.state;
    const resp=await fetch(metadata.token_endpoint,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',
      Authorization:'Basic '+Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')},
      body:new URLSearchParams({grant_type:'authorization_code',code:req.query.code,redirect_uri:REDIRECT,code_verifier:sess.verifier})});
    if(!resp.ok)throw new Error('Token exchange rejected');
    const data=await resp.json();if(!data.id_token)throw new Error('No identity token returned');
    const {payload}=await jwtVerify(data.id_token,jwks,{issuer:ISSUER,audience:CLIENT_ID,algorithms:['RS256']});
    if(payload.nonce!==sess.nonce)throw new Error('Nonce mismatch');
    sess.user={sub:payload.sub,name:payload.name||payload.sub};
    delete sess.verifier;delete sess.nonce;
    res.redirect(303,'/');
  }catch(err){console.error('OIDC callback:',err.message);sessions.delete(id);res.clearCookie('site_sid',{httpOnly:true,secure,sameSite:'lax'});res.status(400).send(page('<p>Sign-in failed; please retry.</p><a href="/">Back</a>'));}
});
app.get('/logout',(req,res)=>{const id=sid(req);if(id)sessions.delete(id);res.clearCookie('site_sid',{httpOnly:true,secure,sameSite:'lax'});res.redirect('/');});
app.listen(Number(process.env.PORT||4000),'0.0.0.0',()=>console.log('Connected client running. Redirect URL:',REDIRECT));