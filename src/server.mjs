import express from 'express';
import helmet from 'helmet';
import {createHmac} from 'node:crypto';
import { Provider } from 'oidc-provider';
import { initDatabase, getOrMakeKeys, PostgresOidcAdapter, findByEmail, findById, verifyPassword,
  createClient, listClients, listUsers, createUser, createDashboardSession, getDashboardSession,
  deleteDashboardSession, getWalletPass, claimWalletPass, completeWalletPass, failWalletPass,
  listPasskeys,listPortalSessions,revokePortalSession,updateProfile,listAuthorizedApps,revokeAuthorizedApp,
  authenticatePassword,consumeAuthLimit,clearAuthLimit,recordSecurityEvent,listSecurityEvents } from './db.mjs';
import { home, portalLogin, interactionLogin, interactionConsent, errorPage, setupPending, walletPage, informationPage } from './ui.mjs';
import {portal} from './dashboard.mjs';
import {installPasskeyRoutes} from './passkeys.mjs';
import { createWalletPass, getWalletUsage, WalletServiceError } from './wallet.mjs';
import { resetPasswordWithToken } from './db.mjs';
import { passwordReset } from './ui.mjs';
import {installEmailAccountRoutes} from './enrollment.mjs';
import {emailSettings} from './email.mjs';

const ISSUER=(process.env.ISSUER||process.env.URL||'').trim().replace(/\/$/,'');
if (!ISSUER) throw new Error('Set ISSUER to your exact public HTTPS URL');
const issuerUrl=new URL(ISSUER);
if (issuerUrl.pathname !== '/' || issuerUrl.search || issuerUrl.hash || (issuerUrl.protocol!=='https:' && !(issuerUrl.protocol==='http:' && ['localhost','127.0.0.1'].includes(issuerUrl.hostname)))) {
  throw new Error('ISSUER must be a root-level HTTPS URL, except for localhost development');
}
const PORT=Number(process.env.PORT||3000);
const databaseConfigured = Boolean(process.env.DATABASE_URL);
const ownerReady = databaseConfigured ? await initDatabase() : false;
const identityKeys = databaseConfigured ? await getOrMakeKeys() : null;
const provider=identityKeys ? new Provider(ISSUER,{
  clients: [],
  adapter: PostgresOidcAdapter,
  jwks: {keys: identityKeys.signingKeys},
  cookies: {keys: identityKeys.cookieKeys},
  interactions: {url(ctx,interaction){return `/interaction/${interaction.uid}`;}},
  features: {devInteractions:{enabled:false}, revocation:{enabled:true}},
  claims: {openid:['sub'],email:['email','email_verified'],profile:['name']},
  async findAccount(ctx,id){
    const account=await findById(id);
    if(!account) return undefined;
    return {accountId:String(account.id),async claims(){return {sub:String(account.id),name:account.name,
      // Never expose an unverified email as a verified identity claim.
      ...(account.email_verified?{email:account.email,email_verified:true}:{email_verified:false})};}};
  }
}) : null;
if(provider)provider.proxy=true;
const app=express();
app.disable('x-powered-by');
app.set('trust proxy',1);
// Helmet's no-referrer default turns ordinary form POST origins into "null".
// Preserve the origin for HB ID forms while withholding referrers from other sites.
app.use(helmet({referrerPolicy:{policy:'same-origin'},frameguard:{action:'deny'},
  strictTransportSecurity:{maxAge:31536000,includeSubDomains:false},
  contentSecurityPolicy:{directives:{'default-src':["'self'"],'script-src':["'self'"],
    'script-src-attr':["'none'"],'style-src':["'self'"],'style-src-attr':["'none'"],
    'connect-src':["'self'"],'font-src':["'self'"],'img-src':["'self'",'data:'],
    'object-src':["'none'"],'base-uri':["'none'"],'frame-ancestors':["'none'"],
    'form-action':["'self'"],'upgrade-insecure-requests':issuerUrl.protocol==='https:'?[]:null}}}));
app.use((_req,res,next)=>{res.set('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=(), publickey-credentials-get=(self), publickey-credentials-create=(self)');next();});
app.use(['/portal','/interaction'],(_req,res,next)=>{res.set('Cache-Control','no-store');next();});
// Keep hosted UI on the issuer that owns its cookies and WebAuthn credentials.
// An alternate deployment URL must never become an extra trusted form origin.
app.use((req,res,next)=>{
  if(process.env.VERCEL&&issuerUrl.protocol==='https:'&&['GET','HEAD'].includes(req.method)&&
    (req.path==='/'||req.path==='/portal'||req.path.startsWith('/portal/')||req.path==='/wallet/login')&&req.hostname!==issuerUrl.hostname){
    res.set('Cache-Control','no-store');return res.redirect(307,ISSUER+req.originalUrl);
  }
  next();
});
app.use('/portal',express.urlencoded({extended:false,limit:'16kb'}));
app.use('/interaction',express.urlencoded({extended:false,limit:'16kb'}));
app.use(['/portal','/interaction'],express.json({limit:'64kb'}));
app.use(express.static(new URL('../public/',import.meta.url).pathname,{fallthrough:true,maxAge:'1h'}));
const secureCookie=issuerUrl.protocol==='https:';
function html(res,contents,status=200){res.status(status).type('html').send(contents);}
function jsonRequest(req){return Boolean(req.is('application/json')||req.get('accept')?.includes('application/json'));}
function requestError(req,res,title,message,status){
  if(jsonRequest(req))return res.status(status).json({error:message});
  return html(res,errorPage(title,message,status),status);
}
function cookies(req){
  const values={};
  for(const part of (req.headers.cookie||'').split(';')){
    const match=/^\s*([^=\s]+)=(.*)$/.exec(part);if(!match)continue;
    try{values[match[1]]=decodeURIComponent(match[2]);}catch{/* Ignore malformed cookies. */}
  }
  if(secureCookie){values.hb_portal=values['__Host-hb_portal'];values.hb_passkey=values['__Host-hb_passkey'];}
  return values;
}
function originGuard(req,res,next){
  const origin=req.get('origin');
  // Older browsers can omit Origin. Accept only an exact trusted Referer
  // in that case; never override an explicitly foreign Origin.
  let trusted=origin===issuerUrl.origin;
  if(!origin||origin==='null'){
    try{trusted=new URL(req.get('referer')).origin===issuerUrl.origin;}catch{trusted=false;}
  }
  if(req.get('sec-fetch-site')==='cross-site')trusted=false;
  if(!trusted)return requestError(req,res,'Request blocked','Please reopen HB ID from its sign-in page and try again.',403);
  next();
}
const limitKey=value=>createHmac('sha256',identityKeys.cookieKeys[0]).update(value).digest('hex');
async function rateLimit(req,res,next){
  const route=req.path.replace(/^\/interaction\/[^/]+/,'/interaction');
  req.rateLimitKeys=[limitKey(`ip:${req.ip||'unknown'}:${route}`)];
  if(typeof req.body?.email==='string')req.rateLimitKeys.push(limitKey(`account:${req.body.email.trim().toLowerCase()}:${route}`));
  let allowed=true;
  for(const [index,key] of req.rateLimitKeys.entries())if(!await consumeAuthLimit(key,index===0?8:20))allowed=false;
  if(!allowed){res.set('Retry-After','900');return requestError(req,res,'Too many attempts','Too many attempts. Wait 15 minutes before trying again.',429);}
  next();
}
const clearRateLimit=async req=>{for(const key of req.rateLimitKeys||[])await clearAuthLimit(key);};
const portalCookieName=secureCookie?'__Host-hb_portal':'hb_portal';
function setPortalCookie(res,token){if(secureCookie)res.clearCookie('hb_portal',{path:'/'});res.cookie(portalCookieName,token,{httpOnly:true,secure:secureCookie,sameSite:'lax',path:'/',maxAge:12*3600*1000});}
function clearPortalCookie(res){res.clearCookie(portalCookieName,{httpOnly:true,secure:secureCookie,sameSite:'lax',path:'/'});}
async function requirePortal(req,res,next){
  const user=await getDashboardSession(cookies(req).hb_portal);
  if(!user){if(jsonRequest(req))return res.status(401).json({error:'Your session expired. Please sign in again.',redirect:'/portal/login'});return res.redirect('/portal/login');}
  req.portalSession=user;next();
}
function requireAdmin(req,res,next){if(!req.portalSession?.is_admin)return requestError(req,res,'Admin access required','Only the platform administrator can manage applications and accounts.',403);next();}
function csrfGuard(req,res,next){if(!req.portalSession||!req.body?._csrf||req.body._csrf!==req.portalSession.csrf)return requestError(req,res,'Security check failed','Please reopen the portal page and try again.',403);next();}
async function confirmOwnerPassword(req,res,next){
  const account=await findByEmail(req.portalSession.email);
  if(!account||!await verifyPassword(req.body?.current_password,account.password_hash)){
    await recordSecurityEvent(req.portalSession.id,'owner_check_failed');
    return requestError(req,res,'Confirm your password','Enter your current HB ID password to approve this owner action.',401);
  }
  await clearRateLimit(req);next();
}
function validRedirect(input){
  try{
    const u=new URL(String(input||''));
    if(u.username||u.password||u.hash||u.search.length>2000||u.href.length>2048||input.includes('*'))return false;
    if(u.protocol==='https:')return true;
    return u.protocol==='http:' && ['localhost','127.0.0.1'].includes(u.hostname);
  }catch{return false;}
}
async function renderPortal(req,res,{message='',error='',created=null,view}={}){
  const session=req.portalSession;
  const [apps,users,passkeys,sessions,connections,pass,events]=await Promise.all([
    session.is_admin?listClients():[],session.is_admin?listUsers():[],listPasskeys(session.id),
    listPortalSessions(session.id,cookies(req).hb_portal),listAuthorizedApps(session.id),getWalletPass(session.id),listSecurityEvents(session.id)]);
  const results={'profile-saved':'Your profile has been saved.','session-revoked':'That portal session has been signed out.',
    'app-disconnected':'Website permission removed. It will need your consent again.','passkey-added':'Your passkey is ready. Use it next time you sign in.',
    'passkey-removed':'Passkey removed from HB ID.'};
  const selected=view||req.path.split('/')[2]||'overview';
  res.set('Cache-Control','no-store');
  html(res,portal({session,apps,users,passkeys,sessions,connections,pass,events,created,issuer:ISSUER,view:selected,
    mailConfigured:emailSettings().ready,message:message||results[req.query.result]||'',error:error||(req.query.result==='password-incorrect'?'Your current password is incorrect.':'')}));
}
app.get('/healthz', (_req,res)=>res.status(200).json({ok:true,ready:ownerReady}));
app.get('/readyz', (_req,res)=>res.status(ownerReady?200:503).json({ready:ownerReady}));
app.get('/', (_req,res)=>html(res,home({issuer:ISSUER})));
app.get(['/about','/privacy','/security'],(req,res)=>html(res,informationPage(req.path.slice(1))));
app.get('/.well-known/security.txt',(_req,res)=>res.type('text/plain').send(`Contact: mailto:haidermalik@devolper.online\nExpires: 2027-04-22T00:00:00Z\nPreferred-Languages: en\nCanonical: ${ISSUER}/.well-known/security.txt\nPolicy: ${ISSUER}/security\n`));
// Only the hosting account owner can seed an administrator through private env vars.
// There is deliberately no public first-user enrollment route.
app.use((_req,res,next)=>{
  if(ownerReady)return next();
  res.set('Cache-Control','no-store');
  if(jsonRequest(_req))return res.status(503).json({error:'HB ID is temporarily unavailable. Please try again shortly.'});
  return html(res,setupPending(),503);
});
app.get('/portal/login', async(req,res)=>{
  if(await getDashboardSession(cookies(req).hb_portal))return res.redirect('/portal');
  html(res,portalLogin());
});
installEmailAccountRoutes(app,{issuer:ISSUER,originGuard,rateLimit});
app.get('/portal/reset-password',(_req,res)=>html(res,passwordReset()));
app.post('/portal/reset-password',originGuard,rateLimit,async(req,res)=>{
  const password=req.body?.password;
  if(typeof password!=='string'||password.length<14||password.length>200||password!==req.body?.confirm){
    return res.status(400).json({error:'Use matching passwords of 14–200 characters.'});
  }
  const ok=await resetPasswordWithToken(req.body?.token,password);
  if(!ok)return res.status(400).json({error:'This recovery link is invalid, expired, or already used. Request a new one from Forgot password.'});
  clearPortalCookie(res);await clearRateLimit(req);
  return res.json({ok:true});
});
app.post('/portal/login',originGuard,rateLimit,async(req,res)=>{
  const account=await authenticatePassword(req.body.email,req.body.password);
  if(!account){await recordSecurityEvent(null,'sign_in_failed');return html(res,portalLogin('Invalid email or password.'),401);}
  if(!await finishPortalLogin(req,res,account.id,{passwordHash:account.password_hash}))return html(res,portalLogin('Please sign in again.'),401);
  await clearRateLimit(req);await recordSecurityEvent(account.id,'password_sign_in');
  res.redirect(303,'/portal');
});
async function finishPortalLogin(req,res,userId,credential={}){
  const token=await createDashboardSession(userId,req.get('user-agent')||'',credential);
  if(!token)return false;
  await deleteDashboardSession(cookies(req).hb_portal);
  setPortalCookie(res,token);return true;
}
installPasskeyRoutes(app,{issuerUrl,originGuard,requirePortal,csrfGuard,rateLimit,clearRateLimit,cookies,provider,finishPortalLogin});
app.get('/portal',requirePortal,async(req,res)=>renderPortal(req,res));
app.get(['/portal/apps','/portal/members'],requirePortal,requireAdmin,async(req,res)=>renderPortal(req,res));
app.get(['/portal/security','/portal/profile','/portal/connections'],requirePortal,async(req,res)=>renderPortal(req,res));
app.post('/portal/profile',originGuard,requirePortal,csrfGuard,async(req,res)=>{
  const name=String(req.body.name||'').trim();
  if(name.length<2||name.length>100)return renderPortal(req,res,{view:'profile',error:'Enter a display name of 2–100 characters.'});
  await updateProfile(req.portalSession.id,name);res.redirect(303,'/portal/profile?result=profile-saved');
});
app.post('/portal/sessions/revoke',originGuard,requirePortal,csrfGuard,async(req,res)=>{
  await revokePortalSession(req.portalSession.id,String(req.body.session_id||''));
  res.redirect(303,'/portal/security?result=session-revoked');
});
app.post('/portal/connections/revoke',originGuard,requirePortal,csrfGuard,async(req,res)=>{
  await revokeAuthorizedApp(req.portalSession.id,String(req.body.client_id||''));
  res.redirect(303,'/portal/connections?result=app-disconnected');
});
app.get('/wallet/login',async(req,res)=>{
  res.set('Cache-Control','no-store');
  // The QR has no account identifier or login token. Only the browser session counts.
  const session=await getDashboardSession(cookies(req).hb_portal);
  res.redirect(303,session?'/portal':'/portal/login');
});
app.get('/portal/wallet',requirePortal,async(req,res)=>{
  res.set('Cache-Control','no-store');
  let connection=null;
  if(process.env.WALLETWALLET_API_KEY){
    try{connection={status:'connected',...await getWalletUsage({timeoutMs:5000})};}
    catch(error){connection={status:error instanceof WalletServiceError?error.code:'provider_unavailable'};}
  }
  html(res,walletPage({session:req.portalSession,pass:await getWalletPass(req.portalSession.id),
    configured:Boolean(process.env.WALLETWALLET_API_KEY),connection,message:req.query.result==='unavailable'?'Your card could not be created. Check the Wallet status below before trying again.':''}));
});
app.post('/portal/wallet/create',originGuard,requirePortal,csrfGuard,async(req,res)=>{
  res.set('Cache-Control','no-store');
  if(!process.env.WALLETWALLET_API_KEY)return res.redirect(303,'/portal/wallet?result=unavailable');
  const user=req.portalSession;
  if(!await claimWalletPass(user.id))return res.redirect(303,'/portal/wallet');
  let issued;
  try {issued=await createWalletPass(user,{issuer:ISSUER});}
  catch(error){
    const known=error instanceof WalletServiceError;
    await failWalletPass(user.id,known?error.code:'creation_uncertain',known?error.uncertain:true);
    return res.redirect(303,'/portal/wallet?result=unavailable');
  }
  // A failed database save leaves the row pending, preventing duplicate issuance.
  await completeWalletPass(user.id,issued);
  return res.redirect(303,'/portal/wallet');
});
app.post('/portal/logout',originGuard,requirePortal,csrfGuard,async(req,res)=>{
  await deleteDashboardSession(cookies(req).hb_portal);clearPortalCookie(res);res.redirect(303,'/');
});
app.post('/portal/apps',originGuard,requirePortal,requireAdmin,csrfGuard,rateLimit,confirmOwnerPassword,async(req,res)=>{
  const name=String(req.body.name||'').trim();
  const redirect=String(req.body.redirect_uri||'').trim();
  if(name.length<2||name.length>90)return renderPortal(req,res,{view:'apps',error:'Application name must be 2–90 characters.'});
  if(!validRedirect(redirect))return renderPortal(req,res,{view:'apps',error:'Use a valid HTTPS callback URL. Only localhost may use HTTP for testing.'});
  const created=await createClient(name,redirect);
  await recordSecurityEvent(req.portalSession.id,'website_created');
  return renderPortal(req,res,{view:'apps',created,message:`${name} has been registered. Copy the client secret now.`});
});
app.post('/portal/users',originGuard,requirePortal,requireAdmin,csrfGuard,rateLimit,confirmOwnerPassword,async(req,res)=>{
  const name=String(req.body.name||'').trim();
  const email=String(req.body.email||'').trim().toLowerCase();
  const password=String(req.body.password||'');
  if(name.length<2||name.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<14||password.length>200){
    return renderPortal(req,res,{view:'members',error:'Enter a valid name, email and unique password of 14–200 characters.'});
  }
  try{await createUser(name,email,password);await recordSecurityEvent(req.portalSession.id,'member_created');return renderPortal(req,res,{view:'members',message:`Account created for ${name}. Give the temporary password to that person privately.`});}
  catch(e){if(e.code==='23505')return renderPortal(req,res,{view:'members',error:'An account already exists for that email.'});throw e;}
});
// oidc-provider uses signed cookies to bind the interaction to its authorization request.
app.get('/interaction/:uid',async(req,res)=>{
  const details=await provider.interactionDetails(req,res);
  if(details.uid!==req.params.uid)return html(res,errorPage('Invalid interaction','This sign-in attempt is no longer valid.',400),400);
  const client=await provider.Client.find(details.params.client_id);
  const clientName=client?.clientName||details.params.client_id||'Unknown app';
  res.set('Cache-Control','no-store');
  if(details.prompt.name==='login')return html(res,interactionLogin({clientName,uid:details.uid,email:details.params.login_hint||''}));
  if(details.prompt.name==='consent')return html(res,interactionConsent({clientName,uid:details.uid,scopes:details.params.scope?.split(/\s+/).filter(Boolean)||[]}));
  return html(res,errorPage('Unsupported request','This authorization action is not available.',400),400);
});
app.post('/interaction/:uid/login',originGuard,rateLimit,async(req,res)=>{
  const details=await provider.interactionDetails(req,res);
  if(details.uid!==req.params.uid||details.prompt.name!=='login')return html(res,errorPage('Invalid login flow','Please restart the sign-in.',400),400);
  const user=await authenticatePassword(req.body.email,req.body.password);
  if(!user){
    await recordSecurityEvent(null,'sign_in_failed');
    const client=await provider.Client.find(details.params.client_id);
    return html(res,interactionLogin({clientName:client?.clientName||'the website',uid:details.uid,error:'Invalid email or password.',email:String(req.body.email||'').slice(0,250)}),401);
  }
  await clearRateLimit(req);await recordSecurityEvent(user.id,'password_sign_in');
  await provider.interactionFinished(req,res,{login:{accountId:String(user.id)}},{mergeWithLastSubmission:false});
});
app.post('/interaction/:uid/confirm',originGuard,async(req,res)=>{
  const details=await provider.interactionDetails(req,res);
  if(details.uid!==req.params.uid||details.prompt.name!=='consent')return html(res,errorPage('Invalid consent flow','Please restart the sign-in.',400),400);
  const {prompt:{details:missing},params,session}=details;
  if(!session?.accountId)return html(res,errorPage('Session expired','Please sign in again.',401),401);
  let grantId=details.grantId;
  let grant=grantId?await provider.Grant.find(grantId):new provider.Grant({accountId:session.accountId,clientId:params.client_id});
  if(!grant)grant=new provider.Grant({accountId:session.accountId,clientId:params.client_id});
  if(missing.missingOIDCScope?.length)grant.addOIDCScope(missing.missingOIDCScope.join(' '));
  if(missing.missingOIDCClaims?.length)grant.addOIDCClaims(missing.missingOIDCClaims);
  if(missing.missingResourceScopes){for(const [resource,scopes] of Object.entries(missing.missingResourceScopes))grant.addResourceScope(resource,scopes.join(' '));}
  grantId=await grant.save();
  const consent=details.grantId?{}:{grantId};
  await provider.interactionFinished(req,res,{consent},{mergeWithLastSubmission:true});
});
app.post('/interaction/:uid/abort',originGuard,async(req,res)=>{
  const details=await provider.interactionDetails(req,res);
  if(details.uid!==req.params.uid)return html(res,errorPage('Invalid sign-in','Restart the sign-in from your website.',400),400);
  await provider.interactionFinished(req,res,{error:'access_denied',error_description:'The user cancelled sign-in.'},{mergeWithLastSubmission:false});
});
if(provider)app.use(provider.callback());
app.use((err,req,res,next)=>{
  if(res.headersSent)return next(err);
  if(err?.type==='entity.parse.failed')return requestError(req,res,'Invalid request','This request could not be read. Refresh HB ID and try again.',400);
  if(err?.type==='entity.too.large')return requestError(req,res,'Request too large','This request is too large. Please try again.',413);
  console.error('HB ID request error:',/^[A-Z0-9_]{2,40}$/.test(err?.code||'')?err.code:'SERVER_ERROR');
  return requestError(req,res,'Request failed','Please retry. If the problem continues, contact the HB ID administrator.',500);
});
// Serverless hosts import the app; traditional Node.js hosts use npm start.
if (process.env.HB_ID_SERVERLESS !== 'true' && process.env.NETLIFY !== 'true' && !process.env.VERCEL) {
  app.listen(PORT,'0.0.0.0',()=>console.log(`HB ID provider listening on port ${PORT} with issuer ${ISSUER}`));
}
export default app;
