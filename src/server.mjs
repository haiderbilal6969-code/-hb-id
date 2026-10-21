import express from 'express';
import helmet from 'helmet';
import { Provider } from 'oidc-provider';
import { initDatabase, getOrMakeKeys, PostgresOidcAdapter, findByEmail, findById, verifyPassword,
  createClient, listClients, listUsers, createUser, createDashboardSession, getDashboardSession,
  deleteDashboardSession, getWalletPass, claimWalletPass, completeWalletPass, failWalletPass } from './db.mjs';
import { home, portal, portalLogin, interactionLogin, interactionConsent, errorPage, setupPending, walletPage } from './ui.mjs';
import { createWalletPass, WalletServiceError } from './wallet.mjs';

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
app.use(helmet({referrerPolicy:{policy:'same-origin'},contentSecurityPolicy:{directives:{'style-src':["'self'","'unsafe-inline'"],'upgrade-insecure-requests':null}}}));
app.use(['/portal','/interaction'],(_req,res,next)=>{res.set('Cache-Control','no-store');next();});
app.use('/portal',express.urlencoded({extended:false,limit:'16kb'}));
app.use('/interaction',express.urlencoded({extended:false,limit:'16kb'}));
app.use(express.static(new URL('../public/',import.meta.url).pathname,{fallthrough:true,maxAge:'1h'}));
const secureCookie=issuerUrl.protocol==='https:';
function html(res,contents,status=200){res.status(status).type('html').send(contents);}
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split(/=(.*)/s).slice(0,2)).filter(x=>x[0]).map(([k,v])=>[k,decodeURIComponent(v||'')]));}
function originGuard(req,res,next){
  const origin=req.get('origin');
  // Older browsers can omit Origin. Accept only an exact trusted Referer
  // in that case; never override an explicitly foreign Origin.
  let trusted=origin===issuerUrl.origin;
  if(!origin||origin==='null'){
    try{trusted=new URL(req.get('referer')).origin===issuerUrl.origin;}catch{trusted=false;}
  }
  if(req.get('sec-fetch-site')==='cross-site')trusted=false;
  if(!trusted){return html(res,errorPage('Request blocked','Please reopen the sign-in page from the HB ID website and try again.',403),403);}
  next();
}
const limiter=new Map();
function rateLimit(req,res,next){
  const key=String(req.ip||'unknown')+':'+req.path.replace(/\/interaction\/[a-z0-9_-]+\/login/i,'/interaction/login');
  const now=Date.now();
  if(limiter.size>5000){for(const [k,v] of limiter){if(now-v.since>900000)limiter.delete(k);}}
  let record=limiter.get(key);
  if(!record||now-record.since>900000){record={since:now,count:0};limiter.set(key,record);}
  record.count++;
  if(record.count>8){return html(res,errorPage('Too many attempts','Try again later. For urgent access, contact the HB ID administrator.',429),429);}
  req.rateLimitKey=key;next();
}
const clearRateLimit=req=>limiter.delete(req.rateLimitKey);
function setPortalCookie(res,token){res.cookie('hb_portal',token,{httpOnly:true,secure:secureCookie,sameSite:'lax',path:'/',maxAge:12*3600*1000});}
function clearPortalCookie(res){res.clearCookie('hb_portal',{httpOnly:true,secure:secureCookie,sameSite:'lax',path:'/'});}
async function requirePortal(req,res,next){
  const user=await getDashboardSession(cookies(req).hb_portal);
  if(!user)return res.redirect('/portal/login');
  req.portalSession=user;next();
}
function requireAdmin(req,res,next){if(!req.portalSession?.is_admin)return html(res,errorPage('Admin access required','Only the platform administrator can manage applications and accounts.',403),403);next();}
function csrfGuard(req,res,next){if(!req.portalSession||!req.body?._csrf||req.body._csrf!==req.portalSession.csrf)return html(res,errorPage('Security check failed','Please reopen the portal page and try again.',403),403);next();}
function validRedirect(input){
  try{
    const u=new URL(String(input||''));
    if(u.username||u.password||u.hash||u.search.length>2000||u.href.length>2048||input.includes('*'))return false;
    if(u.protocol==='https:')return true;
    return u.protocol==='http:' && ['localhost','127.0.0.1'].includes(u.hostname);
  }catch{return false;}
}
async function renderPortal(req,res,{message='',error='',created=null}={}){
  const [apps,users]=await Promise.all([listClients(),listUsers()]);
  res.set('Cache-Control','no-store');
  html(res,portal({session:req.portalSession,apps,users,created,issuer:ISSUER,message,error}));
}
app.get('/healthz', (_req,res)=>res.status(200).json({ok:true,ready:ownerReady}));
app.get('/readyz', (_req,res)=>res.status(ownerReady?200:503).json({ready:ownerReady}));
app.get('/', (_req,res)=>html(res,home()));
// Only the hosting account owner can seed an administrator through private env vars.
// There is deliberately no public first-user enrollment route.
app.use((_req,res,next)=>{
  if(ownerReady)return next();
  res.set('Cache-Control','no-store');
  return html(res,setupPending(),503);
});
app.get('/portal/login', async(req,res)=>{
  if(await getDashboardSession(cookies(req).hb_portal))return res.redirect('/portal');
  html(res,portalLogin());
});
app.post('/portal/login',originGuard,rateLimit,async(req,res)=>{
  const account=await findByEmail(req.body.email);
  const valid=account && await verifyPassword(String(req.body.password||''),account.password_hash);
  if(!valid)return html(res,portalLogin('Invalid email or password.'),401);
  clearRateLimit(req);
  setPortalCookie(res,await createDashboardSession(account.id));
  res.redirect(303,'/portal');
});
app.get('/portal',requirePortal,async(req,res)=>renderPortal(req,res));
app.get('/wallet/login',async(req,res)=>{
  res.set('Cache-Control','no-store');
  // The QR has no account identifier or login token. Only the browser session counts.
  const session=await getDashboardSession(cookies(req).hb_portal);
  res.redirect(303,session?'/portal':'/portal/login');
});
app.get('/portal/wallet',requirePortal,async(req,res)=>{
  res.set('Cache-Control','no-store');
  html(res,walletPage({session:req.portalSession,pass:await getWalletPass(req.portalSession.id),
    configured:Boolean(process.env.WALLETWALLET_API_KEY),message:req.query.result==='unavailable'?'Pass creation is unavailable right now. Please contact the platform owner.':''}));
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
app.post('/portal/apps',originGuard,requirePortal,requireAdmin,csrfGuard,async(req,res)=>{
  const name=String(req.body.name||'').trim();
  const redirect=String(req.body.redirect_uri||'').trim();
  if(name.length<2||name.length>90)return renderPortal(req,res,{error:'Application name must be 2–90 characters.'});
  if(!validRedirect(redirect))return renderPortal(req,res,{error:'Use a valid HTTPS callback URL. Only localhost may use HTTP for testing.'});
  const created=await createClient(name,redirect);
  return renderPortal(req,res,{created,message:`${name} has been registered. Copy the client secret now.`});
});
app.post('/portal/users',originGuard,requirePortal,requireAdmin,csrfGuard,async(req,res)=>{
  const name=String(req.body.name||'').trim();
  const email=String(req.body.email||'').trim().toLowerCase();
  const password=String(req.body.password||'');
  if(name.length<2||name.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<14||password.length>200){
    return renderPortal(req,res,{error:'Enter a valid name, email and unique password of 14–200 characters.'});
  }
  try{await createUser(name,email,password);return renderPortal(req,res,{message:`Account created for ${name}. Give the temporary password to that person privately.`});}
  catch(e){if(e.code==='23505')return renderPortal(req,res,{error:'An account already exists for that email.'});throw e;}
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
  const user=await findByEmail(req.body.email);
  const valid=user && await verifyPassword(String(req.body.password||''),user.password_hash);
  if(!valid){
    const client=await provider.Client.find(details.params.client_id);
    return html(res,interactionLogin({clientName:client?.clientName||'the website',uid:details.uid,error:'Invalid email or password.',email:String(req.body.email||'').slice(0,250)}),401);
  }
  clearRateLimit(req);
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
  console.error('HB ID request error:',err?.message||'Unknown error');
  if(res.headersSent)return next(err);
  return html(res,errorPage('Request failed','Please retry. If the problem continues, contact the HB ID administrator.',500),500);
});
// Serverless hosts import the app; traditional Node.js hosts use npm start.
if (process.env.HB_ID_SERVERLESS !== 'true' && process.env.NETLIFY !== 'true' && !process.env.VERCEL) {
  app.listen(PORT,'0.0.0.0',()=>console.log(`HB ID provider listening on port ${PORT} with issuer ${ISSUER}`));
}
export default app;
