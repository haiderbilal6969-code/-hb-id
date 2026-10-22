// WalletWallet issues the pass; HB ID alone authenticates the browser.
const API = 'https://api.walletwallet.dev';
export class WalletServiceError extends Error {
  constructor(code, uncertain=false) { super(code); this.code=code; this.uncertain=uncertain; }
}
export function walletPassBody({name,issuer}) {
  const base=new URL(issuer);
  if(base.protocol!=='https:' || base.pathname!=='/' || base.search || base.hash || base.username || base.password) throw new WalletServiceError('https_required');
  const loginUrl=new URL('/wallet/login',base).href;
  return {
    logoText:'HB ID', organizationName:'HB ID', description:'HB ID sign-in shortcut',
    colorPreset:'dark', sharingProhibited:true,
    primaryFields:[{label:'HB ID LOGIN',value:String(name).slice(0,150)}],
    secondaryFields:[{label:'ACCESS',value:'Your connected websites'}],
    backFields:[
      {label:'Open HB ID',value:loginUrl},
      {label:'Sign-in',value:'An active HB ID session opens your portal. Otherwise sign in on the HB ID website.'},
      {label:'Security',value:'This card is a sign-in shortcut. Possession of the card does not grant account access.'}
    ],
    barcodeValue:loginUrl, barcodeFormat:'QR', barcodeAltText:'Open HB ID'
  };
}
function googleUrl(value) {
  try { const u=new URL(value); return u.protocol==='https:' && u.hostname==='pay.google.com' && u.pathname.startsWith('/gp/v/save/') && !u.username && !u.password ? u.href : null; }
  catch {return null;}
}
function shareUrl(value) {
  try { const u=new URL(value); return u.protocol==='https:' && u.hostname==='pass.walletwallet.dev' && u.pathname.startsWith('/p/') && !u.username && !u.password ? u.href : null; }
  catch {return null;}
}
export async function createWalletPass(user,{issuer,apiKey=process.env.WALLETWALLET_API_KEY,fetchImpl=fetch}={}) {
  apiKey=typeof apiKey==='string'?apiKey.trim():'';
  if(!apiKey) throw new WalletServiceError('not_configured');
  const body=walletPassBody({name:user.name,issuer});
  const options={headers:{Authorization:`Bearer ${apiKey}`},redirect:'error',signal:AbortSignal.timeout(15000)};
  const usage=await getWalletUsage({apiKey,fetchImpl});
  // Stop at the included quota. Never upgrade a plan or buy passes automatically.
  if(!Number.isFinite(usage.remaining) || usage.remaining<=0) throw new WalletServiceError('quota_reached');
  let response;
  try {
    response=await fetchImpl(`${API}/api/passes?format=json`,{
      ...options,method:'POST',headers:{...options.headers,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)
    });
  } catch {throw new WalletServiceError('creation_uncertain',true);}
  if(!response.ok) {
    if(response.status>=500)throw new WalletServiceError('creation_uncertain',true);
    throw new WalletServiceError(response.status===429?'quota_reached':response.status===401?'provider_auth':'provider_rejected');
  }
  let result;
  try {result=await response.json();} catch {throw new WalletServiceError('creation_uncertain',true);}
  const googleSaveUrl=googleUrl(result.googleSaveUrl);
  if(!googleSaveUrl || typeof result.serialNumber!=='string' || !/^[a-f0-9-]{36}$/i.test(result.serialNumber)) throw new WalletServiceError('creation_uncertain',true);
  return {serialNumber:result.serialNumber,googleSaveUrl,shareUrl:shareUrl(result.shareUrl)};
}
export async function getWalletUsage({apiKey=process.env.WALLETWALLET_API_KEY,fetchImpl=fetch,timeoutMs=10000}={}){
  apiKey=typeof apiKey==='string'?apiKey.trim():'';
  if(!apiKey)throw new WalletServiceError('not_configured');
  try {
    const response=await fetchImpl(`${API}/api/auth/usage`,{headers:{Authorization:`Bearer ${apiKey}`},redirect:'error',signal:AbortSignal.timeout(timeoutMs)});
    if(!response.ok)throw new WalletServiceError(response.status===401?'provider_auth':'provider_unavailable');
    const usage=await response.json();
    return {remaining:Number.isFinite(usage?.remaining)?usage.remaining:null,
      limit:Number.isFinite(usage?.limit)?usage.limit:null,
      count:Number.isFinite(usage?.count)?usage.count:null,
      plan:['free','trial','pro','business','enterprise'].includes(usage?.plan)?usage.plan:null};
  } catch(e) {if(e instanceof WalletServiceError)throw e;throw new WalletServiceError('provider_unavailable');}
}
