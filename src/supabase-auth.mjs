import {createClient} from '@supabase/supabase-js';

export function supabaseSettings(env=process.env){
  const url=String(env.SUPABASE_URL||'').trim().replace(/\/$/,'');
  const key=String(env.SUPABASE_PUBLISHABLE_KEY||'').trim();
  let valid=false;
  try{const u=new URL(url);valid=u.protocol==='https:'&&u.hostname.endsWith('.supabase.co')&&u.pathname==='/'&&!u.search&&!u.hash&&!u.username&&!u.password;}catch{}
  const configured=valid&&/^sb_publishable_[A-Za-z0-9_-]+$/.test(key);
  return {url,key,configured,ready:configured&&env.SUPABASE_AUTH_ENABLED==='true'};
}

export class EmailAuthError extends Error{
  constructor(code='unavailable'){super('Email sign-in could not be completed');this.code=code;}
}

function client(fetchImpl){
  const settings=supabaseSettings();
  if(!settings.ready)throw new EmailAuthError('not_configured');
  // A fresh, server-only client for each operation. Never share a user's session
  // across requests or store access/refresh tokens in the browser.
  return createClient(settings.url,settings.key,{
    auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false},
    global:{fetch:(url,init={})=>fetchImpl(url,{...init,signal:AbortSignal.any([...(init.signal?[init.signal]:[]),AbortSignal.timeout(8000)])})}
  });
}

export async function sendSupabaseCode(email,fetchImpl=fetch){
  const auth=client(fetchImpl).auth;
  let result;
  try{result=await auth.signInWithOtp({email,options:{shouldCreateUser:true}});}catch{throw new EmailAuthError();}
  if(result.error){
    if(result.error.code==='over_email_send_rate_limit'||result.error.status===429)throw new EmailAuthError('rate_limited');
    throw new EmailAuthError();
  }
}

export async function verifySupabaseCode(email,code,fetchImpl=fetch){
  if(typeof code!=='string'||!/^\d{6,10}$/.test(code))throw new EmailAuthError('invalid_code');
  const auth=client(fetchImpl).auth;
  try{
    const {data,error}=await auth.verifyOtp({email,token:code,type:'email'});
    if(error||!data.session?.access_token)throw new EmailAuthError('invalid_code');
    // Fetch the authoritative user from Auth; do not trust browser-supplied
    // identities, decoded JWTs, or user-editable metadata for local privileges.
    const verified=await auth.getUser(data.session.access_token);
    const user=verified.data?.user;
    if(verified.error||!user||!user.email_confirmed_at||user.is_anonymous||
      !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(user.id)||
      String(user.email||'').toLowerCase()!==email)throw new EmailAuthError('invalid_code');
    // Email OTP alone must not bypass an enrolled Supabase second factor.
    if(user.factors?.some(f=>f.status==='verified'))throw new EmailAuthError('second_factor');
    return {id:user.id.toLowerCase(),email};
  }catch(error){throw error instanceof EmailAuthError?error:new EmailAuthError();}
  finally{
    // HB ID issues its own short-lived portal session. The provider's refresh
    // session is not needed after this one-time authentication assertion.
    try{await auth.signOut({scope:'local'});}catch{}
  }
}
