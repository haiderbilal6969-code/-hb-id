import {randomUUID} from 'node:crypto';
import {pool,query,rand,digest,hashPassword,verifyPassword,findByEmail,recordSecurityEvent} from './db.mjs';
import {reserveEmailSend,validEmail} from './enrollment.mjs';
import {auth,formField,esc as e} from './ui.mjs';
import {supabaseSettings,sendSupabaseCode,verifySupabaseCode,EmailAuthError} from './supabase-auth.mjs';

const validToken=t=>typeof t==='string'&&/^[A-Za-z0-9_-]{43}$/.test(t);
export async function emailChallenge(token,stage,attempt=false){
  if(!validToken(token))return null;
  const sql=attempt?`UPDATE email_auth_challenges SET attempts=attempts+1 WHERE token_hash=$1 AND stage=$2
    AND expires_at>NOW() AND attempts<5 RETURNING payload`:
    'SELECT payload FROM email_auth_challenges WHERE token_hash=$1 AND stage=$2 AND expires_at>NOW() AND attempts<5';
  return (await query(sql,[digest(token),stage])).rows[0]?.payload||null;
}
async function putChallenge(stage,payload){
  const token=rand(32);
  await query('DELETE FROM email_auth_challenges WHERE expires_at<NOW()');
  await query("INSERT INTO email_auth_challenges(token_hash,stage,payload,expires_at) VALUES($1,$2,$3::jsonb,NOW()+interval '10 minutes')",[digest(token),stage,JSON.stringify(payload)]);
  return token;
}
async function removeChallenge(token){if(validToken(token))await query('DELETE FROM email_auth_challenges WHERE token_hash=$1',[digest(token)]);}

// The verified challenge is a server-side authentication assertion. Account
// matching and challenge consumption run together so concurrent requests cannot
// bind two local accounts or replay a successfully completed assertion.
export async function completeEmailAccount(token,{name,password,confirm}={}){
  const snapshot=await emailChallenge(token,'verified');
  if(!snapshot)return null;
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    // Account-before-challenge lock order matches recovery and unlinking.
    const found=(await client.query('SELECT * FROM users WHERE email=$1 FOR UPDATE',[snapshot.email])).rows[0];
    const challenge=(await client.query(`UPDATE email_auth_challenges SET attempts=attempts+1
      WHERE token_hash=$1 AND stage='verified' AND expires_at>NOW() AND attempts<5 RETURNING payload`,[digest(token)])).rows[0]?.payload;
    if(!challenge){await client.query('ROLLBACK');return null;}
    const fail=async()=>{await client.query('COMMIT');return null;};
    if(challenge.userId?(found?.id!==challenge.userId||found.auth_version!==challenge.version):Boolean(found))return await fail();
    if(found?.supabase_user_id&&found.supabase_user_id!==challenge.supabaseId)return await fail();
    let account=found,linked=false;
    if(found){
      if(!found.supabase_user_id){
        if(!await verifyPassword(password,found.password_hash))return await fail();
        account=(await client.query(`UPDATE users SET supabase_user_id=$2,email_verified=true,auth_version=auth_version+1
          WHERE id=$1 RETURNING *`,[found.id,challenge.supabaseId])).rows[0];
        linked=true;
      }
    }else{
      if(typeof name!=='string'||name.trim().length<2||name.trim().length>100||typeof password!=='string'||
        password.length<14||password.length>200||password!==confirm)return await fail();
      account=(await client.query(`INSERT INTO users(id,name,email,password_hash,email_verified,is_admin,supabase_user_id)
        VALUES($1,$2,$3,$4,true,false,$5) RETURNING *`,[randomUUID(),name.trim(),challenge.email,await hashPassword(password),challenge.supabaseId])).rows[0];
      linked=true;
    }
    await client.query('DELETE FROM email_auth_challenges WHERE token_hash=$1',[digest(token)]);
    await client.query('COMMIT');return {account,linked};
  }catch(error){await client.query('ROLLBACK');if(error.code==='23505')return null;throw error;}
  finally{client.release();}
}

export async function unlinkEmailAccount(userId,password){
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const user=(await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE',[userId])).rows[0];
    if(!user||!await verifyPassword(password,user.password_hash)){await client.query('ROLLBACK');return false;}
    await client.query('UPDATE users SET supabase_user_id=NULL,auth_version=auth_version+1 WHERE id=$1',[userId]);
    await client.query("DELETE FROM email_auth_challenges WHERE payload->>'userId'=$1",[String(userId)]);
    await client.query('DELETE FROM dashboard_sessions WHERE user_id=$1',[userId]);
    await client.query('COMMIT');return true;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}

function emailPage({base='/portal/email',stage='start',payload,error=''}={}){
  const back=base.startsWith('/interaction/')?base.replace(/\/email$/,''):'/portal/login';
  let title='Sign in with an email code',description='We will send a one-time code to your email address.',body;
  if(stage==='code'){
    title='Check your email';description='Enter the sign-in code sent to your email. This request expires in 10 minutes.';
    body=`<form method="post" action="${e(base)}/verify"><div class="form-field"><label for="code">Email code</label><input id="code" name="code" type="text" required inputmode="numeric" pattern="[0-9]{6,10}" minlength="6" maxlength="10" autocomplete="one-time-code"><small>Use the code from the email you just requested.</small></div><button class="button full" type="submit">Verify code →</button></form><p class="hint"><a class="help-link" href="${e(base)}">Use a different email or request a new code</a></p>`;
  }else if(stage==='verified'){
    const existing=Boolean(payload.userId);
    title=existing?'Connect your HB ID':'Create your HB ID';
    description=existing?'Email verified. Confirm your existing HB ID password once to enable email-code sign-in.':'Email verified. Choose your name and a unique HB ID backup password.';
    body=`<p class="hint">${e(payload.email)}</p><form method="post" action="${e(base)}/complete">${existing?'':formField('Display name','name','text',{autocomplete:'name'})}${formField(existing?'Current HB ID password':'HB ID backup password','password','password',{autocomplete:existing?'current-password':'new-password',minlength:existing?undefined:14,hint:existing?'This preserves your existing account, permissions, and Wallet card.':'14–200 characters. Use a password you do not use for other services.'})}${existing?'':formField('Confirm backup password','confirm','password',{autocomplete:'new-password',minlength:14})}<button class="button full" type="submit">${existing?'Enable email sign-in':'Create account'} →</button></form>`;
  }else{
    body=`<form method="post" action="${e(base)}">${formField('Email address','email','email',{autocomplete:'email',placeholder:'you@example.com'})}<button class="button full" type="submit">Send sign-in code →</button></form><p class="hint">First time? Verify your email, then create your HB ID. Existing members confirm their HB ID password once.</p>`;
  }
  return auth(title,description,`${body}<p class="hint"><a class="help-link" href="${e(back)}">← Back to sign in</a></p>`,{error});
}

export function installSupabaseAuthRoutes(app,{issuerUrl,originGuard,rateLimit,clearRateLimit,cookies,
  requirePortal,csrfGuard,provider,finishPortalLogin,clearPortalCookie}){
  const secure=issuerUrl.protocol==='https:';
  const cookieName=secure?'__Host-hb_email':'hb_email';
  const cookieOptions={httpOnly:true,secure,sameSite:'strict',path:'/',maxAge:600000};
  const token=req=>cookies(req)[cookieName];
  const clear=res=>res.clearCookie(cookieName,{httpOnly:true,secure,sameSite:'strict',path:'/'});
  const show=(res,opts,status=200)=>res.status(status).type('html').send(emailPage(opts));
  const base=req=>req.params.uid?`/interaction/${req.params.uid}/email`:'/portal/email';
  const context=req=>req.params.uid||null;
  async function available(req,res,next){
    if(!supabaseSettings().ready)return show(res,{base:base(req),error:'Email-code sign-in is being set up. Use your password or passkey.'},503);
    if(req.params.uid){
      try{const d=await provider.interactionDetails(req,res);if(d.uid!==req.params.uid||d.prompt.name!=='login')throw new Error();}
      catch{return show(res,{error:'Restart sign-in from the connected website.'},400);}
    }
    next();
  }
  async function finish(req,res,pendingToken){
    const result=await completeEmailAccount(pendingToken,req.body);
    if(!result)return false;
    const {account,linked}=result;
    if(!await finishPortalLogin(req,res,account.id,{passwordHash:account.password_hash,supabaseUserId:account.supabase_user_id,authVersion:account.auth_version}))return false;
    clear(res);await clearRateLimit(req);
    if(linked)await recordSecurityEvent(account.id,'email_code_linked');
    await recordSecurityEvent(account.id,'email_code_sign_in');
    if(req.params.uid)await provider.interactionFinished(req,res,{login:{accountId:String(account.id),amr:['email']}},{mergeWithLastSubmission:false});
    else res.redirect(303,'/portal');
    return true;
  }
  for(const route of ['/portal/email','/interaction/:uid/email']){
    app.get(route,available,async(req,res)=>{
      const pending=await emailChallenge(token(req),'verified');
      if(pending?.uid===context(req))return show(res,{base:base(req),stage:'verified',payload:pending});
      show(res,{base:base(req)});
    });
    app.post(route,originGuard,rateLimit,available,async(req,res)=>{
      const email=typeof req.body.email==='string'?req.body.email.trim().toLowerCase():'';
      if(!validEmail(email))return show(res,{base:base(req),error:'Enter a valid email address.'},400);
      if(!await reserveEmailSend(email,req.ip))return show(res,{base:base(req),error:'Please wait before requesting another code. Check your inbox and spam folder.'},429);
      const account=await findByEmail(email);
      await removeChallenge(token(req));clear(res);
      try{await sendSupabaseCode(email,app.locals.supabaseAuthFetch);}
      catch(error){return show(res,{base:base(req),error:error instanceof EmailAuthError&&error.code==='rate_limited'?'Please wait before requesting another email code.':'Email sign-in is temporarily unavailable. Use your password or passkey.'},503);}
      const pending=await putChallenge('code',{email,userId:account?.id||null,version:account?.auth_version??null,uid:context(req)});
      res.cookie(cookieName,pending,cookieOptions);res.redirect(303,base(req)+'/code');
    });
    app.get(route+'/code',available,async(req,res)=>{
      const pending=await emailChallenge(token(req),'code');
      if(!pending||pending.uid!==context(req))return res.redirect(303,base(req));
      show(res,{base:base(req),stage:'code'});
    });
    app.post(route+'/verify',originGuard,rateLimit,available,async(req,res)=>{
      const pending=await emailChallenge(token(req),'code',true);
      if(!pending||pending.uid!==context(req))return show(res,{base:base(req),error:'This sign-in request expired. Request a new code.'},400);
      let user;
      try{user=await verifySupabaseCode(pending.email,req.body.code,app.locals.supabaseAuthFetch);}
      catch(error){return show(res,{base:base(req),stage:'code',error:error instanceof EmailAuthError&&error.code==='second_factor'?'This account requires a second factor. Use your HB ID password or passkey.':'The code could not be verified. Check the code or request a new one.'},400);}
      // Rotate the browser binding after successful verification; a concurrent
      // request must win the one-use code assertion before it can continue.
      const taken=await query("DELETE FROM email_auth_challenges WHERE token_hash=$1 AND stage='code' AND expires_at>NOW() RETURNING payload",[digest(token(req))]);
      if(!taken.rowCount)return show(res,{base:base(req),error:'This code was already used. Start again.'},400);
      const current=await findByEmail(pending.email);
      if(pending.userId?(current?.id!==pending.userId||current.auth_version!==pending.version):Boolean(current)){
        clear(res);return show(res,{base:base(req),error:'Your account changed. Start sign-in again.'},400);
      }
      if(current?.supabase_user_id&&current.supabase_user_id!==user.id){clear(res);return show(res,{base:base(req),error:'This email identity does not match your linked account. Use your password or passkey.'},400);}
      const verified=await putChallenge('verified',{...pending,supabaseId:user.id});
      res.cookie(cookieName,verified,cookieOptions);
      if(current?.supabase_user_id){if(await finish(req,res,verified))return;}
      res.redirect(303,base(req));
    });
    app.post(route+'/complete',originGuard,rateLimit,available,async(req,res)=>{
      const pending=await emailChallenge(token(req),'verified');
      if(!pending||pending.uid!==context(req))return show(res,{base:base(req),error:'This sign-in request expired. Request a new code.'},400);
      if(await finish(req,res,token(req)))return;
      show(res,{base:base(req),stage:'verified',payload:pending,error:pending.userId?'Your HB ID password could not be verified, or your account changed. Try again or request a new code.':'Use a name of 2–100 characters and matching passwords of 14–200 characters. If you already have an account, start sign-in again.'},400);
    });
  }
  app.post('/portal/email/unlink',originGuard,requirePortal,csrfGuard,rateLimit,async(req,res)=>{
    if(!await unlinkEmailAccount(req.portalSession.id,req.body.current_password))return res.redirect(303,'/portal/security?result=password-incorrect');
    clear(res);clearPortalCookie(res);await recordSecurityEvent(req.portalSession.id,'email_code_removed');
    res.redirect(303,'/portal/login');
  });
}
