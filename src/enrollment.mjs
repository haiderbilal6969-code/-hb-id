import {randomUUID} from 'node:crypto';
import {pool,query,rand,digest,hashPassword,findByEmail} from './db.mjs';
import {emailSettings,sendAccountMail} from './email.mjs';
import {emailStart,emailVerification} from './ui.mjs';

export function validEmail(value){
  return typeof value==='string'&&value.length<=320&&value.length>3&&
    /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(value);
}

// Shared PostgreSQL quotas survive Vercel cold starts and multiple instances.
// The conservative total also leaves room under Spacemail's trial limit.
export async function reserveEmailSend(email,ip){
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtext('hb-id:email-sending'))");
    await client.query('DELETE FROM email_send_limits WHERE reset_at<=NOW()');
    const limits=[['email-minute:'+digest(email),1,60],['email-hour:'+digest(email),3,3600],
      ['ip-hour:'+digest(String(ip||'unknown')),10,3600],['global-hour',18,3600]];
    for(const [key,max] of limits){
      const r=await client.query('SELECT count FROM email_send_limits WHERE key=$1',[key]);
      if(r.rows[0]?.count>=max){await client.query('ROLLBACK');return false;}
    }
    for(const [key,,seconds] of limits)await client.query(`INSERT INTO email_send_limits(key,count,reset_at)
      VALUES($1,1,NOW()+$2*interval '1 second') ON CONFLICT(key) DO UPDATE SET count=email_send_limits.count+1`,[key,seconds]);
    await client.query('COMMIT');return true;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}

export async function issueSignupToken(email){
  const token=rand(32);
  await query(`INSERT INTO signup_email_tokens(token_hash,email,expires_at) VALUES($1,$2,NOW()+interval '30 minutes')
    ON CONFLICT(email) DO UPDATE SET token_hash=EXCLUDED.token_hash,expires_at=EXCLUDED.expires_at,used_at=NULL`,[digest(token),email]);
  return token;
}

export async function completeSignup(token,name,password){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token))return null;
  if(typeof name!=='string'||name.trim().length<2||name.trim().length>100||
    typeof password!=='string'||password.length<14||password.length>200)return null;
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const found=await client.query(`SELECT email FROM signup_email_tokens WHERE token_hash=$1
      AND used_at IS NULL AND expires_at>NOW() FOR UPDATE`,[digest(token)]);
    if(!found.rowCount){await client.query('ROLLBACK');return null;}
    const created=await client.query(`INSERT INTO users(id,name,email,password_hash,email_verified,is_admin)
      VALUES($1,$2,$3,$4,true,false) ON CONFLICT(email) DO NOTHING RETURNING id,email`,
      [randomUUID(),name.trim(),found.rows[0].email,await hashPassword(password)]);
    await client.query('UPDATE signup_email_tokens SET used_at=NOW() WHERE token_hash=$1',[digest(token)]);
    await client.query('COMMIT');return created.rows[0]||null;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}

export async function issueEmailResetToken(userId){
  const token=rand(32),client=await pool.connect();
  try{
    await client.query('BEGIN');
    // Same account-before-token lock order as token redemption.
    await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[userId]);
    await client.query('UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL',[userId]);
    await client.query(`INSERT INTO password_reset_tokens(token_hash,user_id,expires_at,verifies_email)
      VALUES($1,$2,NOW()+interval '30 minutes',true)`,[digest(token),userId]);
    await client.query('COMMIT');return token;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}

export function installEmailAccountRoutes(app,{issuer,originGuard,rateLimit,emailCodeReady=()=>false}){
  const show=(res,content,status=200)=>res.status(status).type('html').send(content);
  for(const purpose of ['signup','reset']){
    const path=purpose==='signup'?'/portal/signup':'/portal/forgot-password';
    app.get(path,(_req,res)=>purpose==='signup'&&emailCodeReady()?res.redirect(303,'/portal/email'):show(res,emailStart({purpose,configured:emailSettings().ready})));
    app.post(path,originGuard,rateLimit,async(req,res)=>{
      if(!emailSettings().ready)return show(res,emailStart({purpose,configured:false}),503);
      const email=typeof req.body.email==='string'?req.body.email.trim().toLowerCase():'';
      if(!validEmail(email))return show(res,emailStart({purpose,error:'Enter a valid email address.'}),400);
      // Identical public reply for existing, unknown and throttled accounts.
      const response=()=>show(res,emailStart({purpose,sent:true}),202);
      if(!await reserveEmailSend(email,req.ip))return response();
      const user=await findByEmail(email);
      if((purpose==='signup'&&user)||(purpose==='reset'&&!user))return response();
      const token=purpose==='signup'?await issueSignupToken(email):await issueEmailResetToken(user.id);
      try{await sendAccountMail({to:email,purpose,token,issuer},app.locals.accountEmailTransport);}
      catch(error){
        // An SMTP timeout can mean delivery is uncertain. Invalidate this token,
        // keep the quota, and never blindly retry a possibly delivered message.
        const table=purpose==='signup'?'signup_email_tokens':'password_reset_tokens';
        await query(`UPDATE ${table} SET used_at=NOW() WHERE token_hash=$1`,[digest(token)]);
        const safeCodes=new Set(['EAUTH','ETIMEDOUT','ECONNECTION','ESOCKET','EDNS','EMAIL_REJECTED','EMAIL_NOT_CONFIGURED']);
        console.error('HB ID email delivery failed:',safeCodes.has(error.code)?error.code:'DELIVERY_FAILED');
      }
      return response();
    });
  }
  app.get('/portal/verify-email',(_req,res)=>show(res,emailVerification()));
  app.post('/portal/verify-email',originGuard,rateLimit,async(req,res)=>{
    const {token,name,password,confirm}=req.body||{};
    if(typeof password!=='string'||password.length<14||password.length>200||password!==confirm||
      typeof name!=='string'||name.trim().length<2||name.trim().length>100)return res.status(400).json({error:'Enter a name of 2–100 characters and matching passwords of 14–200 characters.'});
    const account=await completeSignup(token,name,password);
    if(!account)return res.status(400).json({error:'This link is invalid, expired, already used, or the account already exists. Request a new link or sign in.'});
    return res.json({ok:true});
  });
}
