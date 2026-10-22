import pg from 'pg';
import { attachDatabasePool } from '@vercel/functions';
import { randomBytes, randomUUID, generateKeyPairSync, scrypt as scryptCb, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCb);
export const pool = process.env.DATABASE_URL
  ? new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 5, idleTimeoutMillis: 30000 })
  : null;
if (pool && process.env.VERCEL) attachDatabasePool(pool);
export const query = (sql, args=[]) => {
  if (!pool) throw new Error('DATABASE_URL environment variable is required');
  return pool.query(sql, args);
};
export const rand = (bytes=32) => randomBytes(bytes).toString('base64url');
export const digest = (value) => createHash('sha256').update(value).digest('hex');
export const escapeHtml = (input='') => String(input ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const result = await scrypt(password, salt, 64, { N:32768, r:8, p:3, maxmem:67108864 });
  return `scrypt$32768$8$3$${salt.toString('hex')}$${result.toString('hex')}`;
}
export async function verifyPassword(password, stored) {
  if(typeof password!=='string'||password.length>200||typeof stored!=='string')return false;
  const legacy=/^scrypt\$16384\$([a-f0-9]{32})\$([a-f0-9]{128})$/.exec(stored);
  const current=/^scrypt\$32768\$8\$3\$([a-f0-9]{32})\$([a-f0-9]{128})$/.exec(stored);
  const parts=current||legacy;if(!parts)return false;
  const expected=Buffer.from(parts[2], 'hex');
  const actual=await scrypt(password, Buffer.from(parts[1], 'hex'), 64,
    {N:current?32768:16384,r:8,p:current?3:1,maxmem:67108864});
  return timingSafeEqual(expected,actual);
}
export async function authenticatePassword(email,password){
  const account=await findByEmail(email);
  // Unknown accounts still perform the expensive password check.
  const dummy=`scrypt$32768$8$3$${'0'.repeat(32)}$${'0'.repeat(128)}`;
  const valid=await verifyPassword(password,account?.password_hash||dummy);
  if(!account||!valid)return null;
  if(account.password_hash.startsWith('scrypt$16384$')){
    const upgraded=await hashPassword(password);
    const changed=await query('UPDATE users SET password_hash=$3 WHERE id=$1 AND password_hash=$2',[account.id,account.password_hash,upgraded]);
    if(!changed.rowCount)return null;
    account.password_hash=upgraded;
  }
  return account;
}
export async function initDatabase() {
  if (!pool) throw new Error('DATABASE_URL environment variable is required');
  // Serialize first-start migrations and owner creation across cold starts.
  const client = await pool.connect();
  const query = (sql, args=[]) => client.query(sql, args);
  try {
    await query('BEGIN');
    await query("SELECT pg_advisory_xact_lock(hashtext('hb-id:initialize'))");
    await query(`CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY, name VARCHAR(150) NOT NULL, email VARCHAR(320) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await query(`CREATE TABLE IF NOT EXISTS oidc_objects (
      model TEXT NOT NULL, id TEXT NOT NULL, payload JSONB NOT NULL,
      expires_at TIMESTAMPTZ, grant_id TEXT, uid TEXT, user_code TEXT,
      PRIMARY KEY(model,id)
    )`);
    await query('CREATE INDEX IF NOT EXISTS oidc_objects_grant_idx ON oidc_objects (grant_id)');
    await query('CREATE INDEX IF NOT EXISTS oidc_objects_uid_idx ON oidc_objects (uid)');
    await query('CREATE INDEX IF NOT EXISTS oidc_objects_code_idx ON oidc_objects (user_code)');
    await query(`CREATE TABLE IF NOT EXISTS dashboard_sessions (
      token_hash CHAR(64) PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL
    )`);
    await query('ALTER TABLE dashboard_sessions ADD COLUMN IF NOT EXISTS session_id UUID NOT NULL DEFAULT gen_random_uuid()');
    await query('ALTER TABLE dashboard_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
    await query("ALTER TABLE dashboard_sessions ADD COLUMN IF NOT EXISTS user_agent VARCHAR(256) NOT NULL DEFAULT ''");
    await query('ALTER TABLE dashboard_sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
    await query(`CREATE TABLE IF NOT EXISTS auth_rate_limits (
      key CHAR(64) PRIMARY KEY, count INTEGER NOT NULL, reset_at TIMESTAMPTZ NOT NULL
    )`);
    await query('CREATE INDEX IF NOT EXISTS auth_rate_limits_expiry_idx ON auth_rate_limits(reset_at)');
    await query('DELETE FROM auth_rate_limits WHERE reset_at<NOW()');
    await query(`CREATE TABLE IF NOT EXISTS security_events (
      id UUID PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      action VARCHAR(40) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await query('CREATE INDEX IF NOT EXISTS security_events_user_idx ON security_events(user_id,created_at DESC)');
    await query("DELETE FROM security_events WHERE created_at<NOW()-interval '30 days'");
    await query(`CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(60) NOT NULL, public_key BYTEA NOT NULL, counter BIGINT NOT NULL,
      transports JSONB NOT NULL DEFAULT '[]', device_type TEXT NOT NULL, backed_up BOOLEAN NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_used_at TIMESTAMPTZ
    )`);
    await query('CREATE INDEX IF NOT EXISTS passkeys_user_idx ON passkeys (user_id)');
    await query(`CREATE TABLE IF NOT EXISTS passkey_challenges (
      token_hash CHAR(64) PRIMARY KEY, purpose TEXT NOT NULL, payload JSONB NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    )`);
    await query('DELETE FROM passkey_challenges WHERE expires_at < NOW()');
    await query(`CREATE TABLE IF NOT EXISTS system_config (
      name TEXT PRIMARY KEY, value JSONB NOT NULL
    )`);
    await query(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash CHAR(64) PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
    )`);
    await query('ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS verifies_email BOOLEAN NOT NULL DEFAULT FALSE');
    await query(`CREATE TABLE IF NOT EXISTS signup_email_tokens (
      token_hash CHAR(64) PRIMARY KEY, email VARCHAR(320) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
    )`);
    await query(`CREATE TABLE IF NOT EXISTS email_send_limits (
      key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at TIMESTAMPTZ NOT NULL
    )`);
    await query(`CREATE TABLE IF NOT EXISTS wallet_passes (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('pending','ready','failed','unknown')),
      serial_number TEXT, google_save_url TEXT, share_url TEXT, error_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await query('DELETE FROM dashboard_sessions WHERE expires_at < NOW()');
    const email=process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
    const password=process.env.BOOTSTRAP_ADMIN_PASSWORD;
    if (email && password) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 320) throw new Error('BOOTSTRAP_ADMIN_EMAIL must be a valid email address');
      if (password.length < 14 || password.length > 200) throw new Error('BOOTSTRAP_ADMIN_PASSWORD needs 14–200 characters');
      const n=await query('SELECT COUNT(*)::int AS n FROM users WHERE is_admin=true');
      if(n.rows[0].n===0){
        await query('INSERT INTO users (id,name,email,password_hash,is_admin,email_verified) VALUES ($1,$2,$3,$4,true,false) ON CONFLICT(email) DO NOTHING',
          [randomUUID(), 'HB ID Owner', email, await hashPassword(password)]);
        console.log('Initial administrator seeded. Remove BOOTSTRAP_ADMIN_PASSWORD from host variables after seeding.');
      }
    }
    const admin=await query('SELECT COUNT(*)::int AS n FROM users WHERE is_admin=true');
    await query('COMMIT');
    return admin.rows[0].n > 0;
  } catch (error) {
    await query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
export async function getOrMakeKeys() {
  const existing=await query('SELECT value FROM system_config WHERE name=$1',['identity_keys']);
  if (existing.rows.length) return existing.rows[0].value;
  const { privateKey }=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk=privateKey.export({format:'jwk'});
  jwk.use='sig'; jwk.alg='RS256'; jwk.kid=rand(10);
  const config={ signingKeys:[jwk], cookieKeys:[rand(64),rand(64)] };
  await query('INSERT INTO system_config (name,value) VALUES ($1,$2::jsonb) ON CONFLICT(name) DO NOTHING',['identity_keys', JSON.stringify(config)]);
  const saved=await query('SELECT value FROM system_config WHERE name=$1',['identity_keys']);
  return saved.rows[0].value;
}
export async function findByEmail(email){
  const r=await query('SELECT * FROM users WHERE email=$1',[String(email||'').trim().toLowerCase()]);
  return r.rows[0]||null;
}
export async function resetPasswordWithToken(token,password){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token))return false;
  if(typeof password!=='string'||password.length<14||password.length>200)return false;
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    // Always lock the account before any token row to avoid redemption races.
    await client.query(`SELECT id FROM users WHERE id=(SELECT user_id FROM password_reset_tokens
      WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW()) FOR UPDATE`,[digest(token)]);
    const found=await client.query(`SELECT user_id,verifies_email FROM password_reset_tokens
      WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE`,[digest(token)]);
    if(!found.rowCount){await client.query('ROLLBACK');return false;}
    const userId=found.rows[0].user_id;
    await client.query('UPDATE users SET password_hash=$2,email_verified=email_verified OR $3 WHERE id=$1',[userId,await hashPassword(password),found.rows[0].verifies_email]);
    await client.query('UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL',[userId]);
    await client.query('DELETE FROM dashboard_sessions WHERE user_id=$1',[userId]);
    await client.query('DELETE FROM passkeys WHERE user_id=$1',[userId]);
    await client.query("DELETE FROM passkey_challenges WHERE payload->>'userId'=$1",[String(userId)]);
    await client.query("DELETE FROM oidc_objects WHERE model<>'Client' AND (payload->>'accountId'=$1 OR grant_id IN (SELECT id FROM oidc_objects WHERE model='Grant' AND payload->>'accountId'=$1))",[String(userId)]);
    await client.query("INSERT INTO security_events(id,user_id,action) VALUES($1,$2,'password_reset')",[randomUUID(),userId]);
    await client.query('COMMIT');return true;
  }catch(error){await client.query('ROLLBACK');throw error;}
  finally{client.release();}
}
export async function findById(id){
  const r=await query('SELECT id,name,email,email_verified,is_admin FROM users WHERE id=$1',[id]);
  return r.rows[0]||null;
}
export async function createUser(name,email,password){
  const hashed=await hashPassword(password);
  const r=await query('INSERT INTO users (id,name,email,password_hash) VALUES ($1,$2,$3,$4) RETURNING id,email',[randomUUID(),name,email,hashed]);
  return r.rows[0];
}
export async function listUsers(){
  const r=await query('SELECT id,name,email,is_admin,created_at FROM users ORDER BY created_at DESC LIMIT 100');
  return r.rows;
}
export async function createDashboardSession(userId,userAgent='',{passwordHash=null,passkeyId=null}={}){
  const token=rand(32); const csrf=rand(24);
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const account=(await client.query('SELECT password_hash FROM users WHERE id=$1 FOR UPDATE',[userId])).rows[0];
    if(!account||(passwordHash&&account.password_hash!==passwordHash)||
      (passkeyId&&!(await client.query('SELECT id FROM passkeys WHERE id=$1 AND user_id=$2',[passkeyId,userId])).rowCount)){
      await client.query('ROLLBACK');return null;
    }
    await client.query("INSERT INTO dashboard_sessions (token_hash,user_id,csrf,expires_at,user_agent) VALUES ($1,$2,$3,NOW()+interval '12 hours',$4)",[digest(token),userId,csrf,String(userAgent).slice(0,256)]);
    await client.query('COMMIT');return token;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}
export async function getDashboardSession(token){
  if(!token) return null;
  const r=await query(`UPDATE dashboard_sessions s SET last_seen_at=NOW() FROM users u
    WHERE u.id=s.user_id AND s.token_hash=$1 AND s.expires_at>NOW()
      AND s.last_seen_at>NOW()-interval '30 minutes'
    RETURNING s.*,u.name,u.email,u.is_admin,u.id`,[digest(token)]);
  return r.rows[0]||null;
}
export async function deleteDashboardSession(token){ if(token) await query('DELETE FROM dashboard_sessions WHERE token_hash=$1',[digest(token)]); }
export async function getWalletPass(userId){
  const r=await query('SELECT status,google_save_url,share_url,error_code,updated_at FROM wallet_passes WHERE user_id=$1',[userId]);
  return r.rows[0]||null;
}
export async function claimWalletPass(userId){
  const r=await query(`INSERT INTO wallet_passes(user_id,status) VALUES($1,'pending')
    ON CONFLICT(user_id) DO UPDATE SET status='pending',error_code=NULL,updated_at=NOW()
    WHERE wallet_passes.status='failed' RETURNING user_id`,[userId]);
  return r.rowCount===1;
}
export async function completeWalletPass(userId,pass){
  await query(`UPDATE wallet_passes SET status='ready',serial_number=$2,google_save_url=$3,
    share_url=$4,error_code=NULL,updated_at=NOW() WHERE user_id=$1 AND status='pending'`,
    [userId,pass.serialNumber,pass.googleSaveUrl,pass.shareUrl]);
}
export async function failWalletPass(userId,code,uncertain){
  await query("UPDATE wallet_passes SET status=$2,error_code=$3,updated_at=NOW() WHERE user_id=$1 AND status='pending'",[userId,uncertain?'unknown':'failed',code]);
}
export async function createClient(name,redirectUri){
  const clientId='hb_'+rand(16);
  const secret=rand(40);
  const client={client_id:clientId,client_secret:secret,client_name:name,
    redirect_uris:[redirectUri],response_types:['code'],grant_types:['authorization_code'],
    token_endpoint_auth_method:'client_secret_basic',application_type:'web'};
  await query(`INSERT INTO oidc_objects(model,id,payload) VALUES('Client',$1,$2::jsonb)`,[clientId,JSON.stringify(client)]);
  return {clientId,secret,client};
}
export async function listClients(){
  const r=await query("SELECT id,payload->>'client_name' AS name,payload->'redirect_uris' AS redirect_uris FROM oidc_objects WHERE model='Client' ORDER BY id LIMIT 100");
  return r.rows;
}
export async function listPortalSessions(userId,currentToken){
  return (await query(`SELECT session_id,created_at,expires_at,user_agent,token_hash=$2 AS is_current
    FROM dashboard_sessions WHERE user_id=$1 AND expires_at>NOW() AND last_seen_at>NOW()-interval '30 minutes' ORDER BY created_at DESC LIMIT 50`,[userId,digest(currentToken||'')])).rows;
}
export async function consumeAuthLimit(key,max=8){
  await query('DELETE FROM auth_rate_limits WHERE reset_at<NOW()');
  const result=await query(`INSERT INTO auth_rate_limits(key,count,reset_at) VALUES($1,1,NOW()+interval '15 minutes')
    ON CONFLICT(key) DO UPDATE SET count=auth_rate_limits.count+1 RETURNING count`,[key]);
  return result.rows[0].count<=max;
}
export async function clearAuthLimit(key){if(key)await query('DELETE FROM auth_rate_limits WHERE key=$1',[key]);}
const eventActions=new Set(['password_sign_in','passkey_sign_in','sign_in_failed','password_reset','passkey_added','passkey_removed','website_created','member_created','owner_check_failed']);
export async function recordSecurityEvent(userId,action){
  if(!eventActions.has(action))throw new Error('Unknown security event');
  await query("DELETE FROM security_events WHERE created_at<NOW()-interval '30 days'");
  await query('INSERT INTO security_events(id,user_id,action) VALUES($1,$2,$3)',[randomUUID(),userId||null,action]);
}
export async function listSecurityEvents(userId){
  return (await query("SELECT action,created_at FROM security_events WHERE user_id=$1 AND created_at>NOW()-interval '30 days' ORDER BY created_at DESC LIMIT 10",[userId])).rows;
}
export async function revokePortalSession(userId,sessionId){
  if(!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(String(sessionId)))return false;
  return (await query('DELETE FROM dashboard_sessions WHERE user_id=$1 AND session_id=$2',[userId,sessionId])).rowCount>0;
}
export async function updateProfile(userId,name){await query('UPDATE users SET name=$2 WHERE id=$1',[userId,name]);}
export async function listAuthorizedApps(userId){
  return (await query(`SELECT g.payload->>'clientId' AS id,COALESCE(c.payload->>'client_name','Connected website') AS name,
    COUNT(*)::int AS grants FROM oidc_objects g LEFT JOIN oidc_objects c
    ON c.model='Client' AND c.id=g.payload->>'clientId'
    WHERE g.model='Grant' AND g.payload->>'accountId'=$1 AND (g.expires_at IS NULL OR g.expires_at>NOW())
    GROUP BY g.payload->>'clientId',c.payload->>'client_name'`,[String(userId)])).rows;
}
export async function revokeAuthorizedApp(userId,clientId){
  await query(`WITH owned AS (SELECT id FROM oidc_objects WHERE model='Grant' AND payload->>'accountId'=$1 AND payload->>'clientId'=$2)
    DELETE FROM oidc_objects WHERE model<>'Client' AND (grant_id IN (SELECT id FROM owned) OR (model='Grant' AND id IN (SELECT id FROM owned)))`,[String(userId),clientId]);
}
export async function listPasskeys(userId){
  return (await query('SELECT id,name,transports,device_type,backed_up,created_at,last_used_at FROM passkeys WHERE user_id=$1 ORDER BY created_at',[userId])).rows;
}
export async function savePasskey(userId,name,info,sessionHash=null){
  const c=info.credential;
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[userId]);
    if(sessionHash&&!(await client.query(`SELECT token_hash FROM dashboard_sessions WHERE user_id=$1 AND token_hash=$2
      AND expires_at>NOW() AND last_seen_at>NOW()-interval '30 minutes'`,[userId,sessionHash])).rowCount){
      await client.query('ROLLBACK');return false;
    }
    await client.query(`INSERT INTO passkeys(id,user_id,name,public_key,counter,transports,device_type,backed_up)
    VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,[c.id,userId,name,Buffer.from(c.publicKey),c.counter,JSON.stringify(c.transports||[]),info.credentialDeviceType,info.credentialBackedUp]);
    await client.query('COMMIT');return true;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}
export async function findPasskey(id){
  if(typeof id!=='string'||id.length>2048)return null;
  return (await query('SELECT * FROM passkeys WHERE id=$1',[id])).rows[0]||null;
}
export async function updatePasskeyCounter(id,oldCounter,info){
  return (await query('UPDATE passkeys SET counter=$3,backed_up=$4,last_used_at=NOW() WHERE id=$1 AND counter=$2',
    [id,oldCounter,info.newCounter,info.credentialBackedUp])).rowCount===1;
}
export async function removePasskey(userId,id){await query('DELETE FROM passkeys WHERE user_id=$1 AND id=$2',[userId,id]);}
export async function createPasskeyChallenge(purpose,payload){
  const token=rand();
  await query('DELETE FROM passkey_challenges WHERE expires_at<NOW()');
  await query("INSERT INTO passkey_challenges(token_hash,purpose,payload,expires_at) VALUES($1,$2,$3::jsonb,NOW()+interval '5 minutes')",[digest(token),purpose,JSON.stringify(payload)]);
  return token;
}
export async function consumePasskeyChallenge(token,purpose){
  if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token))return null;
  return (await query('DELETE FROM passkey_challenges WHERE token_hash=$1 AND purpose=$2 AND expires_at>NOW() RETURNING payload',[digest(token),purpose])).rows[0]?.payload||null;
}
export class PostgresOidcAdapter {
  constructor(model){this.model=model;}
  async upsert(id,payload,expiresIn){
    const exp=Number.isFinite(expiresIn)?Math.floor(Date.now()/1000)+expiresIn:null;
    await query(`INSERT INTO oidc_objects(model,id,payload,expires_at,grant_id,uid,user_code)
      VALUES($1,$2,$3::jsonb,CASE WHEN $4::bigint IS NULL THEN NULL ELSE to_timestamp($4::bigint) END,$5,$6,$7)
      ON CONFLICT(model,id) DO UPDATE SET payload=EXCLUDED.payload,expires_at=EXCLUDED.expires_at,
      grant_id=EXCLUDED.grant_id,uid=EXCLUDED.uid,user_code=EXCLUDED.user_code`,
    [this.model,id,JSON.stringify(payload),exp,payload.grantId||null,payload.uid||null,payload.userCode||null]);
  }
  async find(id){
    const r=await query('SELECT payload FROM oidc_objects WHERE model=$1 AND id=$2 AND (expires_at IS NULL OR expires_at>NOW())',[this.model,id]);
    return r.rows[0]?.payload;
  }
  async findByUid(uid){
    const r=await query('SELECT payload FROM oidc_objects WHERE model=$1 AND uid=$2 AND (expires_at IS NULL OR expires_at>NOW())',[this.model,uid]);
    return r.rows[0]?.payload;
  }
  async findByUserCode(userCode){
    const r=await query('SELECT payload FROM oidc_objects WHERE model=$1 AND user_code=$2 AND (expires_at IS NULL OR expires_at>NOW())',[this.model,userCode]);
    return r.rows[0]?.payload;
  }
  async destroy(id){await query('DELETE FROM oidc_objects WHERE model=$1 AND id=$2',[this.model,id]);}
  async consume(id){
    await query("UPDATE oidc_objects SET payload=jsonb_set(payload,'{consumed}',to_jsonb($3::bigint),true) WHERE model=$1 AND id=$2",[this.model,id,Math.floor(Date.now()/1000)]);
  }
  async revokeByGrantId(grantId){await query('DELETE FROM oidc_objects WHERE grant_id=$1',[grantId]);}
}
