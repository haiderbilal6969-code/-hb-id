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
  const result = await scrypt(password, salt, 64, { N:16384, r:8, p:1, maxmem:33554432 });
  return `scrypt$16384$${salt.toString('hex')}$${result.toString('hex')}`;
}
export async function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.startsWith('scrypt$16384$')) return false;
  const pieces=stored.split('$');
  if (pieces.length !== 4 || !/^[a-f0-9]{32}$/.test(pieces[2]) || !/^[a-f0-9]{128}$/.test(pieces[3])) return false;
  const expected=Buffer.from(pieces[3], 'hex');
  const actual=await scrypt(password, Buffer.from(pieces[2], 'hex'), 64, { N:16384, r:8, p:1, maxmem:33554432 });
  return timingSafeEqual(expected,actual);
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
    await query(`CREATE TABLE IF NOT EXISTS system_config (
      name TEXT PRIMARY KEY, value JSONB NOT NULL
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
export async function createDashboardSession(userId){
  const token=rand(32); const csrf=rand(24);
  await query("INSERT INTO dashboard_sessions (token_hash,user_id,csrf,expires_at) VALUES ($1,$2,$3,NOW()+interval '12 hours')",[digest(token),userId,csrf]);
  return token;
}
export async function getDashboardSession(token){
  if(!token) return null;
  const r=await query(`SELECT s.*,u.name,u.email,u.is_admin,u.id FROM dashboard_sessions s
      JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()`,[digest(token)]);
  return r.rows[0]||null;
}
export async function deleteDashboardSession(token){ if(token) await query('DELETE FROM dashboard_sessions WHERE token_hash=$1',[digest(token)]); }
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
