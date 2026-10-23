import {test} from 'node:test';
import assert from 'node:assert/strict';
import {supabaseSettings,sendSupabaseCode,verifySupabaseCode,EmailAuthError} from '../src/supabase-auth.mjs';

const configured={SUPABASE_URL:'https://example.supabase.co',SUPABASE_PUBLISHABLE_KEY:'sb_publishable_local_fixture',SUPABASE_AUTH_ENABLED:'true'};
const identity={id:'176d982d-5c5e-4da7-8cd2-fc32c35838cd',email:'member@example.invalid',email_confirmed_at:new Date().toISOString(),aud:'authenticated',role:'authenticated',app_metadata:{provider:'email'},user_metadata:{is_admin:true}};
const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
const withSettings=async callback=>{
  const previous=Object.fromEntries(Object.keys(configured).map(k=>[k,process.env[k]]));
  Object.assign(process.env,configured);
  try{await callback();}finally{for(const[k,v]of Object.entries(previous)){if(v===undefined)delete process.env[k];else process.env[k]=v;}}
};

test('email sign-in fails closed for non-publishable keys, invalid origins and an absent activation switch',()=>{
  assert.equal(supabaseSettings(configured).ready,true);
  for(const patch of [{SUPABASE_PUBLISHABLE_KEY:'service_role_private_fixture'},{SUPABASE_URL:'https://example.supabase.co.attacker.invalid'},{SUPABASE_URL:'http://example.supabase.co'},{SUPABASE_URL:'https://example.supabase.co/other'},{SUPABASE_AUTH_ENABLED:'false'}])
    assert.equal(supabaseSettings({...configured,...patch}).ready,false);
});
test('provider verification requires a fresh authoritative, confirmed matching user and revokes its temporary refresh session',async()=>withSettings(async()=>{
  const calls=[];
  const transport=async(url,init)=>{
    calls.push({url:String(url),init});
    if(String(url).includes('/verify'))return json({access_token:'local-access-fixture',refresh_token:'local-refresh-fixture',expires_in:3600,token_type:'bearer',user:identity});
    if(String(url).includes('/user'))return json(identity);
    if(String(url).includes('/logout'))return new Response(null,{status:204});
    throw new Error('Unexpected endpoint');
  };
  const user=await verifySupabaseCode(identity.email,'123456',transport);
  assert.deepEqual(user,{id:identity.id,email:identity.email});
  assert.equal(user.is_admin,undefined,'Editable provider metadata cannot grant an HB ID role');
  assert.ok(calls.some(c=>c.url.endsWith('/user')),'The Auth server validates the user');
  assert.ok(calls.some(c=>c.url.includes('/logout?scope=local')),'The unused refresh session is revoked');
  assert.ok(calls.every(c=>c.init.signal),'Every provider call is time bounded');
}));
test('unconfirmed, mismatched, anonymous and second-factor identities cannot authenticate with email alone',async()=>withSettings(async()=>{
  for(const patch of [{email_confirmed_at:null},{email:'other@example.invalid'},{is_anonymous:true},{factors:[{status:'verified',factor_type:'totp'}]}]){
    const transport=async(url)=>String(url).includes('/verify')?json({access_token:'local-access',refresh_token:'local-refresh',expires_in:3600,token_type:'bearer',user:identity}):String(url).includes('/user')?json({...identity,...patch}):new Response(null,{status:204});
    await assert.rejects(verifySupabaseCode(identity.email,'123456',transport),EmailAuthError);
  }
}));
test('delivery and verification failures do not expose provider response details',async()=>withSettings(async()=>{
  const denied=async()=>json({code:'unexpected_failure',msg:'private provider response must stay private'},400);
  await assert.rejects(sendSupabaseCode(identity.email,denied),e=>e instanceof EmailAuthError&&!e.message.includes('private'));
  await assert.rejects(verifySupabaseCode(identity.email,'123456',denied),e=>e instanceof EmailAuthError&&!e.message.includes('private'));
  await assert.rejects(verifySupabaseCode(identity.email,'not-a-code',()=>{throw new Error('Should not call provider');}),EmailAuthError);
}));
