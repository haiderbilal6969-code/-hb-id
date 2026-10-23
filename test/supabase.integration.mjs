import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash} from 'node:crypto';

export async function checkSupabaseIntegration({request,follow,app,db,jar,issuer,ownerPassword}){
  const emailAuth=await import('../src/email-auth.mjs');
  const owner=await db.findByEmail('owner@example.invalid');
  const ownerId=owner.id,remoteId=randomUUID();
  const beforePass=await db.getWalletPass(ownerId);
  assert.equal((await request('/portal/email')).status,503,'Email auth is unavailable before explicit activation');
  process.env.SUPABASE_URL='https://fixture.supabase.co';
  process.env.SUPABASE_PUBLISHABLE_KEY='sb_publishable_local_auth_fixture';
  process.env.SUPABASE_AUTH_ENABLED='true';
  const identities=new Map([['owner@example.invalid',{id:remoteId,email:'owner@example.invalid',email_confirmed_at:new Date().toISOString()}]]);
  let providerEmail,providerCalls=0;
  const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
  app.locals.supabaseAuthFetch=async(url,init)=>{
    providerCalls++;
    const u=new URL(url);
    if(u.pathname.endsWith('/otp')){
      const data=JSON.parse(init.body);providerEmail=data.email;
      if(!identities.has(providerEmail))identities.set(providerEmail,{id:randomUUID(),email:providerEmail,email_confirmed_at:new Date().toISOString()});
      return json({});
    }
    if(u.pathname.endsWith('/verify')){
      const data=JSON.parse(init.body);
      if(data.token!=='123456')return json({code:'otp_expired',msg:'Expired'},403);
      providerEmail=data.email;
      return json({access_token:'fixture-access-token',refresh_token:'fixture-refresh-token',token_type:'bearer',expires_in:3600,user:identities.get(data.email)});
    }
    if(u.pathname.endsWith('/user'))return json({...identities.get(providerEmail),user_metadata:{is_admin:true,name:'Untrusted provider name'}});
    if(u.pathname.endsWith('/logout'))return new Response(null,{status:204});
    throw new Error('Unexpected Supabase fixture request');
  };
  const clearLimits=async()=>{await db.query('DELETE FROM email_send_limits');await db.query('DELETE FROM auth_rate_limits');};
  const cookieToken=()=>[...jar.values()].map(v=>v.pair).find(c=>c.startsWith('hb_email='))?.slice('hb_email='.length);
  const send=async(email,base='/portal/email')=>{
    await clearLimits();
    const result=await request(base,{method:'POST',form:{email}});
    assert.equal(result.status,303);assert.equal(result.headers.get('location'),base+'/code');
    const setCookie=result.headers.getSetCookie().find(c=>c.startsWith('hb_email='));
    assert.match(setCookie,/HttpOnly/i);assert.match(setCookie,/SameSite=Strict/i);
    return cookieToken();
  };
  const verify=base=>request((base||'/portal/email')+'/verify',{method:'POST',form:{code:'123456',email:'attacker@example.invalid',is_admin:'true'}});

  assert.equal(JSON.parse((await request('/healthz')).text).authentication.emailCode,true);
  // The old browser session was revoked by earlier recovery tests.
  jar.clear();
  assert.match((await request('/portal/login')).text,/href="\/portal\/email"/);
  assert.equal((await request('/portal/signup')).headers.get('location'),'/portal/email');
  const foreign=await request('/portal/email',{method:'POST',form:{email:owner.email},headers:{Origin:'https://foreign.example'},browser:false});
  assert.equal(foreign.status,403);assert.equal(providerCalls,0);
  const token=await send(owner.email);
  const codePage=await request('/portal/email/code');
  assert.equal(codePage.status,200);assert.match(codePage.text,/autocomplete="one-time-code"/);
  assert.ok(await emailAuth.emailChallenge(token,'code'));
  assert.equal((await request('/portal/email',{method:'POST',form:{email:owner.email}})).status,429,'Persistent resend cooldown applies');
  assert.equal((await request('/portal/email/verify',{method:'POST',form:{code:'000000'}})).status,400);
  assert.equal((await verify()).status,303);
  assert.equal(await emailAuth.emailChallenge(token,'code'),null,'Successful OTP assertions are consumed');
  const verifiedToken=cookieToken();
  assert.notEqual(verifiedToken,token,'Browser binding rotates after proof of email');
  assert.match((await request('/portal/email')).text,/Confirm your existing HB ID password/);
  assert.equal((await db.findByEmail(owner.email)).supabase_user_id,null,'Email proof alone cannot link the owner');
  assert.equal((await request('/portal/email/complete',{method:'POST',form:{password:'incorrect-local-password'}})).status,400);
  const firstLink=await request('/portal/email/complete',{method:'POST',form:{password:ownerPassword,is_admin:'false',email:'attacker@example.invalid',supabaseId:randomUUID()}});
  assert.equal(firstLink.status,303);assert.equal(firstLink.headers.get('location'),'/portal');
  const linked=await db.findByEmail(owner.email);
  assert.equal(linked.id,ownerId);assert.equal(linked.is_admin,true);assert.equal(linked.supabase_user_id,remoteId);assert.equal(linked.email_verified,true);
  assert.deepEqual(await db.getWalletPass(ownerId),beforePass,'Linking preserves the saved Wallet card');
  assert.equal(await emailAuth.completeEmailAccount(verifiedToken,{password:ownerPassword}),null,'Verified challenges cannot be replayed');
  const security=await request('/portal/security');
  assert.match(security.text,/Email-code sign-in/);assert.match(security.text,/Disable email-code sign-in/);
  assert.doesNotMatch(security.text,/fixture-access-token|fixture-refresh-token|sb_publishable/);
  await send(owner.email);
  const nextLogin=await verify();
  assert.equal(nextLogin.status,303);assert.equal(nextLogin.headers.get('location'),'/portal','Linked users sign in without their local password');
  assert.equal((await request('/portal')).status,200);
  console.log('PASS: Supabase email code links the existing owner only after password confirmation, preserves Wallet and local identity, and supports later passwordless sign-in');

  const newEmail='new-email-code-member@example.invalid';
  await send(newEmail);assert.equal((await verify()).status,303);
  const signupPassword=randomBytes(24).toString('base64url');
  const signup={name:'Email Code Member',password:signupPassword,confirm:signupPassword,is_admin:'true',email:owner.email};
  assert.equal((await request('/portal/email/complete',{method:'POST',form:signup})).status,303);
  const member=await db.findByEmail(newEmail);
  assert.equal(member.is_admin,false);assert.equal(member.email_verified,true);assert.equal(member.name,'Email Code Member');
  assert.equal((await request('/portal/apps')).status,403,'Provider and browser metadata cannot grant owner permissions');
  await send('expiring@example.invalid');
  const expiredToken=cookieToken();
  await db.query("UPDATE email_auth_challenges SET expires_at=NOW()-interval '1 second' WHERE token_hash=$1",[db.digest(expiredToken)]);
  const callsBefore=providerCalls;
  assert.equal((await verify()).status,400);assert.equal(providerCalls,callsBefore,'Expired challenges fail before contacting the provider');
  await send('attempt-limit@example.invalid');
  for(let i=0;i<5;i++)assert.equal((await request('/portal/email/verify',{method:'POST',form:{code:'000000'}})).status,400);
  const afterAttempts=providerCalls;
  assert.equal((await verify()).status,400);assert.equal(providerCalls,afterAttempts,'The sixth code attempt cannot reach the provider');
  console.log('PASS: verified new signups remain members; expired and exhausted challenges fail closed without provider calls');

  // Complete the same email method inside a signed OIDC interaction and exchange
  // its code, proving the issuer and stable HB ID subject are preserved.
  await clearLimits();
  const created=await db.createClient('Email Code OIDC Test','https://email-client.example.invalid/callback');
  const verifier=randomBytes(32).toString('base64url');
  const params={client_id:created.clientId,redirect_uri:'https://email-client.example.invalid/callback',response_type:'code',scope:'openid profile email',state:db.rand(16),nonce:db.rand(16),prompt:'login',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'};
  let interaction=await follow(await request('/auth?'+new URLSearchParams(params)));
  const base=interaction.text.match(/href="(\/interaction\/[^\"]+\/email)"/)?.[1];
  assert.ok(base,'OIDC interaction offers the email-code method');
  assert.equal((await request(base)).status,200);
  await send(owner.email,base);
  assert.equal((await request('/portal/email/verify',{method:'POST',form:{code:'123456'}})).status,400,'An interaction-bound challenge cannot be used for a portal request');
  let result=await verify(base);
  assert.equal(result.status,303);
  result=await follow(result);
  if(!result.callback){
    const consent=result.text.match(/action="(\/interaction\/[^\"]+\/confirm)"/)?.[1];
    assert.ok(consent,'Email authentication still requires OIDC consent');
    result=await follow(await request(consent,{method:'POST',form:{}}));
  }
  assert.ok(result.callback?.searchParams.get('code'));
  const exchange=await request('/token',{method:'POST',browser:false,headers:{Authorization:'Basic '+Buffer.from(created.clientId+':'+created.secret).toString('base64')},form:{grant_type:'authorization_code',redirect_uri:params.redirect_uri,code:result.callback.searchParams.get('code'),code_verifier:verifier}});
  assert.equal(exchange.status,200);
  const oidcTokens=JSON.parse(exchange.text);
  const claims=JSON.parse(Buffer.from(oidcTokens.id_token.split('.')[1],'base64url'));
  assert.equal(claims.sub,ownerId);assert.equal(claims.iss,issuer);
  const userinfo=await request('/me',{browser:false,headers:{Authorization:'Bearer '+oidcTokens.access_token}});
  assert.equal(userinfo.status,200);assert.equal(JSON.parse(userinfo.text).email_verified,true);
  console.log('PASS: Supabase email sign-in completes OIDC consent and Authorization Code + PKCE with the existing HB ID subject and issuer');

  const portalPage=await request('/portal/security');
  const csrf=portalPage.text.match(/name="_csrf" value="([^\"]+)"/)?.[1];
  assert.ok(csrf);
  await send(owner.email);
  const stale=cookieToken();
  assert.equal((await request('/portal/email/unlink',{method:'POST',form:{current_password:ownerPassword}})).status,403);
  assert.equal((await request('/portal/email/unlink',{method:'POST',form:{_csrf:csrf,current_password:'incorrect'}})).headers.get('location'),'/portal/security?result=password-incorrect');
  const removed=await request('/portal/email/unlink',{method:'POST',form:{_csrf:csrf,current_password:ownerPassword}});
  assert.equal(removed.status,303);assert.equal((await db.findByEmail(owner.email)).supabase_user_id,null);
  assert.equal(await emailAuth.emailChallenge(stale,'code'),null);
  assert.equal((await request('/portal')).status,302);
  assert.equal(await db.createDashboardSession(ownerId,'',{supabaseUserId:remoteId,authVersion:linked.auth_version}),null,'Disabled email credentials cannot create late sessions');

  // Recovery also invalidates an in-flight verified assertion.
  await send(owner.email);await verify();
  const staleVerified=cookieToken();
  const reset=await import('../src/enrollment.mjs');
  const recovery=await reset.issueEmailResetToken(ownerId);
  assert.equal(await db.resetPasswordWithToken(recovery,ownerPassword),true);
  assert.equal(await emailAuth.completeEmailAccount(staleVerified,{password:ownerPassword}),null);
  assert.equal((await db.findByEmail(owner.email)).supabase_user_id,null);
  console.log('PASS: unlinking and password recovery revoke pending email assertions and prevent late session creation');
  delete process.env.SUPABASE_URL;delete process.env.SUPABASE_PUBLISHABLE_KEY;delete process.env.SUPABASE_AUTH_ENABLED;
}
