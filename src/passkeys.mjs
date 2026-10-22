import {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {findByEmail,findById,verifyPassword,listPasskeys,savePasskey,findPasskey,updatePasskeyCounter,
  removePasskey,createPasskeyChallenge,consumePasskeyChallenge,digest,recordSecurityEvent} from './db.mjs';

export function installPasskeyRoutes(app,{issuerUrl,originGuard,requirePortal,csrfGuard,rateLimit,
  clearRateLimit,cookies,provider,finishPortalLogin}){
  const secure=issuerUrl.protocol==='https:';
  const cookieOptions={httpOnly:true,secure,sameSite:'strict',path:'/',maxAge:300000};
  const cookieName=secure?'__Host-hb_passkey':'hb_passkey';
  const fail=(res,message='The passkey could not be verified. Please try again.',status=400)=>res.status(status).json({error:message});
  function setChallenge(res,token){res.cookie(cookieName,token,cookieOptions);}
  async function takeChallenge(req,res,purpose){
    res.clearCookie(cookieName,{httpOnly:true,secure,sameSite:'strict',path:'/'});
    return consumePasskeyChallenge(cookies(req).hb_passkey,purpose);
  }
  async function interaction(req,res){
    const details=await provider.interactionDetails(req,res);
    if(details.uid!==req.params.uid||details.prompt.name!=='login')throw new Error('Invalid interaction');
    return details;
  }
  app.post('/portal/passkeys/register/options',originGuard,requirePortal,csrfGuard,rateLimit,async(req,res)=>{
    const account=await findByEmail(req.portalSession.email);
    if(!account||typeof req.body.password!=='string'||!await verifyPassword(req.body.password,account.password_hash))return fail(res,'Your current password is incorrect.',401);
    const passkeys=await listPasskeys(account.id);
    if(passkeys.length>=10)return fail(res,'You can keep up to 10 passkeys. Remove one before adding another.');
    const name=String(req.body.name||'My passkey').trim();
    if(name.length<2||name.length>60)return fail(res,'Give your passkey a name of 2–60 characters.');
    const options=await generateRegistrationOptions({rpName:'HB ID',rpID:issuerUrl.hostname,
      userID:Buffer.from(String(account.id)),userName:account.email,userDisplayName:account.name,
      attestationType:'none',supportedAlgorithmIDs:[-7,-257],
      excludeCredentials:passkeys.map(p=>({id:p.id,transports:p.transports})),
      authenticatorSelection:{residentKey:'required',userVerification:'required'}});
    const token=await createPasskeyChallenge('register',{challenge:options.challenge,userId:String(account.id),
      session:digest(cookies(req).hb_portal),name});
    setChallenge(res,token);await clearRateLimit(req);res.json(options);
  });
  app.post('/portal/passkeys/register/verify',originGuard,requirePortal,csrfGuard,async(req,res)=>{
    const saved=await takeChallenge(req,res,'register');
    if(!saved||saved.userId!==String(req.portalSession.id)||saved.session!==digest(cookies(req).hb_portal))return fail(res,'This passkey setup expired. Start again.');
    let result;
    try{result=await verifyRegistrationResponse({response:req.body.credential,expectedChallenge:saved.challenge,
      expectedOrigin:issuerUrl.origin,expectedRPID:issuerUrl.hostname,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]});}
    catch{return fail(res);}
    if(!result.verified)return fail(res);
    try{if(!await savePasskey(saved.userId,saved.name,result.registrationInfo,saved.session))return fail(res,'Your session expired. Sign in and start again.');}
    catch(error){if(error.code==='23505')return fail(res,'That passkey is already registered.');throw error;}
    await recordSecurityEvent(saved.userId,'passkey_added');
    res.json({ok:true,redirect:'/portal/security?result=passkey-added'});
  });
  app.post('/portal/passkeys/remove',originGuard,requirePortal,csrfGuard,rateLimit,async(req,res)=>{
    const account=await findByEmail(req.portalSession.email);
    if(!account||typeof req.body.password!=='string'||!await verifyPassword(req.body.password,account.password_hash))return res.redirect(303,'/portal/security?result=password-incorrect');
    await removePasskey(account.id,String(req.body.id||''));await clearRateLimit(req);
    await recordSecurityEvent(account.id,'passkey_removed');
    res.redirect(303,'/portal/security?result=passkey-removed');
  });
  async function options(req,res){
    let uid=null;
    if(req.params.uid){try{uid=(await interaction(req,res)).uid;}catch{return fail(res,'Restart sign-in from the connected website.');}}
    const result=await generateAuthenticationOptions({rpID:issuerUrl.hostname,allowCredentials:[],userVerification:'required'});
    setChallenge(res,await createPasskeyChallenge('authenticate',{challenge:result.challenge,uid}));
    res.json(result);
  }
  async function verify(req,res){
    const saved=await takeChallenge(req,res,'authenticate');
    if(!saved||saved.uid!==(req.params.uid||null))return fail(res,'This sign-in request expired. Start again.');
    if(saved.uid){try{await interaction(req,res);}catch{return fail(res,'Restart sign-in from the connected website.');}}
    const credential=await findPasskey(req.body.credential?.id);
    if(!credential)return fail(res);
    const handle=req.body.credential?.response?.userHandle;
    // Discoverable credentials are tied to the internal account, never a supplied email.
    if(!handle||handle!==Buffer.from(String(credential.user_id)).toString('base64url'))return fail(res);
    let result;
    try{result=await verifyAuthenticationResponse({response:req.body.credential,expectedChallenge:saved.challenge,
      expectedOrigin:issuerUrl.origin,expectedRPID:issuerUrl.hostname,requireUserVerification:true,
      credential:{id:credential.id,publicKey:new Uint8Array(credential.public_key),counter:Number(credential.counter),transports:credential.transports}});}
    catch{return fail(res);}
    if(!result.verified||!await updatePasskeyCounter(credential.id,credential.counter,result.authenticationInfo))return fail(res);
    if(!await findById(credential.user_id))return fail(res);
    await clearRateLimit(req);
    if(saved.uid){
      const redirect=await provider.interactionResult(req,res,{login:{accountId:String(credential.user_id),amr:['webauthn']}},{mergeWithLastSubmission:false});
      await recordSecurityEvent(credential.user_id,'passkey_sign_in');
      res.json({ok:true,redirect});
    }else{
      if(!await finishPortalLogin(req,res,credential.user_id,{passkeyId:credential.id}))return fail(res);
      await recordSecurityEvent(credential.user_id,'passkey_sign_in');
      res.json({ok:true,redirect:'/portal'});
    }
  }
  app.post('/portal/passkeys/login/options',originGuard,rateLimit,options);
  app.post('/portal/passkeys/login/verify',originGuard,rateLimit,verify);
  app.post('/interaction/:uid/passkeys/options',originGuard,rateLimit,options);
  app.post('/interaction/:uid/passkeys/verify',originGuard,rateLimit,verify);
}
