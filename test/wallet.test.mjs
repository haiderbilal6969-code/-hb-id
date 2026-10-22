import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createWalletPass,walletPassBody,getWalletUsage} from '../src/wallet.mjs';
const issuer='https://identity.example';
const serialNumber='de9583fe-7209-4f13-88dd-74a02a404415';
const response={serialNumber,googleSaveUrl:'https://pay.google.com/gp/v/save/test-only',shareUrl:`https://pass.walletwallet.dev/p/${serialNumber}`};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
test('QR remains a public sign-in link and contains no account credential',()=>{
 const pass=walletPassBody({issuer,name:'Member'});
 assert.equal(pass.barcodeValue,`${issuer}/wallet/login`);
 assert.equal(new URL(pass.barcodeValue).search,'');
 assert.equal('password' in pass,false);
 assert.equal('credentials' in pass,false);
 assert.throws(()=>walletPassBody({issuer:'https://user:password@identity.example',name:'Member'}));
});
test('creates a Google save link using free-plan fields and a server-only API key',async()=>{
 const calls=[];
 const pass=await createWalletPass({name:'Member'},{issuer,apiKey:'test-provider-key',fetchImpl:async(url,options)=>{
  calls.push({url,options});
  return calls.length===1?json({remaining:1}):json(response);
 }});
 assert.equal(pass.googleSaveUrl,response.googleSaveUrl);
 assert.equal(calls.length,2);
 const body=JSON.parse(calls[1].options.body);
 assert.equal(body.colorPreset,'dark');
 for(const field of ['credentials','featuredActions','logoURL','color','email','password','session'])assert.equal(field in body,false);
 assert.equal(calls[1].options.body.includes('test-provider-key'),false);
 assert.equal(calls[1].options.headers.Authorization,'Bearer test-provider-key');
 assert.equal(calls[1].options.redirect,'error');
});
test('an exhausted or unknown quota never issues a pass',async()=>{
 for(const usage of [{remaining:0},{remaining:-1},{}]) {
  let calls=0;
  await assert.rejects(createWalletPass({name:'Member'},{issuer,apiKey:'test',fetchImpl:async()=>{calls++;return json(usage);}}),e=>e.code==='quota_reached'&&!e.uncertain);
  assert.equal(calls,1);
 }
});
test('network failures after creation starts are uncertain and must not auto-retry',async()=>{
 let calls=0;
 await assert.rejects(createWalletPass({name:'Member'},{issuer,apiKey:'test',fetchImpl:async()=>{
  if(++calls===1)return json({remaining:1});
  throw Error('timeout');
 }}),e=>e.code==='creation_uncertain'&&e.uncertain);
 assert.equal(calls,2);
});
test('untrusted provider links cannot become portal redirect targets',async()=>{
 let calls=0;
 await assert.rejects(createWalletPass({name:'Member'},{issuer,apiKey:'test',fetchImpl:async()=>++calls===1?json({remaining:1}):json({...response,googleSaveUrl:'https://attacker.example/save'})}),e=>e.uncertain);
});
test('provider rejection is retryable without leaking its response',async()=>{
 let calls=0;
 await assert.rejects(createWalletPass({name:'Member'},{issuer,apiKey:'test',fetchImpl:async()=>++calls===1?json({remaining:1}):json({error:'provider-private-data'},401)}),e=>e.code==='provider_auth'&&!e.uncertain&&!e.message.includes('provider-private-data'));
});
test('Wallet connection check reads usage without issuing or revealing provider data',async()=>{
 const calls=[];
 const usage=await getWalletUsage({apiKey:'private-test-key',fetchImpl:async(url,options)=>{
  calls.push({url,options});return json({remaining:12,limit:20,count:8,plan:'free',privateField:'must-not-leak'});
 }});
 assert.equal(calls.length,1);assert.equal(calls[0].url,'https://api.walletwallet.dev/api/auth/usage');
 assert.equal(calls[0].options.method,undefined);assert.equal(calls[0].options.redirect,'error');
 assert.deepEqual(usage,{remaining:12,limit:20,count:8,plan:'free'});
 assert.equal(JSON.stringify(usage).includes('private'),false);
 for(const status of [401,500])await assert.rejects(getWalletUsage({apiKey:'private-test-key',fetchImpl:async()=>json({error:'private-provider-message'},status)}),e=>!e.message.includes('private-provider-message'));
});
