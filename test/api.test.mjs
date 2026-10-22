import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const context=vm.createContext({window:{}});
vm.runInContext(await readFile(new URL('../public/api.js',import.meta.url),'utf8'),context);
const parse=context.window.HBID.jsonResponse;
test('HTML error pages never become a raw JSON parser error',async()=>{
  for(const status of [400,401,403,404,429,500,503]){
    await assert.rejects(parse(new Response('<!doctype html><h1>private server details</h1>',{status,headers:{'Content-Type':'text/html'}})),error=>{
      assert.doesNotMatch(error.message,/Unexpected token|doctype|private server details|JSON/i);
      if(status===429)assert.match(error.message,/15 minutes/);
      return true;
    });
  }
});
test('valid JSON preserves safe API errors and session recovery',async()=>{
  await assert.rejects(parse(new Response(JSON.stringify({error:'Your session expired.',redirect:'/portal/login'}),{status:401,headers:{'Content-Type':'application/json'}})),e=>e.status===401&&e.redirect==='/portal/login');
  await assert.rejects(parse(new Response(JSON.stringify({error:'Forbidden',redirect:'https://untrusted.example'}),{status:403,headers:{'Content-Type':'application/json'}})),e=>!e.redirect);
  const result=await parse(new Response(JSON.stringify({challenge:'test-challenge'}),{headers:{'Content-Type':'application/json'}}));
  assert.equal(result.challenge,'test-challenge');
});
test('malformed JSON and successful HTML use a readable fallback',async()=>{
  for(const response of [new Response('{bad-json',{headers:{'Content-Type':'application/json'}}),new Response('<html>proxy sign-in</html>',{headers:{'Content-Type':'text/html'}})])
    await assert.rejects(parse(response),e=>!/Unexpected token|proxy sign-in|bad-json/.test(e.message));
});
test('passkey button shows a useful message when an intermediary returns HTML',async()=>{
 let click;
 const status={textContent:''};
 const button={dataset:{base:'/portal/passkeys/login'},addEventListener(event,callback){click=callback;}};
 const sandbox=vm.createContext({window:{isSecureContext:true,SimpleWebAuthnBrowser:{browserSupportsWebAuthn:()=>true}},
  document:{querySelectorAll:()=>[],getElementById:id=>id==='passkey-status'?status:id==='passkey-login'?button:null},
  fetch:async()=>new Response('<!doctype html><h1>Blocked</h1>',{status:403,headers:{'Content-Type':'text/html'}}),
  location:{href:'https://identity.example/portal/login',origin:'https://identity.example'},URL});
 vm.runInContext(await readFile(new URL('../public/api.js',import.meta.url),'utf8'),sandbox);
 sandbox.HBID=sandbox.window.HBID;
 vm.runInContext(await readFile(new URL('../public/portal.js',import.meta.url),'utf8'),sandbox);
 await click();
 assert.match(status.textContent,/security check/i);assert.doesNotMatch(status.textContent,/Unexpected token|JSON|doctype/);
 assert.equal(button.disabled,false);
});
