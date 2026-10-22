(() => {
  for(const button of document.querySelectorAll('[data-copy]'))button.addEventListener('click',async()=>{
    const target=document.getElementById(button.dataset.copy);
    try{await navigator.clipboard.writeText(target.textContent);button.textContent='Copied';setTimeout(()=>button.textContent='Copy',1800);}
    catch{button.textContent='Select and copy the text below';}
  });
  const status=document.getElementById('passkey-status');
  const register=document.getElementById('passkey-register');
  const signIn=document.getElementById('passkey-login');
  async function send(url,body){
    const response=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify(body)});
    if(response.redirected){
      const target=new URL(response.url,location.href);
      if(target.origin!==location.origin)throw new Error('Open HB ID directly in your browser and try again.');
      location.assign(target.href);return null;
    }
    try{return await HBID.jsonResponse(response);}
    catch(error){if(error.redirect){location.assign(error.redirect);return null;}throw error;}
  }
  function errorMessage(error){
    if(error.name==='NotAllowedError'||error.code==='ERROR_CEREMONY_ABORTED')return 'No passkey was used. Try again, or sign in with your password and add a passkey in Security.';
    if(error.name==='InvalidStateError')return 'This device already has a passkey for your account.';
    if(error.name==='TypeError')return 'Could not connect to HB ID. Check your connection or open HB ID in Chrome.';
    if(error.name==='SyntaxError')return 'HB ID returned an unexpected response. Refresh the page and try again.';
    return error.message||'Passkey unavailable. Try your main browser or use your password.';
  }
  if(register||signIn){
    const supported=window.isSecureContext&&window.SimpleWebAuthnBrowser?.browserSupportsWebAuthn();
    if(!supported){
      if(register)register.querySelector('button').disabled=true;
      if(signIn)signIn.disabled=true;
      status.textContent='Passkeys are unavailable in this browser. Open HB ID in Chrome or use your password.';
      return;
    }
  }
  register?.addEventListener('submit',async event=>{
    event.preventDefault();const button=register.querySelector('button');button.disabled=true;status.textContent='Confirm with your device when prompted.';
    const csrf=register.elements._csrf.value;
    try{
      const optionsJSON=await send('/portal/passkeys/register/options',{_csrf:csrf,name:register.elements.name.value,password:register.elements.password.value});
      register.elements.password.value='';if(!optionsJSON)return;
      const credential=await SimpleWebAuthnBrowser.startRegistration({optionsJSON});
      const result=await send('/portal/passkeys/register/verify',{_csrf:csrf,credential});
      if(result?.ok)location.assign(result.redirect);
    }catch(error){status.textContent=errorMessage(error);}finally{button.disabled=false;register.elements.password.value='';}
  });
  signIn?.addEventListener('click',async()=>{
    signIn.disabled=true;status.textContent='Choose your HB ID passkey.';
    try{
      const base=signIn.dataset.base;
      const optionsJSON=await send(base+'/options',{});if(!optionsJSON)return;
      const credential=await SimpleWebAuthnBrowser.startAuthentication({optionsJSON});
      const result=await send(base+'/verify',{credential});
      if(result?.ok)location.assign(result.redirect);
    }catch(error){status.textContent=errorMessage(error);}finally{signIn.disabled=false;}
  });
})();
