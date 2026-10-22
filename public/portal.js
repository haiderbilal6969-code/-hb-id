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
    const response=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(response.redirected){location.assign(response.url);return null;}
    const result=await response.json();
    if(!response.ok)throw new Error(result.error||'Please try again.');
    return result;
  }
  function errorMessage(error){
    if(error.name==='NotAllowedError'||error.code==='ERROR_CEREMONY_ABORTED')return 'Passkey prompt closed. You can try again or use your password.';
    if(error.name==='InvalidStateError')return 'This device already has a passkey for your account.';
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
