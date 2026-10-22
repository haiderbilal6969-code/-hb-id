(() => {
  const form=document.getElementById('reset-form');
  const status=document.getElementById('reset-status');
  const login=document.getElementById('reset-login');
  let token=new URLSearchParams(location.hash.slice(1)).get('token')||'';
  // Remove the credential from browser history; it never enters a query string.
  history.replaceState(null,'',location.pathname);
  if(!/^[A-Za-z0-9_-]{43}$/.test(token))return;
  form.hidden=false;
  status.textContent='Your recovery link can be used once. Enter your new password below.';
  form.addEventListener('submit',async(event)=>{
    event.preventDefault();
    const password=form.elements.password.value, confirm=form.elements.confirm.value;
    if(password.length<14||password.length>200||password!==confirm){status.textContent='Use matching passwords of 14–200 characters.';return;}
    const button=form.querySelector('button');button.disabled=true;
    try{
      const response=await fetch(form.action,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({token,password,confirm})});
      await HBID.jsonResponse(response);
      token='';form.reset();form.hidden=true;login.hidden=false;status.classList.add('ok');
      status.textContent='Password saved. Sign in with your account email and new password.';
    }catch(error){status.textContent=error.name==='TypeError'?'Connection interrupted. Try signing in with your new password first; if it did not save, reopen your recovery link.':error.message;}
    finally{button.disabled=false;}
  });
})();
