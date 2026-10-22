(() => {
  const form=document.getElementById('verify-email-form');
  const status=document.getElementById('verify-email-status');
  const login=document.getElementById('verify-email-login');
  let token=new URLSearchParams(location.hash.slice(1)).get('token')||'';
  // Keep the one-use credential out of request URLs, logs and browser history.
  history.replaceState(null,'',location.pathname);
  if(!/^[A-Za-z0-9_-]{43}$/.test(token))return;
  form.hidden=false;
  status.textContent='Choose your display name and a unique password to finish creating your HB ID.';
  form.addEventListener('submit',async event=>{
    event.preventDefault();
    const name=form.elements.name.value.trim(),password=form.elements.password.value,confirm=form.elements.confirm.value;
    if(name.length<2||name.length>100||password.length<14||password.length>200||password!==confirm){
      status.textContent='Enter a name of 2–100 characters and matching passwords of 14–200 characters.';return;
    }
    const button=form.querySelector('button');button.disabled=true;
    try{
      const response=await fetch(form.action,{method:'POST',credentials:'same-origin',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({token,name,password,confirm})});
      const result=await response.json();
      if(!response.ok){status.textContent=result.error||'Unable to create the account. Please try again.';return;}
      token='';form.reset();form.hidden=true;login.hidden=false;status.classList.add('ok');
      status.textContent='Your email is verified and your HB ID is ready. Sign in with your email and new password.';
    }catch{status.textContent='Connection interrupted. Try signing in first; if your account was not created, reopen your email link.';}
    finally{button.disabled=false;}
  });
})();
