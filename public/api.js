(() => {
  const messages={
    400:'This request could not be completed. Refresh the page and try again.',
    401:'Your session has expired. Sign in again to continue.',
    403:'The security check failed. Reopen HB ID and try again.',
    404:'This action is unavailable. Refresh HB ID and try again.',
    413:'This request is too large. Please try again.',
    429:'Too many attempts. Wait 15 minutes before trying again.',
    500:'HB ID could not complete this request. Please try again shortly.',
    503:'HB ID is temporarily unavailable. Please try again shortly.'
  };
  async function jsonResponse(response){
    const fallback=messages[response.status]||'HB ID returned an unexpected response. Refresh the page and try again.';
    if(!/\bapplication\/(?:[\w.-]+\+)?json\b/i.test(response.headers.get('content-type')||''))throw new Error(fallback);
    let result;
    try{result=await response.json();}catch{throw new Error(fallback);}
    if(!result||typeof result!=='object'||Array.isArray(result))throw new Error(fallback);
    if(!response.ok){
      const error=new Error(typeof result.error==='string'?result.error.slice(0,300):fallback);
      error.status=response.status;
      if(response.status===401&&result.redirect==='/portal/login')error.redirect=result.redirect;
      throw error;
    }
    return result;
  }
  window.HBID=Object.freeze({jsonResponse});
})();
