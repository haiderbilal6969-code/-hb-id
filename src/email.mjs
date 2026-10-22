import nodemailer from 'nodemailer';

// Server-only configuration. Credentials and message bodies are never logged.
export function emailSettings(env=process.env){
  const user=(env.SMTP_USER||'').trim();
  const from=(env.EMAIL_FROM||user).trim();
  const port=Number(env.SMTP_PORT||465);
  const host=(env.SMTP_HOST||'mail.spacemail.com').trim();
  const address=/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/;
  const ready=Boolean(address.test(user)&&address.test(from)&&env.SMTP_PASSWORD&&host&&[465,587].includes(port));
  return {ready,from,options:{host,port,secure:port===465,requireTLS:port===587,
    auth:{user,pass:env.SMTP_PASSWORD},tls:{minVersion:'TLSv1.2'},
    connectionTimeout:10000,greetingTimeout:10000,socketTimeout:15000,dnsTimeout:5000,
    disableFileAccess:true,disableUrlAccess:true,logger:false,debug:false}};
}

export async function sendAccountMail({to,purpose,token,issuer},transport){
  const settings=emailSettings();
  if(!settings.ready)throw Object.assign(new Error('Email delivery is not configured'),{code:'EMAIL_NOT_CONFIGURED'});
  // Always derive links from the configured issuer, never from a request Host header.
  const base=new URL(issuer);
  if(base.protocol!=='https:'&&!(base.protocol==='http:'&&['localhost','127.0.0.1'].includes(base.hostname)))throw new Error('Invalid email issuer');
  const signup=purpose==='signup';
  if(!signup&&purpose!=='reset')throw new Error('Invalid email purpose');
  if(!/^[A-Za-z0-9_-]{43}$/.test(token))throw new Error('Invalid email token');
  const url=new URL(signup?'/portal/verify-email':'/portal/reset-password',base);
  url.hash=new URLSearchParams({token}).toString();
  const subject=signup?'Verify your email for HB ID':'Reset your HB ID password';
  const text=`${signup?'Verify your email address, then choose your HB ID name and password.':'You requested a new password for your HB ID account.'}\n\n${url.href}\n\nThis link expires in 30 minutes and can be used once. If you did not request it, ignore this email.\n\nHB ID`;
  const sender=transport||nodemailer.createTransport(settings.options);
  const result=await sender.sendMail({from:{name:'HB ID',address:settings.from},to:{address:to},subject,text,
    disableFileAccess:true,disableUrlAccess:true});
  if(!result.accepted?.length)throw Object.assign(new Error('Email was not accepted'),{code:'EMAIL_REJECTED'});
}
