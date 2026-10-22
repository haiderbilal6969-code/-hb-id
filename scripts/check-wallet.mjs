import {getWalletUsage,WalletServiceError} from '../src/wallet.mjs';
// Optional deployment diagnostic: checks authentication and quota, never issues
// a pass and never prints a key, provider response body, or bearer header.
if(!process.env.WALLETWALLET_API_KEY)console.log('HB ID Wallet check:',JSON.stringify({status:'not_configured'}));
else{
  try{
    const usage=await getWalletUsage();
    console.log('HB ID Wallet check:',JSON.stringify({status:'connected',...usage}));
  }catch(error){console.log('HB ID Wallet check:',JSON.stringify({status:error instanceof WalletServiceError?error.code:'provider_unavailable'}));}
}
