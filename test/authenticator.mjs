// A synthetic authenticator for protocol tests. Never used by the application.
import {generateKeyPairSync,createHash,randomBytes,sign} from 'node:crypto';
import {isoCBOR} from '@simplewebauthn/server/helpers';
const hash=value=>createHash('sha256').update(value).digest();
const b64=value=>Buffer.from(value).toString('base64url');
export function testAuthenticator(origin){
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});
  const jwk=publicKey.export({format:'jwk'});
  const id=randomBytes(32),rpHash=hash(new URL(origin).hostname);
  const cose=isoCBOR.encode(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
  let handle;
  return {id:b64(id),
    register(options,{wrongOrigin=false}={}){
      handle=options.user.id;
      const length=Buffer.alloc(2);length.writeUInt16BE(id.length);
      const authData=Buffer.concat([rpHash,Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),length,id,Buffer.from(cose)]);
      const attestation=isoCBOR.encode(new Map([['fmt','none'],['attStmt',new Map()],['authData',new Uint8Array(authData)]]));
      return {id:b64(id),rawId:b64(id),type:'public-key',clientExtensionResults:{},response:{
        clientDataJSON:b64(JSON.stringify({type:'webauthn.create',challenge:options.challenge,origin:wrongOrigin?'https://untrusted.example':origin,crossOrigin:false})),
        attestationObject:b64(attestation),transports:['internal']}};
    },
    authenticate(options,{counter=1,wrongOrigin=false,unverified=false,badSignature=false}={}){
      const clientData=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:options.challenge,origin:wrongOrigin?'https://untrusted.example':origin,crossOrigin:false}));
      const count=Buffer.alloc(4);count.writeUInt32BE(counter);
      const authData=Buffer.concat([rpHash,Buffer.from([unverified?0x01:0x05]),count]);
      const signature=sign('sha256',Buffer.concat([authData,hash(clientData)]),privateKey);
      if(badSignature)signature[signature.length-1]^=1;
      return {id:b64(id),rawId:b64(id),type:'public-key',clientExtensionResults:{},response:{
        clientDataJSON:b64(clientData),authenticatorData:b64(authData),signature:b64(signature),userHandle:handle}};
    }
  };
}
