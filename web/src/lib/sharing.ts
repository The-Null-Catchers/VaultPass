import {b64,unb64,bytes,context,seal,open,encryptJSON,decryptJSON,Envelope,hex} from "./crypto";
const buf=(v:Uint8Array)=>new Uint8Array(v).buffer;
export async function createIdentity(accountKey:Uint8Array,userId:string){
 const pair=await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["encrypt","decrypt"]);
 const privateBytes=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
 try{return {public_key:b64(new Uint8Array(await crypto.subtle.exportKey("spki",pair.publicKey))),private_key:await seal(accountKey,privateBytes,context("sharing-private",userId))};}finally{privateBytes.fill(0);}
}
export async function fingerprint(publicKey:string){return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",buf(unb64(publicKey))))).match(/.{1,8}/g)!.join(" ");}
export async function encryptShare(data:unknown,publicKey:string,sender:string,recipient:string){
 const id=crypto.randomUUID(),key=bytes(32),label=new TextEncoder().encode(context("share-key",id,sender,recipient));
 try{const rsa=await crypto.subtle.importKey("spki",buf(unb64(publicKey)),{name:"RSA-OAEP",hash:"SHA-256"},false,["encrypt"]);
 return {id,recipient_id:recipient,wrapped_key:b64(new Uint8Array(await crypto.subtle.encrypt({name:"RSA-OAEP",label},rsa,buf(key)))),payload:await encryptJSON(key,data,context("share",id,sender,recipient))};}finally{key.fill(0);}
}
export async function decryptShare<T>(share:{id:string;sender_id:string;recipient_id:string;wrapped_key:string;payload:Envelope},accountKey:Uint8Array,privateEnvelope:Envelope){
 const privateBytes=await open(accountKey,privateEnvelope,context("sharing-private",share.recipient_id));
 try{const rsa=await crypto.subtle.importKey("pkcs8",buf(privateBytes),{name:"RSA-OAEP",hash:"SHA-256"},false,["decrypt"]);
 const key=new Uint8Array(await crypto.subtle.decrypt({name:"RSA-OAEP",label:new TextEncoder().encode(context("share-key",share.id,share.sender_id,share.recipient_id))},rsa,buf(unb64(share.wrapped_key))));
 try{return await decryptJSON<T>(key,share.payload,context("share",share.id,share.sender_id,share.recipient_id));}finally{key.fill(0);}
 }finally{privateBytes.fill(0);}
}
