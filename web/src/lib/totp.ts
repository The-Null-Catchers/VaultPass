export function base32(secret:string) {
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", s=secret.toUpperCase().replace(/\s|=/g,"");
  let bits=0,value=0; const out=[];
  for(const c of s) {const n=alphabet.indexOf(c);if(n<0) throw new Error("Invalid Base32 secret");value=(value<<5)|n;bits+=5;if(bits>=8){bits-=8;out.push((value>>>bits)&255);}}
  if(!out.length) throw new Error("Empty TOTP secret");
  return new Uint8Array(out);
}
export async function totp(secret:string, timestamp=Date.now(), digits=6, period=30, algorithm="SHA-1") {
  if(![6,8].includes(digits) || period<15 || period>120) throw new Error("Unsupported TOTP parameters");
  const counter=new Uint8Array(8);new DataView(counter.buffer).setBigUint64(0,BigInt(Math.floor(timestamp/1000/period)));
  const key=await crypto.subtle.importKey("raw",base32(secret),{name:"HMAC",hash:algorithm},false,["sign"]);
  const mac=new Uint8Array(await crypto.subtle.sign("HMAC",key,counter));
  const offset=mac[mac.length-1]&15;
  const binary=((mac[offset]&127)<<24)|(mac[offset+1]<<16)|(mac[offset+2]<<8)|mac[offset+3];
  return (binary%10**digits).toString().padStart(digits,"0");
}
