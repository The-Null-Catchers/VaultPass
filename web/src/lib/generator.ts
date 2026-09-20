import { bytes } from "./crypto";
export function randomIndex(n: number): number {
  if (!Number.isSafeInteger(n) || n < 1 || n > 256) throw new Error("Invalid alphabet size");
  const limit=256-256%n;
  let x; do {x=bytes(1)[0];} while(x>=limit);
  return x%n;
}
export function generate(length=24, symbols=true, ambiguous=false) {
  if (!Number.isInteger(length) || length<12 || length>128) throw new Error("Choose 12–128 characters");
  const groups=["abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZ","0123456789",...(symbols?["!@#$%^&*()-_=+[]{}:?,."]:[])].map(g=>ambiguous?g:g.replace(/[Il1O0o]/g,""));
  const alphabet=groups.join("");
  // Rejection sampling gives a uniform distribution over strings satisfying all categories.
  let password: string;
  do {password=Array.from({length},()=>alphabet[randomIndex(alphabet.length)]).join("");} while(!groups.every(g=>[...password].some(c=>g.includes(c))));
  return {password, entropy:Math.floor(length*Math.log2(alphabet.length)), estimate:"Upper-bound entropy estimate before category constraints; not a security guarantee."};
}
export function health(items: {password?:string;username?:string;url?:string}[]) {
  const passwords=items.filter(i=>i.password);
  const counts=new Map<string,number>();
  for(const i of passwords) counts.set(i.password!, (counts.get(i.password!)||0)+1);
  return {total:passwords.length,weak:passwords.filter(i=>i.password!.length<14).length,reused:passwords.filter(i=>counts.get(i.password!)!>1).length};
}
export async function breachCount(password: string) {
  const digest=new Uint8Array(await crypto.subtle.digest("SHA-1",new TextEncoder().encode(password)));
  const hash=Array.from(digest,b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();
  const response=await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0,5)}`,{headers:{"Add-Padding":"true"},referrerPolicy:"no-referrer",credentials:"omit"});
  if(!response.ok) throw new Error("Breach service unavailable");
  return Number((await response.text()).split(/\r?\n/).find(row=>row.startsWith(hash.slice(5)+":"))?.split(":")[1]||0);
}
