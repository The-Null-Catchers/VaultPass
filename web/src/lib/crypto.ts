import { argon2id } from "hash-wasm";
export type Envelope = {v: 1; nonce: string; ciphertext: string};
export type Bundle = {salt: string; profile: "argon2id-m65536-t3-p4-v1"; account_key: Envelope};
export const PROFILE = "argon2id-m65536-t3-p4-v1" as const;
const enc = new TextEncoder();
export const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
export const hex = (v: Uint8Array) => Array.from(v, b => b.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string) => {
  if (!/^(?:[a-f0-9]{2})+$/i.test(s)) throw new Error("Invalid hex encoding");
  return Uint8Array.from(s.match(/../g)!, x => parseInt(x,16));
};
export const b64 = (v: Uint8Array) => { let s=""; for (const b of v) s+=String.fromCharCode(b); return btoa(s); };
export const unb64 = (v: string) => Uint8Array.from(atob(v), c => c.charCodeAt(0));
const buffer = (v: Uint8Array) => new Uint8Array(v).buffer;
export async function derive(master: string, salt: string) {
  if (unhex(salt).length !== 16) throw new Error("Invalid salt");
  const root = await argon2id({password: master, salt: unhex(salt), parallelism: 4, iterations: 3, memorySize: 65536, hashLength: 32, outputType: "binary"});
  try {
    const hkdf = await crypto.subtle.importKey("raw", buffer(root), "HKDF", false, ["deriveBits"]);
    const subkey = async (label: string) => new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF", hash:"SHA-256", salt:new Uint8Array(32), info:enc.encode(`vaultpass:v1:${label}`)}, hkdf,256));
    return {wrap: await subkey("wrap"), auth: hex(await subkey("auth"))};
  } finally {root.fill(0);}
}
export async function seal(key: Uint8Array, plaintext: Uint8Array, context: string): Promise<Envelope> {
  if (key.length !== 32) throw new Error("Invalid key length");
  const nonce = bytes(12);
  const k = await crypto.subtle.importKey("raw", buffer(key), "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM",iv:buffer(nonce),additionalData:enc.encode(context),tagLength:128}, k,buffer(plaintext));
  return {v:1,nonce:b64(nonce),ciphertext:b64(new Uint8Array(ciphertext))};
}
export async function open(key: Uint8Array, envelope: Envelope, context: string): Promise<Uint8Array> {
  if (envelope.v !== 1 || unb64(envelope.nonce).length !== 12 || key.length !== 32) throw new Error("Invalid envelope");
  const k = await crypto.subtle.importKey("raw",buffer(key),"AES-GCM",false,["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:buffer(unb64(envelope.nonce)),additionalData:enc.encode(context),tagLength:128},k,buffer(unb64(envelope.ciphertext))));
}
export const context = (kind: string, ...ids: (string|number)[]) => ["vaultpass","v1",kind,...ids].join(":");
export async function createAccount(master: string) {
  if (master.length < 12) throw new Error("Use at least 12 characters for your master password");
  const id = crypto.randomUUID(), vaultId = crypto.randomUUID(), salt = hex(bytes(16));
  const derived = await derive(master,salt), accountKey = bytes(32), vaultKey=bytes(32);
  try {
    const bundle: Bundle = {salt,profile:PROFILE,account_key:await seal(derived.wrap,accountKey,context("account",id))};
    return {id,vaultId,bundle,auth:derived.auth,accountKey,vaultKey,wrappedVaultKey:await seal(accountKey,vaultKey,context("vault",id,vaultId))};
  } finally {derived.wrap.fill(0);}
}
export async function unlock(master: string, id: string, bundle: Bundle) {
  if (bundle.profile !== PROFILE) throw new Error("Unsupported KDF profile");
  const d=await derive(master,bundle.salt);
  try {return await open(d.wrap,bundle.account_key,context("account",id));} finally {d.wrap.fill(0);}
}
export async function rewrap(master: string, id: string, accountKey: Uint8Array) {
  if (master.length < 12) throw new Error("Use at least 12 characters");
  const salt=hex(bytes(16)), d=await derive(master,salt);
  try {return {auth_secret:d.auth,bundle:{salt,profile:PROFILE,account_key:await seal(d.wrap,accountKey,context("account",id))}};} finally {d.wrap.fill(0);}
}
export async function encryptJSON(key: Uint8Array, value: unknown, aad: string) {return seal(key,enc.encode(JSON.stringify(value)),aad);}
export async function decryptJSON<T>(key: Uint8Array, envelope: Envelope, aad: string): Promise<T> {
  const clear = await open(key,envelope,aad);
  try {return JSON.parse(new TextDecoder().decode(clear)) as T;} finally {clear.fill(0);}
}
