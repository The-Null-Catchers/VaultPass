import {Bundle,Envelope,unlock,open,context,decryptJSON} from "./crypto";
export type VaultData={title:string;type:string;username:string;password:string;url:string;notes:string;tags:string;folder:string;favorite:boolean;totp:string};
export function validateItem(value:unknown):VaultData {
 if(!value||typeof value!=="object")throw new Error("Invalid item");
 const v=value as Record<string,unknown>, result:Record<string,unknown>={};
 for(const field of ["title","type","username","password","url","notes","tags","folder","totp"]){const text=v[field]??"";if(typeof text!=="string"||text.length>100000)throw new Error("Invalid item field");result[field]=text;}
 if(!result.title||!["login","note","card","identity","api","recovery","ssh"].includes(result.type as string))throw new Error("Invalid item type or title");
 if(v.favorite!==undefined&&typeof v.favorite!=="boolean")throw new Error("Invalid favorite value");result.favorite=v.favorite===true;
 return result as VaultData;
}
export async function restoreBackup(value:unknown,master:string):Promise<VaultData[]> {
 if(!value||typeof value!=="object")throw new Error("Invalid backup");
 const data=value as {format:string;user_id:string;bundle:Bundle;vaults:{id:string;wrapped_key:Envelope}[];items:{id:string;version:number;payload:Envelope;purged:boolean;deleted:boolean}[]};
 if(data.format!=="vaultpass-backup-v1"||!Array.isArray(data.vaults)||data.vaults.length!==1||!Array.isArray(data.items)||data.items.length>5000)throw new Error("Unsupported backup");
 // Check item identity and metadata before the expensive master-key derivation.
 // Duplicate item IDs would otherwise make a restore produce ambiguous entries.
 const vault=data.vaults[0];
 if(typeof data.user_id!=="string"||!data.user_id||typeof vault?.id!=="string"||!vault.id||!vault.wrapped_key||!data.bundle)throw new Error("Invalid backup metadata");
 const seen=new Set<string>();
 for(const item of data.items){
  if(!item||typeof item!=="object"||typeof item.id!=="string"||!item.id||item.id.length>128||
     !Number.isSafeInteger(item.version)||item.version<1||!item.payload||
     (item.purged!==undefined&&typeof item.purged!=="boolean")||
     (item.deleted!==undefined&&typeof item.deleted!=="boolean")||
     seen.has(item.id))throw new Error("Invalid backup item");
  seen.add(item.id);
 }
 const account=await unlock(master,data.user_id,data.bundle);
 try{const key=await open(account,vault.wrapped_key,context("vault",data.user_id,vault.id));
 try{const items:VaultData[]=[];for(const item of data.items){if(item.purged||item.deleted)continue;items.push(validateItem(await decryptJSON(key,item.payload,context("item",vault.id,item.id,item.version))));}return items;}finally{key.fill(0);}
 }finally{account.fill(0);}
}
