let access="", refresh="";
let pending: Promise<void>|null=null;
export function setTokens(a:string,r:string) {access=a;refresh=r;}
export function clearTokens(){access="";refresh="";}
export class ApiError extends Error {constructor(public status:number,message:string){super(message);}}
async function renew() {
  const response=await fetch("/api/auth/refresh",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:refresh})});
  if(!response.ok){clearTokens();throw new ApiError(401,"Session expired. Log in again.");}
  const result=await response.json();setTokens(result.access_token,result.refresh_token);
}
export async function api<T>(path:string,method="GET",body?:unknown,retry=true):Promise<T>{
  const response=await fetch("/api"+path,{method,headers:{"Content-Type":"application/json",...(access?{Authorization:`Bearer ${access}`}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
  if(response.status===401&&refresh&&retry&&!path.startsWith("/auth/")){
    if(!pending)pending=renew().finally(()=>{pending=null;});await pending;return api(path,method,body,false);
  }
  if(!response.ok){const result=await response.json().catch(()=>({detail:"Request failed"}));throw new ApiError(response.status,typeof result.detail==="string"?result.detail:"Request failed");}
  return response.json();
}
