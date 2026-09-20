import {NextRequest,NextResponse} from "next/server";
export const dynamic="force-dynamic";
async function proxy(request:NextRequest,{params}:{params:Promise<{path:string[]}>}){
 const {path}=await params;
 if(path.some(p=>p===".."||p.includes("/")||p.includes("\\")))return NextResponse.json({detail:"Invalid path"},{status:400});
 const origin=process.env.API_INTERNAL_URL||"http://localhost:8000";
 const target=new URL(path.map(encodeURIComponent).join("/")+request.nextUrl.search,origin+"/");
 const headers=new Headers();
 for(const name of ["content-type","authorization","origin"]) {const value=request.headers.get(name);if(value)headers.set(name,value);}
 const body=["GET","HEAD"].includes(request.method)?undefined:await request.arrayBuffer();
 if(body&&body.byteLength>400000)return NextResponse.json({detail:"Request too large"},{status:413});
 try{const response=await fetch(target,{method:request.method,headers,body,cache:"no-store",redirect:"error",signal:AbortSignal.timeout(30000)});
 return new NextResponse(response.body,{status:response.status,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
 }catch{return NextResponse.json({detail:"API temporarily unavailable"},{status:502});}
}
export {proxy as GET,proxy as POST,proxy as PUT,proxy as DELETE};
