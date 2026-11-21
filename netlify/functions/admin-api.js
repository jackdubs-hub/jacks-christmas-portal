const crypto=require('node:crypto');
const REPO='jackdubs-hub/jacks-christmas-portal',FILE='gifts.json';
const json=(statusCode,data)=>({statusCode,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'},body:JSON.stringify(data)});
function getToken(event){
 const c=(event.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('wishlist_admin_session='));
 if(!c||!process.env.GITHUB_CLIENT_SECRET)return null;
 try{
 const b=Buffer.from(c.split('=').slice(1).join('='),'base64url'),key=crypto.createHash('sha256').update(process.env.GITHUB_CLIENT_SECRET).digest(),d=crypto.createDecipheriv('aes-256-gcm',key,b.subarray(0,12));
 d.setAuthTag(b.subarray(12,28));const p=JSON.parse(Buffer.concat([d.update(b.subarray(28)),d.final()]).toString());
 return p.exp>Date.now()&&p.login.toLowerCase()==='jackdubs-hub'?p.token:null;
 }catch{return null;}
}
const github=(path,token,opts={})=>fetch('https://api.github.com/repos/'+REPO+'/contents/'+path,{...opts,headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','User-Agent':'jacks-christmas-portal','X-GitHub-Api-Version':'2022-11-28',...(opts.headers||{})}});
exports.handler=async(event)=>{
 if(event.httpMethod==='OPTIONS')return {statusCode:405,body:''};
 const token=getToken(event);
 if(!token)return json(401,{error:'Please sign in with GitHub.'});
 if(event.httpMethod!=='GET'&&event.httpMethod!=='PUT')return json(405,{error:'Method not allowed'});
 if(event.httpMethod==='PUT'&&(!event.headers.origin||event.headers.origin!=='https://jacks-christmas-portal.netlify.app'))return json(403,{error:'Invalid request origin'});
 try{
 const res=await github(FILE,token);
 if(!res.ok)return json(res.status===403?403:502,{error:'Could not access the GitHub wishlist. Check repository authorization.'});
 const data=await res.json(),current=JSON.parse(Buffer.from(data.content.replace(/\s/g,''),'base64').toString('utf8'));
 if(event.httpMethod==='GET')return json(200,{gifts:current,sha:data.sha});
 if((event.body||'').length>120000)return json(413,{error:'Wishlist is too large'});
 const body=JSON.parse(event.body||'{}');
 if(!Array.isArray(body.gifts)||body.gifts.length>200||!body.gifts.every(x=>x&&typeof x.name==='string'&&x.name.trim().length>0&&x.name.length<=150&&typeof x.category==='string'&&x.name.length<=150&&['id','name','price','category','priority','link','image','desc'].every(k=>x[k]===undefined||['string','number'].includes(typeof x[k]))))return json(400,{error:'Invalid gift data'});
 if(body.sha!==data.sha)return json(409,{error:'The wishlist changed since you loaded it. Refresh before saving.'});
 const payload={message:'Update Christmas wishlist from private admin dashboard',content:Buffer.from(JSON.stringify(body.gifts,null,2)+'\n').toString('base64'),sha:data.sha,branch:'main'};
 const saved=await github(FILE,token,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
 if(!saved.ok){const detail=await saved.json().catch(()=>({}));return json(saved.status,{error:detail.message||'GitHub could not save the wishlist.'});}
 const result=await saved.json();return json(200,{ok:true,sha:result.content.sha});
 }catch{return json(500,{error:'Unexpected server error. No changes were saved.'});}
};