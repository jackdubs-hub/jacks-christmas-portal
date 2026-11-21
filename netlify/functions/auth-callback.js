const crypto=require('node:crypto');
const COOKIE='wishlist_admin_session';
function cookies(header){return Object.fromEntries((header||'').split(';').map(s=>s.trim().split(/=(.*)/s).slice(0,2)).filter(p=>p.length===2));}
exports.handler=async(event)=>{
 const base='https://jacks-christmas-portal.netlify.app';
 const fail=(reason)=>({statusCode:302,multiValueHeaders:{'Set-Cookie':['wishlist_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0']},headers:{Location:base+'/admin.html?error='+encodeURIComponent(reason)},body:''});
 try{
 const q=event.queryStringParameters||{},c=cookies(event.headers.cookie);
 if(!q.code||!q.state||!c.wishlist_oauth_state||q.state!==c.wishlist_oauth_state)return fail('Login verification failed. Try again.');
 const secret=process.env.GITHUB_CLIENT_SECRET,id=process.env.GITHUB_CLIENT_ID;
 if(!secret||!id)return fail('GitHub credentials are not configured.');
 const res=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:id,client_secret:secret,code:q.code,redirect_uri:base+'/.netlify/functions/auth-callback'})});
 const tokenData=await res.json();if(!res.ok||!tokenData.access_token)return fail('GitHub authorization was unsuccessful.');
 const token=tokenData.access_token;
 const userRes=await fetch('https://api.github.com/user',{headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','User-Agent':'jacks-christmas-portal'}});
 const user=await userRes.json();
 if(!userRes.ok||String(user.login).toLowerCase()!=='jackdubs-hub')return fail('This GitHub account is not authorized to edit the wishlist.');
 const key=crypto.createHash('sha256').update(secret).digest(),iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
 const payload=JSON.stringify({token,login:user.login,exp:Date.now()+8*60*60*1000});
 const encrypted=Buffer.concat([cipher.update(payload,'utf8'),cipher.final()]);
 const cookie=Buffer.concat([iv,cipher.getAuthTag(),encrypted]).toString('base64url');
 return {statusCode:302,headers:{Location:base+'/admin.html'},multiValueHeaders:{'Set-Cookie':[`${COOKIE}=${cookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`,'wishlist_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0']},body:''};
 }catch{return fail('Could not complete GitHub login.');}
};