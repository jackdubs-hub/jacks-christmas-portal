const crypto=require('node:crypto');
exports.handler=async(event)=>{
 const id=process.env.GITHUB_CLIENT_ID;
 if(!id)return {statusCode:503,body:'GitHub login is not configured. Check Netlify environment variables.'};
 const state=crypto.randomBytes(24).toString('hex');
 const url=new URL('https://github.com/login/oauth/authorize');
 url.searchParams.set('client_id',id);
 url.searchParams.set('redirect_uri','https://jacks-christmas-portal.netlify.app/.netlify/functions/auth-callback');
 url.searchParams.set('scope','repo');
 url.searchParams.set('state',state);
 return {statusCode:302,headers:{Location:url.toString(),'Set-Cookie':`wishlist_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`},body:''};
};