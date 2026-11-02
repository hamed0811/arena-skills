import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
const dummyCache=new Map();
export function randomToken(bytes=32){return crypto.randomBytes(bytes).toString('hex');}
export function timingSafeEqualStrings(a,b){const x=Buffer.from(String(a??'')),y=Buffer.from(String(b??''));return x.length===y.length&&crypto.timingSafeEqual(x,y);}
export async function hashPassword(password,rounds=12){return bcrypt.hash(password,rounds);}
export async function verifyPassword(password,hash){try{return await bcrypt.compare(password,hash);}catch{return false;}}
export function dummyPasswordHash(rounds=12){if(!dummyCache.has(rounds))dummyCache.set(rounds,bcrypt.hashSync('not-a-real-password-'+randomToken(8),rounds));return dummyCache.get(rounds);}
export function assertPasswordPolicy(password,{username='',fullName=''}={}){const p=String(password??'');const problems=[];if(p.length<12)problems.push('Password must contain at least 12 characters.');if(!/[a-z]/.test(p)||!/[A-Z]/.test(p)||!/[0-9]/.test(p)||!/[^\w]/.test(p))problems.push('Password must include upper-case, lower-case, number and symbol characters.');if(username&&p.toLowerCase().includes(String(username).toLowerCase()))problems.push('Password must not contain the username.');if(fullName&&String(fullName).trim().length>2&&p.toLowerCase().includes(String(fullName).trim().toLowerCase()))problems.push('Password must not contain the full name.');if(problems.length){const e=new Error(problems.join(' '));e.status=400;e.code='VALIDATION_ERROR';e.details=[{field:'password',message:problems.join(' ')}];throw e;}}
