import session from 'express-session';
export class SqliteSessionStore extends session.Store{
 constructor(db,{ttlMs=28800000}={}){super();this.db=db;this.ttlMs=ttlMs;this.getStmt=db.prepare('SELECT data,expires_at FROM sessions WHERE sid=?');this.setStmt=db.prepare('INSERT INTO sessions(sid,user_id,data,expires_at) VALUES(?,?,?,?) ON CONFLICT(sid) DO UPDATE SET user_id=excluded.user_id,data=excluded.data,expires_at=excluded.expires_at');this.destroyStmt=db.prepare('DELETE FROM sessions WHERE sid=?');this.touchStmt=db.prepare('UPDATE sessions SET expires_at=? WHERE sid=?');}
 get(sid,cb){try{const row=this.getStmt.get(sid);if(!row)return cb(null,null);if(Date.parse(row.expires_at)<=Date.now()){this.destroyStmt.run(sid);return cb(null,null);}return cb(null,JSON.parse(row.data));}catch(e){return cb(e);}}
 set(sid,sess,cb=()=>{}){try{const expires=sess.cookie?.expires?new Date(sess.cookie.expires):new Date(Date.now()+(sess.cookie?.maxAge??this.ttlMs));this.setStmt.run(sid,sess.userId??null,JSON.stringify(sess),expires.toISOString());cb(null);}catch(e){cb(e);}}
 destroy(sid,cb=()=>{}){try{this.destroyStmt.run(sid);cb(null);}catch(e){cb(e);}}
 touch(sid,sess,cb=()=>{}){try{const expires=sess.cookie?.expires?new Date(sess.cookie.expires):new Date(Date.now()+(sess.cookie?.maxAge??this.ttlMs));this.touchStmt.run(expires.toISOString(),sid);cb(null);}catch(e){cb(e);}}
 close(){}
}
