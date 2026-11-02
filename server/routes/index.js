/** API composition root. Middleware order is security-sensitive. */
import express from 'express';
import { loadUser } from '../middleware/auth.js';
import { verifyCsrf } from '../middleware/csrf.js';
import { rateLimit } from '../middleware/rate-limit.js';
import { apiNotFound, asyncHandler } from '../lib/errors.js';
import { createAuthRouter } from './auth.js';
import { createUsersRouter } from './users.js';
import { createCategoriesRouter } from './categories.js';
import { createCostCentersRouter } from './cost-centers.js';
import { createRequestsRouter } from './requests.js';
import { createAuditLogsRouter } from './audit-logs.js';
import { createBackupsRouter } from './backups.js';
import { createImportsRouter } from './imports.js';
const APP_VERSION='2.1.0';
export function createApiRouter({db,appConfig}){
 const router=express.Router();const healthCheck=db.prepare('SELECT 1 AS ok');
 router.get('/health',asyncHandler(async(req,res)=>{let database='ok';try{healthCheck.get();}catch{database='unavailable';}res.status(database==='ok'?200:503).json({status:database==='ok'?'ok':'degraded',database,version:APP_VERSION,uptimeSeconds:Math.floor(process.uptime()),time:new Date().toISOString()});}));
 const apiLimiter=rateLimit({windowMs:appConfig.rateLimit.api.windowMs,max:appConfig.rateLimit.api.max,name:'api'});
 const loginLimiter=rateLimit({windowMs:appConfig.rateLimit.login.windowMs,max:appConfig.rateLimit.login.max,name:'login',message:'Too many sign-in attempts from this address. Try again later.'});
 router.use(apiLimiter);router.use(loadUser(db,appConfig));router.use(verifyCsrf);
 router.use('/auth',createAuthRouter({db,appConfig,loginLimiter}));
 router.use('/users',createUsersRouter({db,appConfig}));router.use('/categories',createCategoriesRouter({db}));router.use('/cost-centers',createCostCentersRouter({db}));router.use('/requests',createRequestsRouter({db,appConfig}));router.use('/audit-logs',createAuditLogsRouter({db}));router.use('/backups',createBackupsRouter({db,appConfig}));router.use('/imports',createImportsRouter({db,appConfig}));
 router.use(apiNotFound);router.limiters=[apiLimiter,loginLimiter];return router;
}
