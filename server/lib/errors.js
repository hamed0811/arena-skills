export class ApiError extends Error {
 constructor(status,code,message,details,headers){super(message);this.name='ApiError';this.status=status;this.code=code;this.details=details;this.headers=headers;}
}
export const badRequest=(message='Invalid request.',details)=>new ApiError(400,'VALIDATION_ERROR',message,details);
export const unauthorized=(message='Authentication required.')=>new ApiError(401,'UNAUTHENTICATED',message);
export const forbidden=(message='Access denied.',code='FORBIDDEN')=>new ApiError(403,code,message);
export const notFound=(message='Resource not found.',code='NOT_FOUND')=>new ApiError(404,code,message);
export const conflict=(code,message='Conflict.')=>new ApiError(409,code,message);
export const tooManyRequests=(message='Too many requests.')=>new ApiError(429,'RATE_LIMITED',message);
export function isForeignKeyViolation(error){return error?.code==='SQLITE_CONSTRAINT_FOREIGNKEY'||/FOREIGN KEY constraint failed/i.test(String(error?.message??''));}
export function asyncHandler(fn){return function wrapped(req,res,next){Promise.resolve(fn(req,res,next)).catch(next);};}
export function apiNotFound(req,res,next){next(notFound('API endpoint not found.','API_NOT_FOUND'));}
export function errorHandler(error,req,res,next){if(res.headersSent)return next(error);const e=error instanceof ApiError?error:new ApiError(500,'INTERNAL_ERROR','An unexpected server error occurred.');if(e.headers)for(const [k,v] of Object.entries(e.headers))res.setHeader(k,v);if(e.status>=500)console.error({requestId:req.id,error:error?.stack??String(error)});res.status(e.status).json({error:{code:e.code,message:e.message,details:e.details??null,requestId:req.id??null}});}
