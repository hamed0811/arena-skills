/**
 * Cross-cutting HTTP security middleware.
 */
import crypto from 'node:crypto';
import helmet from 'helmet';
import { ApiError } from '../lib/errors.js';

/** Correlation id for every request; echoed in responses and server logs. */
export function requestId(req, res, next) {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
}

/**
 * Strict security headers.
 *
 * The CSP is intentionally tight:
 *   script-src 'self'      -> only our own external JS files
 *   script-src-attr 'none' -> *no* inline event handlers (onclick, onerror, …)
 *   style-src 'self'       -> stylesheets only, no inline <style>/style=""
 *   frame-ancestors        -> no framing, except the configured preview host
 *
 * @param {typeof import('../config.js').config} appConfig
 */
export function securityHeaders(appConfig) {
  const isProduction = appConfig.isProduction;

  const helmetMiddleware = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
        frameAncestors: appConfig.security.frameAncestors,
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        // Dev/preview is served over plain http on localhost; forcing https
        // upgrades there would break the app. Production requires HTTPS.
        upgradeInsecureRequests: isProduction ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    // frame-ancestors above is authoritative; XFO would fight the preview iframe.
    frameguard: false,
    hsts: isProduction ? { maxAge: 31_536_000, includeSubDomains: true, preload: false } : false,
    referrerPolicy: { policy: 'no-referrer' },
    dnsPrefetchControl: { allow: false },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    xssFilter: false,
  });

  return function applySecurityHeaders(req, res, next) {
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
    );
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    helmetMiddleware(req, res, next);
  };
}

/** API responses must never be cached by browsers or proxies. */
export function noStore(req, res, next) {
  if (req.path.startsWith('/api') || req.path.startsWith('/auth')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Reject unsafe API requests that are not JSON.
 * Browsers can send cross-site HTML forms without a preflight; requiring a
 * JSON content type (multipart is allowed for imports) prevents that class of
 * CSRF before it reaches the token check.
 */
export function enforceJsonContentType(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  if (!req.path.startsWith('/api')) return next();

  const contentType = String(req.get('content-type') ?? '').toLowerCase();
  const contentLength = Number(req.get('content-length') ?? 0);
  const hasBody = contentLength > 0 || Boolean(req.get('transfer-encoding'));

  if (contentType.startsWith('application/json') || contentType.startsWith('multipart/form-data')) {
    return next();
  }
  if (!hasBody) return next(); // e.g. POST /api/auth/logout with no payload

  return next(new ApiError(
    415,
    'UNSUPPORTED_MEDIA_TYPE',
    'Unsafe API requests must use application/json (or multipart/form-data for imports).',
  ));
}

/**
 * Minimal structured request logging: method, path, status, duration, user id.
 * Bodies, cookies, query strings with tokens and headers are never logged.
 */
export function requestLogger(req, res, next) {
  const enabled = req.app?.locals?.config?.logging?.requests !== false;
  if (!enabled || !req.path.startsWith('/api')) return next();
  const startedAt = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    console.log(JSON.stringify({
      level: 'info',
      requestId: req.id,
      method: req.method,
      // originalUrl keeps the /api prefix even though the router trims req.url.
      path: String(req.originalUrl ?? req.url ?? '').split('?')[0],
      status: res.statusCode,
      durationMs: Math.round(durationMs * 10) / 10,
      userId: req.user?.id ?? null,
    }));
  });
  return next();
}
