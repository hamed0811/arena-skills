/**
 * Small fixed-window rate limiter.
 *
 * This is intentionally dependency-free and in-process. It is enough for a
 * single-node deployment (the target of this system). If the API is ever run
 * as more than one process, move the counters to a shared store (Redis) or the
 * limit becomes N × max.
 */
import { tooManyRequests } from '../lib/errors.js';

/**
 * @param {{windowMs: number, max: number, name: string, message?: string, keyGenerator?: (req: import('express').Request) => string}} options
 */
export function rateLimit({ windowMs, max, name, message, keyGenerator }) {
  /** @type {Map<string, {count: number, resetAt: number}>} */
  const buckets = new Map();

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  }, windowMs);
  sweep.unref?.();

  function middleware(req, res, next) {
    const key = `${name}:${keyGenerator ? keyGenerator(req) : (req.ip ?? 'unknown')}`;
    const now = Date.now();
    let bucket = buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }

    bucket.count += 1;
    const remaining = Math.max(0, max - bucket.count);
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(Math.ceil((bucket.resetAt - now) / 1000)));

    if (bucket.count > max) {
      const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      return next(tooManyRequests(message ?? 'Too many requests. Try again later.', retryAfter));
    }
    return next();
  }

  middleware.close = () => clearInterval(sweep);
  middleware.buckets = buckets;
  return middleware;
}
