import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

/**
 * Middleware that adds a unique request ID to every incoming request.
 * This enables request tracing across logs and services.
 * 
 * The request ID is:
 * 1. Read from X-Request-ID header if provided (for distributed tracing)
 * 2. Generated as a new UUID if not provided
 * 3. Added to response headers for client reference
 * 4. Attached to the request object for use in handlers/services
 */
@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Use existing request ID from header (for distributed tracing) or generate new one
    const requestId = (req.headers['x-request-id'] as string) || uuidv4();
    
    // Attach to request object for access in controllers/services
    (req as any).requestId = requestId;
    
    // Add to response headers so client can reference it
    res.setHeader('X-Request-ID', requestId);
    
    // Log the start of the request
    const startTime = Date.now();
    const { method, originalUrl, ip } = req;
    
    console.log(`[${requestId}] --> ${method} ${originalUrl} | IP: ${ip}`);
    
    // Log when response finishes
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const { statusCode } = res;
      console.log(`[${requestId}] <-- ${method} ${originalUrl} | ${statusCode} | ${duration}ms`);
    });
    
    next();
  }
}
