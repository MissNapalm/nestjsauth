import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  /**
   * Extract the real client IP address, handling proxies and load balancers.
   * IMPORTANT: Only trust X-Forwarded-For if your server is behind a trusted proxy.
   */
  protected async getTracker(req: Record<string, any>): Promise<string> {
    // Priority order for IP extraction:
    // 1. X-Forwarded-For (first IP in chain, set by trusted proxy)
    // 2. X-Real-IP (set by nginx)
    // 3. CF-Connecting-IP (Cloudflare)
    // 4. req.ip (Express default)
    // 5. req.connection.remoteAddress (fallback)
    
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
      // X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
      // The first one is the original client
      const ips = forwardedFor.split(',').map((ip: string) => ip.trim());
      return ips[0];
    }

    const realIp = req.headers['x-real-ip'];
    if (realIp) {
      return Array.isArray(realIp) ? realIp[0] : realIp;
    }

    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) {
      return Array.isArray(cfIp) ? cfIp[0] : cfIp;
    }

    return req.ip || req.connection?.remoteAddress || 'unknown';
  }

  /**
   * Custom error message with more context
   */
  protected async throwThrottlingException(
    context: ExecutionContext,
  ): Promise<void> {
    const req = context.switchToHttp().getRequest();
    const ip = await this.getTracker(req);
    
    // Log the rate limit hit for security monitoring
    console.warn(`⚠️ Rate limit exceeded for IP: ${ip}, Path: ${req.path}`);
    
    throw new ThrottlerException('Too many requests. Please slow down and try again later.');
  }
}
