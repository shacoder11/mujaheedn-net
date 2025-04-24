# rate_limiter.py
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, rate_limit):
        """
        Initialize rate limiter with a rate limit string like "100 per hour"
        """
        try:
            self.limit, _, self.period = rate_limit.split()
            self.limit = int(self.limit)
            self.period_seconds = self._get_period_seconds(self.period.lower())
        except (ValueError, AttributeError):
            raise ValueError("Rate limit format should be 'X per hour/minute/second'")
            
        self.requests = defaultdict(list)
        
    def _get_period_seconds(self, period):
        """Convert period name to seconds"""
        if period == 'second':
            return 1
        elif period == 'minute':
            return 60
        elif period == 'hour':
            return 3600
        else:
            raise ValueError("Unknown period. Use second/minute/hour")

    def check(self, identifier):
        """Check if the request should be allowed"""
        current_time = time.time()
        
        # Remove old requests
        self.requests[identifier] = [
            t for t in self.requests[identifier]
            if current_time - t < self.period_seconds
        ]
        
        if len(self.requests[identifier]) >= self.limit:
            return False
            
        self.requests[identifier].append(current_time)
        return True