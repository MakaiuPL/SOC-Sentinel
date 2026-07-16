import { LRUCache } from "lru-cache";

/**
 * BEZPIECZEŃSTWO: Rate Limiting (okno przesuwne, in-memory).
 *
 * Cel: ochrona darmowych limitów zewnętrznych API (AbuseIPDB, VirusTotal,
 * CrowdSec CTI) oraz mitygacja ataków DoS / enumeracji przez klienta.
 *
 * Dlaczego LRU-cache zamiast zwykłej Mapy? Ograniczenie `max` chroni pamięć
 * serwera przed wyczerpaniem (atak przez spoofing tysięcy adresów IP
 * w nagłówku X-Forwarded-For nie rozsadzi procesu), a TTL automatycznie
 * usuwa nieaktywne wpisy.
 *
 * Uwaga produkcyjna: w środowisku serverless (wiele instancji) należy użyć
 * współdzielonego magazynu, np. @upstash/ratelimit + Redis. Interfejs
 * `checkRateLimit` pozwala podmienić implementację bez zmian w API Route.
 */

const WINDOW_MS = 60_000; // okno: 60 sekund
// Limit celowo dopasowany do najciaśniejszego darmowego planu w łańcuchu
// (VirusTotal: 4 lookups/min) — pojedynczy klient nie wysyci kwoty API
const MAX_REQUESTS = 4;

const requestLog = new LRUCache<string, number[]>({
  max: 5_000,
  ttl: WINDOW_MS,
});

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
}

export function checkRateLimit(clientIp: string): RateLimitResult {
  const now = Date.now();

  // Okno przesuwne: bierzemy pod uwagę tylko żądania z ostatnich 60 s
  const recent = (requestLog.get(clientIp) ?? []).filter(
    (timestamp) => now - timestamp < WINDOW_MS
  );

  if (recent.length >= MAX_REQUESTS) {
    const oldest = recent[0];
    return {
      allowed: false,
      remaining: 0,
      retryAfterSec: Math.max(1, Math.ceil((WINDOW_MS - (now - oldest)) / 1000)),
    };
  }

  recent.push(now);
  requestLog.set(clientIp, recent);

  return {
    allowed: true,
    remaining: MAX_REQUESTS - recent.length,
    retryAfterSec: 0,
  };
}
