import { NextRequest, NextResponse } from "next/server";

import { checkRateLimit } from "@/lib/rate-limit";
import {
  computeVerdict,
  queryAbuseIpDb,
  queryCrowdSec,
  queryGeolocation,
  queryVirusTotal,
} from "@/lib/threat-intel";
import {
  analyzeRequestSchema,
  classifyIndicator,
  isPrivateOrReservedIp,
} from "@/lib/validation";
import type { AnalysisResponse, SourceResult } from "@/types/analysis";
import type { AbuseIpDbData, CrowdSecData } from "@/types/analysis";

// Rate limiter (in-memory) wymaga trwałego procesu Node — nie Edge Runtime
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function getClientIp(request: NextRequest): string {
  // Za reverse proxy (Vercel/nginx) realny adres klienta jest pierwszym
  // wpisem w X-Forwarded-For; kolejne wpisy mogą być sfałszowane
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return request.headers.get("x-real-ip") ?? "127.0.0.1";
}

export async function POST(request: NextRequest) {
  // ── WARSTWA 1: Rate Limiting (przed jakimkolwiek parsowaniem — fail fast) ──
  const clientIp = getClientIp(request);
  const rate = checkRateLimit(clientIp);

  if (!rate.allowed) {
    return NextResponse.json(
      {
        error: `Przekroczono limit zapytań (4/min). Spróbuj ponownie za ${rate.retryAfterSec} s.`,
      },
      {
        status: 429,
        headers: {
          // Standardowy nagłówek — poprawnie skonfigurowane klienty
          // automatycznie odczekają wskazany czas
          "Retry-After": String(rate.retryAfterSec),
          "X-RateLimit-Limit": "4",
          "X-RateLimit-Remaining": "0",
        },
      }
    );
  }

  // ── WARSTWA 2: Bezpieczne parsowanie body (uszkodzony JSON ≠ crash 500) ──
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: "Nieprawidłowy format żądania." },
      { status: 400 }
    );
  }

  // ── WARSTWA 3: Walidacja Zod — biała lista znaków, limity długości ──
  const parsed = analyzeRequestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message ?? "Nieprawidłowe dane wejściowe." },
      { status: 400 }
    );
  }

  // ── WARSTWA 4: Klasyfikacja semantyczna (poprawny IP lub FQDN) ──
  const indicator = parsed.data.query;
  const type = classifyIndicator(indicator);
  if (!type) {
    return NextResponse.json(
      { error: "Podaj poprawny adres IPv4/IPv6 lub w pełni kwalifikowaną domenę." },
      { status: 400 }
    );
  }

  // ── WARSTWA 5: Anty-SSRF — blokada adresów prywatnych i zarezerwowanych ──
  if (type === "ip" && isPrivateOrReservedIp(indicator)) {
    return NextResponse.json(
      {
        error:
          "Adresy prywatne i zarezerwowane (RFC 1918 / link-local) nie podlegają analizie zewnętrznej.",
      },
      { status: 400 }
    );
  }

  // ── Równoległe odpytanie źródeł TI (Promise.all — minimalna latencja).
  // Każdy klient łapie własne wyjątki i zwraca bezpieczny SourceResult,
  // więc awaria jednego źródła nie przerywa całej analizy. ──
  const skippedAbuse: SourceResult<AbuseIpDbData> = {
    status: "skipped",
    message: "AbuseIPDB obsługuje wyłącznie adresy IP — pominięto dla domeny.",
  };
  const skippedCrowdSec: SourceResult<CrowdSecData> = {
    status: "skipped",
    message: "CrowdSec CTI obsługuje wyłącznie adresy IP — pominięto dla domeny.",
  };

  const [abuseIpDb, virusTotal, crowdSec, geolocation] = await Promise.all([
    type === "ip" ? queryAbuseIpDb(indicator) : Promise.resolve(skippedAbuse),
    queryVirusTotal(indicator, type),
    type === "ip" ? queryCrowdSec(indicator) : Promise.resolve(skippedCrowdSec),
    queryGeolocation(indicator),
  ]);

  const { verdict, context } = computeVerdict({
    abuseIpDb,
    virusTotal,
    crowdSec,
    geolocation,
  });

  const result: AnalysisResponse = {
    indicator,
    type,
    verdict,
    verdictContext: context,
    analyzedAt: new Date().toISOString(),
    sources: { abuseIpDb, virusTotal, crowdSec, geolocation },
  };

  return NextResponse.json(result, {
    headers: {
      // Wyniki analizy TI nie mogą być cache'owane przez pośredników
      "Cache-Control": "no-store",
      "X-RateLimit-Limit": "4",
      "X-RateLimit-Remaining": String(rate.remaining),
    },
  });
}
