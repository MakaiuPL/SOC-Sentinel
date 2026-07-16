/**
 * BEZPIECZEŃSTWO: `server-only` gwarantuje błąd kompilacji, gdyby ktokolwiek
 * zaimportował ten moduł (z kluczami API) do komponentu klienckiego.
 */
import "server-only";

import type {
  AbuseIpDbData,
  AnalysisSources,
  CrowdSecData,
  GeolocationData,
  IndicatorType,
  SourceResult,
  Verdict,
  VirusTotalData,
} from "@/types/analysis";

// Twardy timeout: zawieszone zewnętrzne API nie może blokować naszego serwera
// (ochrona przed wyczerpaniem puli połączeń — resource exhaustion)
const REQUEST_TIMEOUT_MS = 8_000;

const GENERIC_SOURCE_ERROR =
  "Źródło chwilowo niedostępne. Werdykt oparto na pozostałych danych.";

function toSafeString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value.slice(0, 200) : null;
}

function toSafeNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * AbuseIPDB — reputacja adresu IP na podstawie zgłoszeń społeczności.
 * Klucz API przesyłany w nagłówku, wyłącznie server-side.
 */
export async function queryAbuseIpDb(
  ip: string
): Promise<SourceResult<AbuseIpDbData>> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return {
      status: "unconfigured",
      message: "Źródło nieaktywne — brak klucza API w konfiguracji serwera.",
    };
  }

  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", ip);
    url.searchParams.set("maxAgeInDays", "90");

    const response = await fetch(url, {
      headers: { Key: apiKey, Accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      cache: "no-store",
    });

    if (!response.ok) throw new Error(`AbuseIPDB HTTP ${response.status}`);

    const payload = await response.json();
    const data = payload?.data ?? {};

    // BEZPIECZEŃSTWO: rzutujemy każde pole na oczekiwany typ — nie ufamy
    // strukturze odpowiedzi zewnętrznego API (ochrona przed data poisoning)
    return {
      status: "ok",
      data: {
        abuseConfidenceScore: toSafeNumber(data.abuseConfidenceScore),
        totalReports: toSafeNumber(data.totalReports),
        isTor: data.isTor === true,
        isp: toSafeString(data.isp),
        usageType: toSafeString(data.usageType),
        lastReportedAt: toSafeString(data.lastReportedAt),
      },
    };
  } catch (error) {
    // Szczegóły błędu tylko do logów serwera — nigdy do przeglądarki
    console.error("[AbuseIPDB] Zapytanie nieudane:", error);
    return { status: "error", message: GENERIC_SOURCE_ERROR };
  }
}

/**
 * VirusTotal v3 — agregacja werdyktów kilkudziesięciu silników AV/TI.
 * Obsługuje zarówno adresy IP, jak i domeny.
 */
export async function queryVirusTotal(
  indicator: string,
  type: IndicatorType
): Promise<SourceResult<VirusTotalData>> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      status: "unconfigured",
      message: "Źródło nieaktywne — brak klucza API w konfiguracji serwera.",
    };
  }

  try {
    const resource = type === "ip" ? "ip_addresses" : "domains";
    const response = await fetch(
      `https://www.virustotal.com/api/v3/${resource}/${encodeURIComponent(indicator)}`,
      {
        headers: { "x-apikey": apiKey, Accept: "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        cache: "no-store",
      }
    );

    if (response.status === 404) {
      return {
        status: "skipped",
        message: "Wskaźnik nie występuje jeszcze w bazie VirusTotal.",
      };
    }
    if (!response.ok) throw new Error(`VirusTotal HTTP ${response.status}`);

    const payload = await response.json();
    const attributes = payload?.data?.attributes ?? {};
    const stats = attributes.last_analysis_stats ?? {};

    const malicious = toSafeNumber(stats.malicious);
    const suspicious = toSafeNumber(stats.suspicious);
    const harmless = toSafeNumber(stats.harmless);
    const undetected = toSafeNumber(stats.undetected);

    return {
      status: "ok",
      data: {
        malicious,
        suspicious,
        harmless,
        undetected,
        totalEngines: malicious + suspicious + harmless + undetected,
        reputation: toSafeNumber(attributes.reputation),
      },
    };
  } catch (error) {
    console.error("[VirusTotal] Zapytanie nieudane:", error);
    return { status: "error", message: GENERIC_SOURCE_ERROR };
  }
}

/**
 * CrowdSec CTI (Smoke API) — reputacja IP z globalnej sieci sensorów
 * behawioralnych. Zwraca sklasyfikowane zachowania (np. ssh-bruteforce,
 * http-scan) i zagregowany werdykt społeczności. Obsługuje wyłącznie IP.
 */
export async function queryCrowdSec(
  ip: string
): Promise<SourceResult<CrowdSecData>> {
  const apiKey = process.env.CROWDSEC_CTI_API_KEY;
  if (!apiKey) {
    return {
      status: "unconfigured",
      message: "Źródło nieaktywne — brak klucza API w konfiguracji serwera.",
    };
  }

  try {
    const response = await fetch(
      `https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`,
      {
        headers: { "x-api-key": apiKey, Accept: "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        cache: "no-store",
      }
    );

    // 404 w Smoke API oznacza brak zgłoszeń — to pozytywny sygnał, nie błąd
    if (response.status === 404) {
      return {
        status: "skipped",
        message: "Adres nie występuje w bazie CrowdSec — brak zgłoszeń z sieci sensorów.",
      };
    }
    if (!response.ok) throw new Error(`CrowdSec HTTP ${response.status}`);

    const data = await response.json();

    // BEZPIECZEŃSTWO: listy z zewnętrznego API przycinamy i rzutujemy na string —
    // nie ufamy ani typom, ani rozmiarowi odpowiedzi (ochrona przed data poisoning)
    const behaviors = Array.isArray(data?.behaviors)
      ? data.behaviors
          .map((b: unknown) =>
            toSafeString((b as { label?: unknown })?.label)
          )
          .filter((label: string | null): label is string => label !== null)
          .slice(0, 8)
      : [];

    const classifications = Array.isArray(data?.classifications?.classifications)
      ? data.classifications.classifications
          .map((c: unknown) =>
            toSafeString((c as { label?: unknown })?.label)
          )
          .filter((label: string | null): label is string => label !== null)
          .slice(0, 8)
      : [];

    return {
      status: "ok",
      data: {
        reputation: toSafeString(data?.reputation) ?? "unknown",
        confidence: toSafeString(data?.confidence),
        overallScore: toSafeNumber(data?.scores?.overall?.total),
        behaviors,
        classifications,
        lastSeen: toSafeString(data?.history?.last_seen),
      },
    };
  } catch (error) {
    console.error("[CrowdSec] Zapytanie nieudane:", error);
    return { status: "error", message: GENERIC_SOURCE_ERROR };
  }
}

/**
 * IP-API — bezkluczowa geolokalizacja (kraj, ISP, ASN) + flagi proxy/hosting.
 * Uwaga: darmowy plan IP-API działa wyłącznie po HTTP — akceptowalne, bo dane
 * są jawne i niekrytyczne; w środowisku komercyjnym należy użyć planu Pro (HTTPS).
 */
export async function queryGeolocation(
  indicator: string
): Promise<SourceResult<GeolocationData>> {
  try {
    const fields =
      "status,message,country,countryCode,city,isp,org,as,proxy,hosting,query";
    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(indicator)}?fields=${fields}`,
      {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        cache: "no-store",
      }
    );

    if (!response.ok) throw new Error(`IP-API HTTP ${response.status}`);

    const data = await response.json();
    if (data?.status !== "success") {
      return {
        status: "skipped",
        message: "Brak danych geolokalizacyjnych dla tego wskaźnika.",
      };
    }

    return {
      status: "ok",
      data: {
        country: toSafeString(data.country),
        countryCode: toSafeString(data.countryCode),
        city: toSafeString(data.city),
        isp: toSafeString(data.isp),
        org: toSafeString(data.org),
        asn: toSafeString(data.as),
        proxy: data.proxy === true,
        hosting: data.hosting === true,
        resolvedIp: toSafeString(data.query),
      },
    };
  } catch (error) {
    console.error("[IP-API] Zapytanie nieudane:", error);
    return { status: "error", message: GENERIC_SOURCE_ERROR };
  }
}

/** Mapa providerów hostingowych — jeśli IP pochodzi z ich puli, pojedyncza
 *  detekcja może być false positive'em (adres został zwolniony i przydzielony
 *  nowemu klientowi po tym, jak poprzedni go "zabrudził"). */
const CLOUD_PROVIDER_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /microsoft|azure/i, label: "Microsoft Azure" },
  { pattern: /amazon|aws/i, label: "Amazon Web Services" },
  { pattern: /google cloud|gcp/i, label: "Google Cloud Platform" },
  { pattern: /digitalocean/i, label: "DigitalOcean" },
  { pattern: /ovh/i, label: "OVHcloud" },
  { pattern: /hetzner/i, label: "Hetzner" },
  { pattern: /linode/i, label: "Linode" },
  { pattern: /vultr/i, label: "Vultr" },
  { pattern: /alibaba cloud|aliyun/i, label: "Alibaba Cloud" },
  { pattern: /oracle cloud|oci/i, label: "Oracle Cloud" },
];

function detectCloudProvider(
  isp: string | null,
  org: string | null,
  hosting: boolean
): string | null {
  if (!hosting) return null;
  const searchIn = [isp, org].filter(Boolean).join(" ");
  for (const provider of CLOUD_PROVIDER_PATTERNS) {
    if (provider.pattern.test(searchIn)) return provider.label;
  }
  // hosting = true ale nie rozpoznano konkretnego providera — dalej warto ostrzec
  return hosting ? "hosting / data center" : null;
}

/**
 * Korelacja wielu źródeł w jeden werdykt + kontekst decyzji.
 *
 * 🔑 Kluczowa wiedza domenowa SOC L1: adresy z pul chmurowych (Azure, AWS, GCP)
 * rotują się dynamicznie — jeśli AbuseIPDB raportuje wysokie confidence score
 * dla IP z chmury, może to być pozostałość po poprzednim kliencie, który dostał
 * ten sam adres i go "zabrudził". Obniżamy wtedy "malicious" → "suspicious"
 * i dodajemy kontekst do werdyktu.
 */
export function computeVerdict(sources: AnalysisSources): {
  verdict: Verdict;
  context: string | null;
} {
  const abuse = sources.abuseIpDb.status === "ok" ? sources.abuseIpDb.data : null;
  const vt = sources.virusTotal.status === "ok" ? sources.virusTotal.data : null;
  const cs = sources.crowdSec.status === "ok" ? sources.crowdSec.data : null;
  const geo = sources.geolocation.status === "ok" ? sources.geolocation.data : null;

  // Sprawdź, czy IP pochodzi z puli hostingowej
  const cloudProvider = geo
    ? detectCloudProvider(geo.isp, geo.org, geo.hosting)
    : null;

  // ── Detekcja złośliwego (wymaga potwierdzenia w 2+ źródłach LUB
  //    pojedynczego bardzo mocnego sygnału z VT wielu silników) ──
  if (
    (vt && vt.malicious >= 3) ||
    ((abuse && abuse.abuseConfidenceScore >= 50) && (cs && cs.reputation === "malicious")) ||
    ((vt && vt.malicious >= 2) && (cs && cs.reputation === "malicious")) ||
    ((abuse && abuse.abuseConfidenceScore >= 70) && (vt && vt.malicious >= 1))
  ) {
    // Mimo złośliwego werdyktu — jeśli to hosting, dodajemy ostrzeżenie
    if (cloudProvider) {
      return {
        verdict: "suspicious",
        context: `Adres z puli ${cloudProvider} — podwyższone ryzyko false positive. IP mogło zostać oznaczone przez poprzedniego najemcę (rotacja adresów w chmurze). Weryfikuj kontekst biznesowy przed eskalacją.`,
      };
    }
    return { verdict: "malicious", context: null };
  }

  // ── Pojedynczy silny sygnał (pojedynczy sygnał z jednego źródła) ──
  if (
    (abuse && abuse.abuseConfidenceScore >= 50) ||
    (vt && vt.malicious >= 2) ||
    (cs && cs.reputation === "malicious")
  ) {
    if (cloudProvider) {
      return {
        verdict: "suspicious",
        context: `Pojedyncze źródło sygnalizuje zagrożenie, ale adres należy do puli ${cloudProvider}. Prawdopodobny false positive — zweryfikuj w dodatkowych źródłach przed reakcją.`,
      };
    }
    return { verdict: "malicious", context: null };
  }

  // ── Detekcja podejrzanego ──
  if (
    (abuse && (abuse.abuseConfidenceScore >= 25 || abuse.isTor)) ||
    (vt && (vt.malicious >= 1 || vt.suspicious >= 1)) ||
    (cs && cs.reputation === "suspicious")
  ) {
    if (cloudProvider) {
      return {
        verdict: "suspicious",
        context: `Niski poziom detekcji — adres ${cloudProvider}. Najpewniej czysty, ale zachowaj czujność przy nietypowym ruchu.`,
      };
    }
    return { verdict: "suspicious", context: null };
  }

  if (abuse || vt || cs || geo) return { verdict: "clean", context: null };

  return { verdict: "unknown", context: null };
}
