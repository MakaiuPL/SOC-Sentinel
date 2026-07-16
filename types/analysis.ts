export type IndicatorType = "ip" | "domain";

export type Verdict = "clean" | "suspicious" | "malicious" | "unknown";

/**
 * Wzorzec dyskryminowanej unii: frontend NIGDY nie otrzymuje surowych błędów
 * zewnętrznych API — jedynie bezpieczny status i ogólny komunikat.
 */
export type SourceResult<T> =
  | { status: "ok"; data: T }
  | { status: "error"; message: string }
  | { status: "skipped"; message: string }
  | { status: "unconfigured"; message: string };

export interface AbuseIpDbData {
  abuseConfidenceScore: number;
  totalReports: number;
  isTor: boolean;
  isp: string | null;
  usageType: string | null;
  lastReportedAt: string | null;
}

export interface VirusTotalData {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  totalEngines: number;
  reputation: number;
}

export interface CrowdSecData {
  reputation: string;
  confidence: string | null;
  overallScore: number;
  behaviors: string[];
  classifications: string[];
  lastSeen: string | null;
}

export interface GeolocationData {
  country: string | null;
  countryCode: string | null;
  city: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  proxy: boolean;
  hosting: boolean;
  resolvedIp: string | null;
}

export interface AnalysisSources {
  abuseIpDb: SourceResult<AbuseIpDbData>;
  virusTotal: SourceResult<VirusTotalData>;
  crowdSec: SourceResult<CrowdSecData>;
  geolocation: SourceResult<GeolocationData>;
}

export interface AnalysisResponse {
  indicator: string;
  type: IndicatorType;
  verdict: Verdict;
  /** Kontekst korekty werdyktu — wyjaśnia analitykowi, dlaczego werdykt został
   *  obniżony/podwyższony (np. "IP w puli Azure — możliwy false positive").
   *  null = brak dodatkowego kontekstu, werdykt surowy z samych API. */
  verdictContext: string | null;
  analyzedAt: string;
  sources: AnalysisSources;
}
