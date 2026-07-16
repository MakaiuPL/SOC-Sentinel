"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ShieldCheck,
  ShieldX,
  ShieldAlert,
  Globe,
  Server,
  MapPin,
  Clock,
  TestTube,
  FileText,
  Radar,
} from "lucide-react";

import type { AnalysisResponse, Verdict } from "@/types/analysis";

const VERDICT_CONFIG: Record<
  Verdict,
  { label: string; icon: React.ReactNode; variant: "success" | "warning" | "destructive" | "default" }
> = {
  clean: {
    label: "Czysty — brak wykrytych zagrożeń",
    icon: <ShieldCheck className="size-5" />,
    variant: "success",
  },
  suspicious: {
    label: "Podejrzany — wymaga dalszej analizy w SOC",
    icon: <ShieldAlert className="size-5" />,
    variant: "warning",
  },
  malicious: {
    label: "Złośliwy — potwierdzone zagrożenie",
    icon: <ShieldX className="size-5" />,
    variant: "destructive",
  },
  unknown: {
    label: "Nierozstrzygnięty — brak danych do werdyktu",
    icon: <ShieldAlert className="size-5" />,
    variant: "default",
  },
};

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("pl-PL", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// Mapowanie werdyktów CrowdSec na polskie etykiety i kolory semantyczne
const CROWDSEC_REPUTATION: Record<
  string,
  { label: string; variant: "success" | "warning" | "destructive" }
> = {
  malicious: { label: "Złośliwy", variant: "destructive" },
  suspicious: { label: "Podejrzany", variant: "warning" },
  known: { label: "Znany (nieszkodliwy)", variant: "success" },
  safe: { label: "Bezpieczny", variant: "success" },
  unknown: { label: "Nieznany", variant: "warning" },
};

export function ResultCards({ result }: { result: AnalysisResponse }) {
  const verdict = VERDICT_CONFIG[result.verdict];
  const { sources } = result;

  return (
    <div className="space-y-5">
      {/* Karta werdyktu */}
      <Card className="border-l-4 border-l-current">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            {verdict.icon}
            Werdykt
          </CardTitle>
          <CardDescription>Skorelowana ocena ze wszystkich źródeł</CardDescription>
        </CardHeader>
        <CardContent>
          <Badge variant={verdict.variant} className="text-sm py-1 px-3">
            {verdict.label}
          </Badge>
          {result.verdictContext && (
            <p className="mt-3 text-xs leading-relaxed text-amber-400/90 border border-amber-500/20 rounded-md p-3 bg-amber-500/5">
              {result.verdictContext}
            </p>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            <Clock className="size-3 inline mr-1" />
            Przeprowadzono analizę: {formatTime(result.analyzedAt)}
          </p>
        </CardContent>
      </Card>

      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {/* AbuseIPDB */}
        <SourceCard
          title="AbuseIPDB"
          icon={<FileText className="size-4" />}
          source={sources.abuseIpDb}
        >
          {sources.abuseIpDb.status === "ok" && (
            <div className="space-y-2">
              <Metric
                label="Poziom zagrożenia"
                value={`${sources.abuseIpDb.data.abuseConfidenceScore}%`}
                variant={
                  sources.abuseIpDb.data.abuseConfidenceScore >= 50
                    ? "destructive"
                    : sources.abuseIpDb.data.abuseConfidenceScore >= 25
                      ? "warning"
                      : "success"
                }
              />
              <Metric
                label="Liczba zgłoszeń"
                value={`${sources.abuseIpDb.data.totalReports}`}
              />
              {sources.abuseIpDb.data.isp && (
                <Metric label="Dostawca (ISP)" value={sources.abuseIpDb.data.isp} />
              )}
              {sources.abuseIpDb.data.isTor && (
                <Badge variant="warning" className="mt-1">Węzeł sieci Tor</Badge>
              )}
            </div>
          )}
        </SourceCard>

        {/* VirusTotal */}
        <SourceCard
          title="VirusTotal"
          icon={<TestTube className="size-4" />}
          source={sources.virusTotal}
        >
          {sources.virusTotal.status === "ok" && (
            <div className="space-y-2">
              <Metric
                label="Złośliwe silniki"
                value={`${sources.virusTotal.data.malicious} / ${sources.virusTotal.data.totalEngines}`}
                variant={
                  sources.virusTotal.data.malicious >= 3
                    ? "destructive"
                    : sources.virusTotal.data.malicious >= 1
                      ? "warning"
                      : "success"
                }
              />
              <Metric
                label="Podejrzane / Czyste"
                value={`${sources.virusTotal.data.suspicious} / ${sources.virusTotal.data.harmless}`}
              />
            </div>
          )}
        </SourceCard>

        {/* CrowdSec CTI */}
        <SourceCard
          title="CrowdSec CTI"
          icon={<Radar className="size-4" />}
          source={sources.crowdSec}
        >
          {sources.crowdSec.status === "ok" && (
            <div className="space-y-2">
              <div>
                <p className="text-xs text-muted-foreground">Reputacja społeczności</p>
                <Badge
                  variant={
                    (CROWDSEC_REPUTATION[sources.crowdSec.data.reputation] ??
                      CROWDSEC_REPUTATION.unknown).variant
                  }
                  className="mt-1"
                >
                  {(CROWDSEC_REPUTATION[sources.crowdSec.data.reputation] ??
                    CROWDSEC_REPUTATION.unknown).label}
                </Badge>
              </div>
              <Metric
                label="Ocena zagrożenia"
                value={`${sources.crowdSec.data.overallScore} / 5`}
                variant={
                  sources.crowdSec.data.overallScore >= 4
                    ? "destructive"
                    : sources.crowdSec.data.overallScore >= 2
                      ? "warning"
                      : "success"
                }
              />
              {sources.crowdSec.data.behaviors.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">
                    Zaobserwowane zachowania
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {sources.crowdSec.data.behaviors.slice(0, 3).map((behavior) => (
                      <Badge key={behavior} variant="secondary" className="text-[10px]">
                        {behavior}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </SourceCard>

        {/* Geolokalizacja */}
        <SourceCard
          title="Geolokalizacja"
          icon={<Globe className="size-4" />}
          source={sources.geolocation}
        >
          {sources.geolocation.status === "ok" && (
            <div className="space-y-2">
              {sources.geolocation.data.country && (
                <Metric
                  label="Kraj"
                  value={`${sources.geolocation.data.country} (${sources.geolocation.data.countryCode})`}
                  icon={<MapPin className="size-3" />}
                />
              )}
              {sources.geolocation.data.isp && (
                <Metric
                  label="ISP / Organizacja"
                  value={sources.geolocation.data.isp}
                  icon={<Server className="size-3" />}
                />
              )}
              {sources.geolocation.data.proxy && (
                <Badge variant="warning" className="mt-1">Proxy / VPN wykryte</Badge>
              )}
              {sources.geolocation.data.hosting && (
                <Badge variant="warning" className="mt-1">Hosting / Data Center</Badge>
              )}
            </div>
          )}
        </SourceCard>
      </div>
    </div>
  );
}

function SourceCard({
  title,
  icon,
  source,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  source: { status: string; message?: string };
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {source.status === "ok" ? (
          children
        ) : (
          <p className="text-xs text-muted-foreground">
            {source.message ?? "Dane niedostępne."}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function Metric({
  label,
  value,
  variant,
  icon,
}: {
  label: string;
  value: string;
  variant?: "success" | "warning" | "destructive";
  icon?: React.ReactNode;
}) {
  const colorClass =
    variant === "destructive"
      ? "text-red-400"
      : variant === "warning"
        ? "text-amber-400"
        : variant === "success"
          ? "text-emerald-400"
          : "text-foreground";

  return (
    <div>
      <p className="text-xs text-muted-foreground flex items-center gap-1">
        {icon}
        {label}
      </p>
      <p className={`font-mono text-sm font-medium ${colorClass}`}>{value}</p>
    </div>
  );
}

export function ResultSkeleton() {
  return (
    <div className="space-y-5">
      <Card>
        <CardHeader className="pb-3">
          <Skeleton className="h-5 w-24" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-6 w-48" />
        </CardContent>
      </Card>
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i}>
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-20" />
            </CardHeader>
            <CardContent className="space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
