"use client";

import { useState, useCallback, FormEvent } from "react";
import { Search, Loader2, Zap } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ResultCards, ResultSkeleton } from "@/components/dashboard/result-cards";
import { SecurityInfo } from "@/components/dashboard/security-info";

import type { AnalysisResponse } from "@/types/analysis";

/**
 * BEZPIECZEŃSTWO: Walidacja po stronie klienta (defense in depth).
 * Mimo że serwer i tak zweryfikuje dane przez Zod, klient zatrzymuje
 * oczywiste błędy zanim dotrą do sieci — mniej zapytań = mniejsza
 * powierzchnia ataku na warstwę API.
 */
const CLIENT_ALLOWED_REGEX = /^[a-zA-Z0-9.:\-]{2,253}$/;

export default function HomePage() {
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);

      const trimmed = query.trim();
      if (!CLIENT_ALLOWED_REGEX.test(trimmed)) {
        setError(
          "Niedozwolone znaki w zapytaniu. Akceptowane są wyłącznie adresy IP i domeny."
        );
        return;
      }

      setLoading(true);
      setResult(null);

      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: trimmed }),
        });

        const payload = await response.json();

        if (!response.ok) {
          setError(
            payload.error ?? `Błąd serwera (HTTP ${response.status}).`
          );
          return;
        }

        setResult(payload as AnalysisResponse);
      } catch {
        setError("Nie można połączyć się z serwerem. Sprawdź połączenie sieciowe.");
      } finally {
        setLoading(false);
      }
    },
    [query]
  );

  return (
    <div className="min-h-screen">
      {/* ── Nagłówek (top bar à la konsola SOC) ── */}
      <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
          <div className="flex items-center gap-2.5">
            <Zap className="size-5 text-muted-foreground" />
            <span className="text-sm font-semibold tracking-wide">
              SOC Sentinel
            </span>
            <Badge variant="outline" className="ml-1 text-[10px]">
              L1 TRIAGE CONSOLE
            </Badge>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="relative flex size-2">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
            </span>
            System operacyjny
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 pb-24 pt-12">
        {/* ── Hero / Intro ── */}
        <div className="mb-10 space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            Analiza wskaźników zagrożeń (IOC)
          </h1>
          <p className="max-w-2xl text-sm text-muted-foreground">
            Wprowadź adres IP lub domenę, aby przeprowadzić wieloźródłową weryfikację
            reputacji z wykorzystaniem AbuseIPDB, VirusTotal oraz danych geolokalizacyjnych.
            Wyniki są korelowane w czasie rzeczywistym z zachowaniem najwyższych
            standardów bezpieczeństwa.
          </p>
        </div>

        {/* ── Formularz analizy ── */}
        <form onSubmit={handleSubmit} className="mb-10 flex flex-col gap-3 sm:flex-row">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Np. 185.220.101.34 lub malware-c2.example.com"
            className="font-mono max-w-xl"
            disabled={loading}
            // Brak atrybutu autoComplete="off" celowo — chcemy umożliwić
            // analitykowi szybkie przywołanie wcześniej badanych wskaźników
            autoComplete="off"
            spellCheck={false}
          />
          <Button type="submit" disabled={loading} className="shrink-0">
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Search className="size-4" />
            )}
            {loading ? "Analizowanie…" : "Analizuj wskaźnik"}
          </Button>
        </form>

        {/* ── Komunikat błędu ── */}
        {error && (
          <Alert variant="destructive" className="mb-10 max-w-xl">
            <AlertTitle>Błąd analizy</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* ── Skeleton loader podczas zapytania ── */}
        {loading && <ResultSkeleton />}

        {/* ── Wyniki analizy ── */}
        {result && !loading && <ResultCards result={result} />}

        {/* ── Separator i sekcja bezpieczeństwa dla rekruterów ── */}
        <div className="my-16 border-t border-border" />

        <SecurityInfo />
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto flex h-12 max-w-6xl items-center justify-between px-4 text-[11px] text-muted-foreground">
          <span>SOC Sentinel L1 Dashboard &copy; {new Date().getFullYear()}</span>
          <span>Projekt demonstracyjny — dane z publicznych API TI</span>
        </div>
      </footer>
    </div>
  );
}
