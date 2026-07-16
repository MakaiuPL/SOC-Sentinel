import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Gauge,
  KeyRound,
  LockKeyhole,
  ShieldCheck,
  XCircle,
} from "lucide-react";

const HARDENING_MEASURES = [
  {
    icon: <Gauge className="size-5 text-amber-400" />,
    title: "Rate Limiting",
    description:
      "Limit 4 zapytań/min z jednego adresu IP — celowo dopasowany do najciaśniejszego darmowego planu w łańcuchu (VirusTotal: 4 lookups/min). Mechanizm okna przesuwnego (sliding window) na bazie LRU cache z TTL — chroni limity darmowych API przed wyczerpaniem, a proces serwera przed atakiem DoS (ograniczenie `max` na 5 000 wpisów zapobiega wyciekowi pamięci przy spoofingu IP).",
  },
  {
    icon: <XCircle className="size-5 text-red-400" />,
    title: "Walidacja danych wejściowych (Zod)",
    description:
      "Biała lista znaków akceptowanych w polu wskaźnika: wyłącznie [a-zA-Z0-9.:-]. Odrzucamy wszystko inne — znaki specjalne, nawiasy, kod HTML — zanim trafi do logiki biznesowej. Maks. długość 253 znaki. Wszystko zdefiniowane jako schemat Zod, który jest pojedynczym źródłem prawdy o dopuszczalnym formacie zapytania.",
  },
  {
    icon: <KeyRound className="size-5 text-emerald-400" />,
    title: "Klucze API tylko server-side",
    description:
      "Klucze do AbuseIPDB, VirusTotal i CrowdSec CTI są przechowywane wyłącznie w zmiennych środowiskowych serwera (bez prefiksu NEXT_PUBLIC_). Żądania do zewnętrznych serwisów TI wykonują się w API Routes Next.js — przeglądarka nigdy nie widzi surowych odpowiedzi ani kluczy. Moduł `server-only` wymusza to na poziomie kompilacji.",
  },
  {
    icon: <ShieldCheck className="size-5 text-blue-400" />,
    title: "Content Security Policy (CSP)",
    description:
      "Dyrektywa `script-src` z kryptograficznym nonce i `strict-dynamic` blokuje wykonanie wstrzykniętych skryptów (XSS). `frame-ancestors: 'none'` chroni przed clickjackingiem. `object-src: 'none'` blokuje Flash/ActiveX. Nagłówek generowany dynamicznie w middleware z unikalnym nonce per każde żądanie HTTP.",
  },
  {
    icon: <LockKeyhole className="size-5 text-violet-400" />,
    title: "Ochrona przed SSRF",
    description:
      "Przed wysłaniem zapytania do zewnętrznych API serwer sprawdza, czy podany adres IP nie należy do zakresów prywatnych (RFC 1918: 10.x.x.x, 192.168.x.x itd.), link-local (169.254.x.x — w tym metadane chmury AWS/GCP) ani loopback (127.x.x.x, ::1). Uniemożliwia to skanowanie sieci wewnętrznej.",
  },
];

export function SecurityInfo() {
  return (
    <section className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold">Architektura bezpieczeństwa</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Poniżej opisuję warstwy zabezpieczeń (defense in depth) zaimplementowane
          w tej aplikacji. Każda odpowiada na konkretne zagrożenie z listy OWASP Top 10.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {HARDENING_MEASURES.map((item) => (
          <Card key={item.title}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                {item.icon}
                {item.title}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-xs leading-relaxed">
                {item.description}
              </CardDescription>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
