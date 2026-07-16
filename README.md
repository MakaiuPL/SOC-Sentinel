# Webowy Cyber Threat Intelligence Dashboard (SOC L1)

Kompletny projekt portfolio demonstrujący umiejętności **Junior SOC Analyst / Helpdesk Security** poprzez zbudowanie profesjonalnego dashboardu do analizy wskaźników zagrożeń (IOC).

## Stos technologiczny

- **Framework:** Next.js 15 (App Router) + TypeScript
- **Stylizacja:** Tailwind CSS + komponenty Shadcn UI (własnoręcznie napisane)
- **Walidacja:** Zod (biała lista znaków + limity długości)
- **Rate Limiting:** LRU cache (in-memory, okno przesuwne, 4 zapytania/min)
- **CSP:** Kryptograficzny nonce generowany per żądanie w middleware
- **Threat Intel:** AbuseIPDB, VirusTotal, CrowdSec CTI, IP-API

## Szybki start

1. Sklonuj repozytorium:
   ```bash
   git clone <url>
   cd SOC-L1
   ```

2. Skopiuj plik konfiguracji środowiska:
   ```bash
   cp .env.example .env.local
   ```

3. Uzupełnij klucze API w `.env.local`:
   - `ABUSEIPDB_API_KEY` — załóż darmowe konto na https://www.abuseipdb.com, następnie wejdź w **Account → API** (https://www.abuseipdb.com/account/api) i kliknij **Create Key** (darmowy plan: 1000 zapytań/dzień)
   - `VIRUSTOTAL_API_KEY` — z https://www.virustotal.com/gui/my-apikey (darmowy plan: 4 zapytania/min, 500/dzień)
   - `CROWDSEC_CTI_API_KEY` — załóż konto na https://app.crowdsec.net, następnie **Settings → CTI API Keys → Create** (opcjonalny — bez klucza źródło jest pomijane)

4. Zainstaluj zależności:
   ```bash
   npm install
   ```

5. Uruchom serwer deweloperski:
   ```bash
   npm run dev
   ```

6. Otwórz http://localhost:3000 w przeglądarce.

## Architektura projektu

```
SOC-L1/
├── middleware.ts            # CSP nonce + nagłówki bezpieczeństwa
├── next.config.ts           # HSTS, X-Frame-Options, Permissions-Policy
├── app/
│   ├── api/analyze/route.ts # Backend API: walidacja → rate limit → TI query
│   ├── layout.tsx           # Root layout (Inter + JetBrains Mono, PL lang)
│   ├── page.tsx             # Frontend: formularz + wynik + opis bezpieczeństwa
│   └── globals.css          # Tailwind + zmienne CSS (ciemny motyw SOC)
├── components/
│   ├── ui/                  # Shadcn: Button, Card, Input, Badge, Alert, Skeleton
│   └── dashboard/           # ResultCards, SecurityInfo
├── lib/
│   ├── rate-limit.ts        # Okno przesuwne 4 zapytania/min
│   ├── threat-intel.ts      # Klienty API (AbuseIPDB, VirusTotal, CrowdSec, IP-API)
│   └── validation.ts        # Zod schema + ochrona SSRF
├── types/
│   └── analysis.ts          # Dyskryminowane unie (safe DTO)
├── tailwind.config.ts
├── tsconfig.json
└── .env.example
```

## Bezpieczeństwo

| Warstwa | Mechanizm |
|---------|-----------|
| Transport | HSTS 2 lata, blokada HTTP (upgrade-insecure-requests) |
| XSS | CSP z nonce + strict-dynamic, Zod biała lista znaków |
| Clickjacking | CSP frame-ancestors: none |
| DoS | Rate limiting 4/min (dopasowany do kwoty VirusTotal), LRU z hard limitem pamięci |
| SSRF | Blokada IP prywatnych / link-local / loopback |
| Sekrety | `server-only` + zmienne bez `NEXT_PUBLIC_` |
| Iniekcje | Biała lista znaków eliminuje SQL/NoSQL/Command Injection |

## Wymagania systemowe

- Node.js ≥ 18
- npm ≥ 9

## Uwagi

- Projekt demonstruje **wiedzę ofensywną i defensywną** — każdy komponent zawiera komentarze uzasadniające decyzje bezpieczeństwa.
- Sekcja **Architektura bezpieczeństwa** na stronie głównej opisuje każdą warstwę zabezpieczeń w języku zrozumiałym zarówno dla technicznego menedżera, jak i rekrutera HR.
