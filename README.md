# SOC Sentinel — Konsola Triage IOC dla Analityka SOC L1

[![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-06b6d4?logo=tailwindcss)](https://tailwindcss.com)

## O co chodzi? (Dla rekrutera)

**Jak czytać ten projekt:** to w pełni działające narzędzie, jakiego używa analityk SOC pierwszej linii do szybkiej oceny, czy podejrzany adres IP lub domena stanowi realne zagrożenie.

Wyobraź sobie zgłoszenie na helpdesku: *"Dostałem dziwny mail z linkiem do 185.220.101.34 — czy to bezpieczne?"* Analityk otwiera SOC Sentinel, wpisuje adres i w ciągu sekund otrzymuje skorelowaną ocenę z czterech niezależnych źródeł threat intelligence — bez przełączania się między zakładkami, bez ręcznego kopiowania kluczy API.

Co konkretnie pokazuje ten projekt:

| Kompetencja | Jak to widać w kodzie |
|---|---|
| **Znajomość workflow SOC / IT Security** | Wzorzec triage: zbierz dane → skoreluj źródła → wystaw werdykt → udokumentuj kontekst. Logika `computeVerdict()` waży sygnały z wielu API zamiast zero-jedynkowej oceny. |
| **Świadomość false positive'ów** | Verdict Context Engine automatycznie obniża priorytet alertu, gdy IP pochodzi z puli chmurowej (Azure, AWS, GCP) — bo adres mógł zostać "zabrudzony" przez poprzedniego klienta. To codzienność w SOC. |
| **Programowanie z myślą o bezpieczeństwie** | Aplikacja nie tylko korzysta z API — sama jest zabezpieczona przed OWASP Top 10: rate limiting, walidacja Zod (biała lista znaków, nie czarna), CSP z nonce, blokada SSRF, ukrywanie kluczy przed frontendem. |
| **Umiejętność integracji API** | Odpytywanie AbuseIPDB, VirusTotal, CrowdSec CTI i IP-API — równolegle (Promise.all), z timeoutem 8s na każde, z bezpieczną obsługą awarii każdego źródła z osobna. |
| **UI / UX w narzędziach bezpieczeństwa** | Interfejs wzorowany na konsolach SOC (CrowdStrike, Splunk): ciemny motyw, semantyczne kolory (zielony = clean, żółty = suspicious, czerwony = malicious), monospace dla danych technicznych, skeleton loader podczas zapytań. |

## Demo (co rekruter zobaczy na ekranie)

1. **Formularz analizy** — wpisujesz IP (np. `185.220.101.34`) lub domenę
2. **Karta werdyktu** — kolorowy badge + skorelowana ocena ryzyka + kontekst decyzji (jeśli dotyczy)
3. **4 karty źródłowe** — AbuseIPDB (reputacja), VirusTotal (silniki AV), CrowdSec (zachowania), geolokalizacja (kraj/ISP/ASN)
4. **Sekcja "Architektura bezpieczeństwa"** — 5 kart opisujących każdą warstwę hardeningu: rate limiting, walidacja wejścia, ochrona kluczy API, CSP, ochrona SSRF

## Szybki start (dla technicznych)

```bash
git clone https://github.com/twojuser/SOC-Sentinel.git
cd SOC-Sentinel
cp .env.example .env.local
# Uzupełnij klucze API w .env.local (instrukcja poniżej)
npm install
npm run dev
```

### Klucze API (darmowe)

| Źródło | DARMOWY limit | Gdzie zdobyć |
|---|---|---|
| AbuseIPDB | 1000/dzień | https://www.abuseipdb.com → Account → API → Create Key |
| VirusTotal | 500/dzień, 4/min | https://www.virustotal.com/gui/my-apikey |
| CrowdSec CTI | ~50/dzień | https://app.crowdsec.net → Settings → CTI API Keys |
| IP-API (geolokalizacja) | bez limitu, bez klucza | — |

> **Uwaga:** aplikacja działa nawet z samym IP-API (geolokalizacja). Każdy kolejny klucz wzbogaca dane. Bez kluczy źródła są pomijane z komunikatem "Źródło nieaktywne".

## Architektura

```
SOC-Sentinel/
├── middleware.ts               # CSP nonce per żądanie + strict-dynamic (anty-XSS)
├── next.config.ts              # HSTS, X-Frame-Options, Permissions-Policy
├── app/
│   ├── api/analyze/route.ts    # 5 warstw obrony: rate limit → parsowanie → Zod → SSRF check → TI query
│   ├── layout.tsx              # Inter + JetBrains Mono, polski lang, dark mode
│   ├── page.tsx                # Dashboard z formularzem, loaderem i wynikami
│   └── globals.css             # Zmienne CSS dla ciemnego motywu SOC
├── components/
│   ├── ui/                     # Button, Card, Input, Badge, Alert, Skeleton (ręczne porty shadcn)
│   └── dashboard/              # ResultCards (z kontekstem false positive), SecurityInfo
├── lib/
│   ├── rate-limit.ts           # Sliding window 4/min, LRU z hard cap 5000 (anti-DoS)
│   ├── threat-intel.ts         # Klienty API + Verdict Context Engine + detekcja chmur
│   ├── validation.ts           # Zod schema + anty-XSS + anty-SSRF (RFC 1918)
│   └── utils.ts                # cn() — łączenie klas Tailwind
└── types/analysis.ts           # Dyskryminowane unie — frontend nigdy nie widzi surowych błędów API
```

## Stos techniczny

- **Next.js 15** (App Router) — server-side API Routes ukrywające klucze przed przeglądarką
- **TypeScript** strict mode — każda struktura zdefiniowana typem
- **Tailwind CSS** — ciemny motyw korporacyjny, 0 niestandardowych kolorów inline
- **Zod** — walidacja typu biała lista: tylko `[a-zA-Z0-9.:-]`, maks. 253 znaki
- **lru-cache** — in-memory rate limiter z oknem przesuwnym
- **lucide-react** — ikony (ShieldCheck, Radar, Globe, etc.)

---

## Co dalej? Twój następny projekt portfolio

Ten projekt pokrywa umiejętność **analizy wskaźników sieciowych (IOC)**. Następny powinien celować w inną domenę security, żebyś pokazał szerokość kompetencji. Rekomenduję:

### PhishCatch — Analizator Wiadomości Phishingowych

**Zakres:** SOC L1 + Helpdesk Security

Narzędzie, do którego analityk wrzuca podejrzanego maila (jako plik `.eml` lub surowy tekst z headera + body). Aplikacja automatycznie:

- Wyciąga nagłówki SPF / DKIM / DMARC i wizualizuje, czy autoryzacja przeszła (zielone/żółte/czerwone checkmarki)
- Parsuje MIME, wyodrębnia attachmenty i zagnieżdżone URLe
- Przepuszcza każdy link przez VirusTotal URL API (ponowne wykorzystanie kodu z tego projektu!)
- Ocenia ryzyko językowe: wykrywa słowa kluczowe w treści (nagłość, presja, podszywanie)
- Generuje raport w formacie nadającym się do wklejenia w zgłoszenie do SOC Tier 2

**Dlaczego HR to kupi:**
- Phishing to wektor nr 1 ataków na organizacje — temat na każdym stanowisku security
- Łączy SOC (analiza techniczna nagłówków) z Helpdeskiem (zgłoszenie od użytkownika)
- Demonstruje znajomość protokołów e-mail (SPF/DKIM/DMARC) — rzadka umiejętność u juniorów
- Kod będzie podobny architektonicznie do SOC Sentinel (Next.js + te same pakiety), więc budujesz szybko
- Pokażesz portfolioowym narzędziem dokładnie to, co rekruter widzi na swojej liście wymagań ogłoszenia

**Inne opcje (jeśli wolisz inną domenę):**

| Projekt | Domena | Co pokazuje |
|---|---|---|
| **LogHound** | SIEM / analiza logów | Parsuje Windows Event Log / syslog, wykrywa brute-force (5+ failed loginów z jednego IP w 60s), wizualizuje oś czasu ataku |
| **PortShadow** | Network Security | Dashboard na wyniki Nmapa — otwarte porty, wykryte wersje usług, porównanie skanów sprzed i po patchowaniu |
| **HashGuard** | Password Security | Sprawdza hashe haseł przez HaveIBeenPwned API (k-anonimowość, tylko 5 pierwszych znaków hasha), ocenia siłę polityki haseł w organizacji |

---

## Wymagania

- Node.js ≥ 18
- npm ≥ 9

## Autor

Projekt demonstracyjny portfolio na stanowiska Junior SOC Analyst / Helpdesk Security / IT Security. Każda linijka kodu opatrzona jest komentarzem wyjaśniającym decyzję bezpieczeństwa — czytaj kod jako uzupełnienie CV.
