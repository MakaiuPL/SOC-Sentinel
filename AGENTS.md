# SOC Sentinel — Konwencje projektu

## Język

- Kod: angielski (nazwy zmiennych, funkcji, typów — standard branżowy)
- Komentarze w kodzie: **polski** (objaśniają decyzje bezpieczeństwa dla rekrutera)
- UI/UX, mikroteksty, placeholder'y: **polski**
- Dane demonstracyjne: **polski**

## Stos

- Next.js 15 (App Router) + TypeScript strict mode
- Tailwind CSS (dark mode only, system SOC)
- Komponenty UI w `components/ui/` (Button, Card, Input, Badge, Alert, Skeleton)
- Walidacja: Zod (biała lista, nie blacklista)
- Rate limiting: LRU cache in-memory
- Font: Inter (sans) + JetBrains Mono (mono) via next/font

## Zasady UI/UX

- **Dark mode permanentny** — `globals.css` definiuje wyłącznie zmienne ciemnego motywu
- Kolory semantyczne: zielony (clean), czerwony (malicious), żółty (suspicious)
- Komponenty shadcn ręcznie napisane (bez CLI shadcn) — `cn()` z `lib/utils.ts`
- Focus states: ring-2 + ring-offset-2 (dostępność WCAG)
- Bez placeholderów "Lorem Ipsum" — realistyczne dane w języku polskim
- Skeleton loader podczas zapytań API — UX płynności

## Bezpieczeństwo (krytyczne)

1. **Walidacja Zod** — biała lista `[a-zA-Z0-9.:-]`, max 253 znaki
2. **Rate limiting** — 4 zapytania/min (dopasowane do darmowego planu VirusTotal), okno przesuwne, LRU z `max`=5000
3. **CSP nonce** — middleware generuje `crypto.randomUUID()` → base64, strict-dynamic
4. **SSRF** — blokada IP prywatnych, link-local, loopback przed fetch
5. **Sekrety** — `server-only`, zmienne bez `NEXT_PUBLIC_`, `.env.local` w `.gitignore`
6. **Timeouty** — 8s na każde zewnętrzne API (AbortSignal.timeout)

## Komendy

```bash
npm run dev     # Next.js dev server (localhost:3000)
npm run build   # Produkcyjny build
npm run lint    # ESLint (next/core-web-vitals)
```
