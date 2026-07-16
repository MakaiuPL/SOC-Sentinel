import { NextRequest, NextResponse } from "next/server";

/**
 * BEZPIECZEŃSTWO: Middleware ustawia Content-Security-Policy z kryptograficznym
 * nonce generowanym per żądanie. Dyrektywa 'strict-dynamic' + nonce eliminuje
 * potrzebę 'unsafe-inline' dla skryptów, co jest kluczową obroną przed XSS —
 * nawet jeśli atakujący wstrzyknie <script>, przeglądarka go nie wykona,
 * bo nie zna jednorazowego nonce.
 */
export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";

  const cspDirectives = [
    `default-src 'self'`,
    // Skrypty tylko z własnego origin + nonce; 'unsafe-eval' wyłącznie w dev (HMR)
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // Tailwind generuje statyczny CSS; 'unsafe-inline' dla stylów to świadomy,
    // niskiego ryzyka kompromis (style nie wykonują kodu) wymagany przez Next.js
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' blob: data:`,
    `font-src 'self'`,
    // Frontend komunikuje się wyłącznie z własnym API — zewnętrzne serwisy TI
    // są odpytywane po stronie serwera, więc nie potrzebują wpisu w CSP
    `connect-src 'self'${isDev ? " ws:" : ""}`,
    `object-src 'none'`,
    // Ochrona przed podmianą bazowego URL (base-tag hijacking)
    `base-uri 'self'`,
    // Formularze mogą wysyłać dane tylko do własnej aplikacji
    `form-action 'self'`,
    // Nowoczesny odpowiednik X-Frame-Options: DENY (anty-clickjacking)
    `frame-ancestors 'none'`,
    ...(isDev ? [] : ["upgrade-insecure-requests"]),
  ];

  const csp = cspDirectives.join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });
  response.headers.set("Content-Security-Policy", csp);

  return response;
}

export const config = {
  matcher: [
    {
      // CSP dotyczy dokumentów HTML — pomijamy assety statyczne i prefetch
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
