import type { NextConfig } from "next";

/**
 * BEZPIECZEŃSTWO: Statyczne nagłówki HTTP dla całej aplikacji.
 * Content-Security-Policy jest ustawiane dynamicznie w middleware.ts,
 * ponieważ wymaga unikalnego kryptograficznego nonce per żądanie.
 */
const securityHeaders = [
  {
    // Wymusza HTTPS przez 2 lata — ochrona przed atakami downgrade / SSL-strip
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  {
    // Blokuje MIME-sniffing (przeglądarka nie zinterpretuje np. tekstu jako skryptu)
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    // Ochrona przed clickjackingiem — zakaz osadzania aplikacji w <iframe>
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    // Ogranicza wyciek pełnych adresów URL do zewnętrznych serwisów
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    // Zasada najmniejszych uprawnień — wyłączamy niepotrzebne API przeglądarki
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
  {
    key: "X-DNS-Prefetch-Control",
    value: "off",
  },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Ukrywa nagłówek "X-Powered-By: Next.js" — utrudnia fingerprinting stacku
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
