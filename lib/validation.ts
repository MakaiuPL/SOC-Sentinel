import { isIP } from "node:net";
import { z } from "zod";

import type { IndicatorType } from "@/types/analysis";

/**
 * BEZPIECZEŃSTWO: Walidacja wejścia metodą białej listy (allow-list).
 *
 * Zamiast wycinać "złe" znaki (blacklista — łatwa do obejścia), akceptujemy
 * WYŁĄCZNIE znaki legalne dla adresów IP i domen: [a-zA-Z0-9 . : -].
 * To z definicji eliminuje XSS (<, >, "), SQL/NoSQL injection (', ;, $),
 * command injection (|, &, `) oraz path traversal (/, \).
 */
const ALLOWED_CHARS_REGEX = /^[a-zA-Z0-9.:\-]+$/;

// RFC 1035: etykiety 1-63 znaków, bez myślnika na początku/końcu, min. jedna kropka
const DOMAIN_REGEX =
  /^(?=.{4,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$/;

export const analyzeRequestSchema = z.object({
  query: z
    .string({ required_error: "Pole wskaźnika jest wymagane." })
    .trim()
    .min(2, "Wskaźnik jest zbyt krótki.")
    // 253 znaki = maksymalna długość FQDN — twardy limit chroni też przed ReDoS
    .max(253, "Wskaźnik przekracza maksymalną długość (253 znaki).")
    .regex(
      ALLOWED_CHARS_REGEX,
      "Wykryto niedozwolone znaki. Akceptowane są wyłącznie adresy IP i nazwy domen."
    ),
});

export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;

/** Klasyfikuje zwalidowany ciąg jako IP (via node:net.isIP) lub domenę. */
export function classifyIndicator(value: string): IndicatorType | null {
  if (isIP(value) !== 0) return "ip";
  if (DOMAIN_REGEX.test(value)) return "domain";
  return null;
}

/**
 * BEZPIECZEŃSTWO: Ochrona przed SSRF (Server-Side Request Forgery).
 *
 * Serwer wykonuje żądania HTTP na podstawie danych od użytkownika — bez tego
 * filtra atakujący mógłby skanować sieć wewnętrzną (10.0.0.0/8, 192.168.0.0/16)
 * lub odpytać metadane chmury (169.254.169.254 — kradzież poświadczeń AWS/GCP).
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const version = isIP(ip);

  if (version === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true; // "this", prywatna, loopback
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a === 169 && b === 254) return true; // link-local + metadane chmury
    if (a === 172 && b >= 16 && b <= 31) return true; // prywatna 172.16.0.0/12
    if (a === 192 && b === 168) return true; // prywatna 192.168.0.0/16
    if (a >= 224) return true; // multicast + zarezerwowane
    return false;
  }

  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::" || lower === "::1") return true; // unspecified, loopback
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA fc00::/7
    if (/^fe[89ab]/.test(lower)) return true; // link-local fe80::/10
    if (lower.startsWith("::ffff:")) return true; // IPv4-mapped — obejście filtra v4
    return false;
  }

  return true; // nieznany format traktujemy jako niebezpieczny (fail-closed)
}
