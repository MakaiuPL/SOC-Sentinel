import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4">
      <p className="text-sm font-medium text-muted-foreground">404</p>
      <h1 className="text-xl font-semibold">Nie znaleziono zasobu</h1>
      <p className="max-w-sm text-center text-sm text-muted-foreground">
        Żądany wskaźnik lub strona nie istnieje. Wróć do konsoli, aby przeprowadzić
        nową analizę.
      </p>
      <Link
        href="/"
        className="mt-2 inline-flex items-center gap-2 text-sm text-foreground underline underline-offset-4 hover:text-muted-foreground transition-colors"
      >
        <ArrowLeft className="size-4" />
        Powrót do konsoli
      </Link>
    </div>
  );
}
