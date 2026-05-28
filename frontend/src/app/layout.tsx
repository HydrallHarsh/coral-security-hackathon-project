import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HarborGuard",
  description: "Schema-aware security investigation agent powered by Coral",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
