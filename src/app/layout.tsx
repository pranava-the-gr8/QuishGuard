import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SafeScan / QuishGuard — Check before you click",
  description: "Zero-Execution QR Code & Malicious URL Threat Inspection Engine with Multi-Layer AI Analysis.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-[#070b12] text-slate-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
