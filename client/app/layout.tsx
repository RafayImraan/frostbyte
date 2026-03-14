import type { Metadata } from "next";
import "./globals.css";
import { Space_Grotesk, Inter } from "next/font/google";
import { ThemeToggle } from "../components/ThemeToggle";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-display",
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-body",
});

export const metadata: Metadata = {
  title: "AI CyberShield",
  description: "Real-Time Scam & Fraud Detection System",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={`${spaceGrotesk.variable} ${inter.variable} bg-cyber`}>
        <div className="min-h-screen relative overflow-hidden">
          <div className="absolute inset-0 grid-overlay" />
          <div className="relative z-10">{children}</div>
          <ThemeToggle />
        </div>
      </body>
    </html>
  );
}
