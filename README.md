# 🛡️ QuishGuard: Zero-Execution QR & URL Threat Inspection Engine

> **Hackathon Problem Statement**:  
> *"The explosive rise of QR Code Phishing (Quishing) and zero-day malicious URLs, combined with the complete lack of safe, real-time preview mechanisms for everyday users."*

> **Our Solution**:  
> A lightweight, zero-execution security web application that allows users to upload or scan a QR code image, extract its URL safely, and run static multi-layer threat evaluation without ever executing or visiting the dangerous webpage.

---

## 🌟 Key Features

1. **🔒 Zero-Execution Engine**:
   - Decodes QR codes directly on the client canvas via `jsQR`.
   - Analyzes target links statically — **0 bytes of untrusted remote JavaScript executed**.
   - No tracking beacons, cookie drops, drive-by downloads, or device fingerprinting risks.

2. **📊 4-Layer Threat Scoring Architecture (0–100%)**:
   - **Layer 1: Heuristic & Lexical Analysis** (0–25 pts): Raw IP host detection, unencrypted HTTP, non-standard ports, `@` credential spoofing, deep subdomains, suspicious TLDs, and executable extensions (`.exe`, `.apk`).
   - **Layer 2: Typosquatting & Homoglyphs** (0–25 pts): Levenshtein distance matching and character substitution (`paypa1`, `micros0ft`) against top enterprise brands (PayPal, Microsoft, Google, Apple, Chase, etc.).
   - **Layer 3: Domain Age & Registry Intelligence** (0–25 pts): Live open ICANN RDAP query flags domains created within the last 14–30 days.
   - **Layer 4: Gemini AI Threat Evaluation** (0–25 pts): Advanced semantic intent classification (credential harvesting, OAuth phishing, drive-by malware) producing plain-English advice for non-technical users.

3. **🎨 Pixel-Accurate UI/UX matching v0 Design**:
   - High-contrast cybersecurity dark theme (`#070b12`, `#0d1825`, `#0d131e`).
   - Dynamic tone styling: **Safe** (Emerald), **Suspicious** (Amber), **Dangerous** (Rose), and **Critical** (Red).
   - Real-time radar scan telemetry and multi-segment risk meter bar.
   - Interactive benchmark switcher (`safe`, `suspicious`, `dangerous`) for live hackathon judging demos.
   - Full Scan History modal.

4. **⚡ Full Stack Supabase Backend**:
   - PostgreSQL schema with Row-Level Security (RLS) policies.
   - Support for both anonymous guest scans and registered user profiles.
   - Storage bucket `qr-codes` configured for QR uploads.
   - Seed data with benchmark threat cases and target brand dictionaries.

---

## 🚀 Getting Started

### 1. Prerequisites
- Node.js 18+ (tested on v24)
- npm or pnpm

### 2. Setup Environment
Copy `.env.example` to `.env.local`:
```bash
cp .env.example .env.local
```

Fill in your Supabase project keys and Gemini API key:
```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
GEMINI_API_KEY=your-gemini-api-key
```
*(Note: If API keys are omitted during local dev, the app automatically falls back to built-in heuristic presets so the UI remains 100% functional for testing!)*

### 3. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 👥 Team Collaboration (5 Roles)

- **Backend**: Runs [`supabase/schema.sql`](supabase/schema.sql) and [`supabase/seed.sql`](supabase/seed.sql) in Supabase SQL editor.
- **Frontend**: Customizes UI components in [`src/app/page.tsx`](src/app/page.tsx) and styling in [`src/app/globals.css`](src/app/globals.css).
- **Full Stack (You)**: Coordinates the 4-layer inspection pipeline in [`src/engine/`](src/engine/) and API routes in [`src/app/api/`](src/app/api/).
- **UI/UX Designers**: Refines v0 screens and brand assets.
- **GitHub**: All code is version controlled and ready to push to your team repository.

---

## 🏆 Hackathon Demo Scenarios to Show Judges

1. **Safe Scan**: Try `https://accounts.google.com`  
   - Result: Score **12/100 (Safe)**, verified official domain, 27-year domain history.
2. **Suspicious Shortened URL**: Try `https://bit.ly/3x8QkLp`  
   - Result: Score **48/100 (Suspicious)**, hides ultimate target, warning issued.
3. **Malicious Quish Attack**: Try `https://paypa1-security-verification.com/login?token=8f92b489a2e`  
   - Result: Score **87/100 (Dangerous)**, Levenshtein typosquatting triggered ("l" replaced by "1"), 2-day-old domain, clear credential theft warning.
4. **QR Code Upload**: Drag and drop any QR code image — watch the client canvas decode the URL with zero execution!
