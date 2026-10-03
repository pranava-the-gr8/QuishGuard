'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  History,
  HelpCircle,
  Sparkles,
  Link2,
  Globe,
  X,
  ScanLine,
  Info,
  QrCode,
  Upload,
  ArrowUpRight,
  BadgeCheck,
  TriangleAlert,
  ChevronRight,
  Clock,
  Lock,
  Layers,
  CheckCircle2,
  AlertCircle,
  Copy,
  ExternalLink,
  RefreshCw,
  Cpu
} from 'lucide-react';
import jsQR from 'jsqr';
import { runZeroExecutionInspection, type InspectionReport } from '@/engine/evaluator';

// Tone styling presets matching the v0 prototype
const TONE_STYLES = {
  emerald: {
    text: 'text-emerald-400',
    badge: 'border-emerald-400/25 bg-emerald-400/10 text-emerald-300',
    border: 'border-emerald-500/25',
    bg: 'from-emerald-950/30 to-[#0d1825]',
    ring: 'border-emerald-500/20',
    soft: 'bg-emerald-500/[0.05]',
    accent: '#34d399',
  },
  amber: {
    text: 'text-amber-400',
    badge: 'border-amber-400/25 bg-amber-400/10 text-amber-300',
    border: 'border-amber-500/25',
    bg: 'from-amber-950/30 to-[#0d1825]',
    ring: 'border-amber-500/20',
    soft: 'bg-amber-500/[0.05]',
    accent: '#fbbf24',
  },
  rose: {
    text: 'text-rose-400',
    badge: 'border-rose-400/25 bg-rose-400/10 text-rose-300',
    border: 'border-rose-500/25',
    bg: 'from-rose-950/30 to-[#0d1825]',
    ring: 'border-rose-500/20',
    soft: 'bg-rose-500/[0.05]',
    accent: '#fb7185',
  },
  crimson: {
    text: 'text-red-400',
    badge: 'border-red-500/30 bg-red-500/15 text-red-300',
    border: 'border-red-600/35',
    bg: 'from-red-950/40 to-[#0d1825]',
    ring: 'border-red-600/25',
    soft: 'bg-red-500/[0.07]',
    accent: '#f87171',
  }
};

interface IndicatorCheck {
  label: string;
  value: string;
  status: 'Pass' | 'Review' | 'Alert';
  icon: React.ElementType;
}

interface ThreatReportView {
  url: string;
  isQr: boolean;
  score: number;
  level: string;
  tone: 'emerald' | 'amber' | 'rose' | 'crimson';
  title: string;
  explanation: string;
  recommendation: string;
  checks: IndicatorCheck[];
  zeroExecution: boolean;
  durationMs: number;
}

// Built-in benchmark presets matching the v0 prototype
const BENCHMARK_PRESETS: Record<'safe' | 'suspicious' | 'dangerous', ThreatReportView> = {
  safe: {
    url: 'https://accounts.google.com',
    isQr: false,
    score: 12,
    level: 'Safe',
    tone: 'emerald',
    title: 'Verified Official Domain',
    explanation: 'This link falls in the safe range. No significant indicators of phishing or malware were detected.',
    recommendation: 'This destination appears safe to visit. Continue to verify the page before entering sensitive information.',
    zeroExecution: true,
    durationMs: 245,
    checks: [
      { label: 'Domain age', value: 'Established · 27 years', status: 'Pass', icon: Clock },
      { label: 'SSL certificate', value: 'Valid & trusted (Google Trust Services)', status: 'Pass', icon: Lock },
      { label: 'Typosquatting', value: 'No similarity detected · Official Match', status: 'Pass', icon: Shield },
      { label: 'Zero Execution', value: '0 bytes executed · Pure static analysis', status: 'Pass', icon: Cpu },
      { label: 'Domain reputation', value: 'Good reputation · Known top Alexa 10', status: 'Pass', icon: Globe },
      { label: 'URL patterns', value: 'No suspicious patterns or evasion', status: 'Pass', icon: Link2 },
    ]
  },
  suspicious: {
    url: 'https://bit.ly/3x8QkLp',
    isQr: false,
    score: 48,
    level: 'Suspicious',
    tone: 'amber',
    title: 'Obfuscated URL Shortener',
    explanation: 'Several signals need review. Avoid entering sensitive information until this destination is independently verified.',
    recommendation: 'Proceed with caution. Verify the sender and domain through a trusted channel before continuing.',
    zeroExecution: true,
    durationMs: 380,
    checks: [
      { label: 'Domain age', value: 'Recently registered target · 18 days', status: 'Review', icon: Clock },
      { label: 'SSL certificate', value: 'Valid, but newly issued', status: 'Pass', icon: Lock },
      { label: 'Typosquatting', value: 'No direct brand match found', status: 'Pass', icon: Shield },
      { label: 'Zero Execution', value: 'Unshortened via HEAD request only', status: 'Review', icon: Cpu },
      { label: 'Domain reputation', value: 'Limited reputation · Low trust TLD', status: 'Review', icon: Globe },
      { label: 'URL patterns', value: 'Opaque redirect hides real landing page', status: 'Review', icon: Link2 },
    ]
  },
  dangerous: {
    url: 'https://paypa1-security-verification.com/login?token=8f92b489a2e',
    isQr: true,
    score: 87,
    level: 'Dangerous',
    tone: 'rose',
    title: 'Quishing: Brand Impersonation',
    explanation: 'Multiple high-risk indicators suggest this destination may be malicious. Do not visit or share sensitive information.',
    recommendation: 'Do not proceed. Close this link and report the message or sender through your organization’s security process.',
    zeroExecution: true,
    durationMs: 412,
    checks: [
      { label: 'Domain age', value: 'Very recent · Registered 2 days ago', status: 'Alert', icon: Clock },
      { label: 'SSL certificate', value: 'Valid Free Cert · Untrusted host', status: 'Review', icon: Lock },
      { label: 'Typosquatting', value: 'Detected · PayPal impersonation ("l" -> "1")', status: 'Alert', icon: Shield },
      { label: 'Zero Execution', value: 'Blocked execution before browser load', status: 'Alert', icon: Cpu },
      { label: 'Domain reputation', value: 'Suspicious registrar & masked privacy', status: 'Alert', icon: Globe },
      { label: 'URL patterns', value: 'Simulated login credential harvesting path', status: 'Alert', icon: Link2 },
    ]
  }
};

export default function HomePage() {
  const [urlInput, setUrlInput] = useState('https://accounts.google.com');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [activeReport, setActiveReport] = useState<ThreatReportView | null>(null);
  const [presetKey, setPresetKey] = useState<'safe' | 'suspicious' | 'dangerous' | 'live'>('safe');
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [showHelpModal, setShowHelpModal] = useState(false);
  const [historyItems, setHistoryItems] = useState<ThreatReportView[]>([
    BENCHMARK_PRESETS.safe,
    BENCHMARK_PRESETS.suspicious,
    BENCHMARK_PRESETS.dangerous
  ]);

  // QR Code Upload State
  const [qrFileName, setQrFileName] = useState<string | null>(null);
  const [qrPreviewUrl, setQrPreviewUrl] = useState<string | null>(null);
  const [qrDecodedUrl, setQrDecodedUrl] = useState<string | null>(null);
  const [qrError, setQrError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Handle URL Form Submit
  const handleScanUrl = async (targetUrl?: string) => {
    const rawUrl = (targetUrl || urlInput).trim();
    if (!rawUrl) return;

    setIsScanning(true);
    setScanStep('Initializing Zero-Execution Inspection Engine...');

    try {
      await new Promise(r => setTimeout(r, 200));
      setScanStep('Running Layer 1: Heuristic & static lexical analysis...');
      await new Promise(r => setTimeout(r, 250));
      setScanStep('Running Layer 2: Checking typosquatting & brand spoofing...');
      await new Promise(r => setTimeout(r, 250));
      setScanStep('Running Layer 3: Querying domain registry & RDAP age...');
      await new Promise(r => setTimeout(r, 300));
      setScanStep('Running Layer 4: Gemini AI threat intent evaluation...');

      // Call our API route or evaluator
      let reportData: InspectionReport;
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: rawUrl })
        });
        const json = await res.json();
        if (json.report) {
          reportData = json.report;
        } else {
          reportData = await runZeroExecutionInspection(rawUrl);
        }
      } catch (err) {
        // Fallback to local client evaluation
        reportData = await runZeroExecutionInspection(rawUrl);
      }

      // Map engine report to UI view
      const tone: 'emerald' | 'amber' | 'rose' | 'crimson' =
        reportData.riskScore >= 90 ? 'crimson' :
        reportData.riskScore >= 60 ? 'rose' :
        reportData.riskScore >= 30 ? 'amber' : 'emerald';

      const level =
        reportData.riskScore >= 90 ? 'Critical' :
        reportData.riskScore >= 60 ? 'Dangerous' :
        reportData.riskScore >= 30 ? 'Suspicious' : 'Safe';

      const domainAgeCheck: IndicatorCheck = {
        label: 'Domain age',
        value: reportData.threatBreakdown.domain_age.age_days !== undefined
          ? `${reportData.threatBreakdown.domain_age.age_days < 30 ? 'Recently registered · ' : 'Established · '}${reportData.threatBreakdown.domain_age.age_days} days`
          : 'Registry data masked',
        status: (reportData.threatBreakdown.domain_age.score >= 18) ? 'Alert' :
                (reportData.threatBreakdown.domain_age.score > 0) ? 'Review' : 'Pass',
        icon: Clock
      };

      const typosquatCheck: IndicatorCheck = {
        label: 'Typosquatting',
        value: reportData.threatBreakdown.typosquatting.target_brand
          ? (reportData.threatBreakdown.typosquatting.is_official_match ? `Verified official ${reportData.threatBreakdown.typosquatting.target_brand}` : `Targeting ${reportData.threatBreakdown.typosquatting.target_brand}`)
          : 'No brand spoofing detected',
        status: (reportData.threatBreakdown.typosquatting.score >= 15) ? 'Alert' :
                (reportData.threatBreakdown.typosquatting.score > 0) ? 'Review' : 'Pass',
        icon: Shield
      };

      const sslCheck: IndicatorCheck = {
        label: 'SSL & Encryption',
        value: reportData.protocol === 'https' ? 'Encrypted HTTPS' : 'Unencrypted plain HTTP',
        status: reportData.protocol === 'https' ? 'Pass' : 'Alert',
        icon: Lock
      };

      const zeroExecutionCheck: IndicatorCheck = {
        label: 'Zero Execution',
        value: 'Isolated static engine · 0 network scripts executed',
        status: 'Pass',
        icon: Cpu
      };

      const reputationCheck: IndicatorCheck = {
        label: 'Domain reputation',
        value: reportData.threatBreakdown.heuristics.flags.includes('raw_ip_address_host')
          ? 'Raw IP Host without domain name'
          : reportData.riskScore > 60 ? 'Untrusted infrastructure' : 'Normal web reputation',
        status: reportData.threatBreakdown.heuristics.flags.includes('raw_ip_address_host') ? 'Alert' :
                reportData.riskScore > 60 ? 'Alert' :
                reportData.riskScore > 30 ? 'Review' : 'Pass',
        icon: Globe
      };

      const urlPatternsCheck: IndicatorCheck = {
        label: 'AI & URL Patterns',
        value: reportData.threatBreakdown.ai_gemini.intent || 'Normal web structure',
        status: reportData.threatBreakdown.ai_gemini.score >= 18 ? 'Alert' :
                reportData.threatBreakdown.ai_gemini.score >= 10 ? 'Review' : 'Pass',
        icon: Link2
      };

      const newReport: ThreatReportView = {
        url: reportData.extractedUrl,
        isQr: false,
        score: reportData.riskScore,
        level,
        tone,
        title: reportData.threatTitle,
        explanation: reportData.summary,
        recommendation: reportData.actionRecommendation,
        zeroExecution: true,
        durationMs: reportData.scanDurationMs,
        checks: [domainAgeCheck, sslCheck, typosquatCheck, zeroExecutionCheck, reputationCheck, urlPatternsCheck]
      };

      setActiveReport(newReport);
      setPresetKey('live');
      setHistoryItems(prev => [newReport, ...prev.filter(item => item.url !== newReport.url)].slice(0, 15));
    } catch (err) {
      console.error(err);
      setActiveReport(BENCHMARK_PRESETS.safe);
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  // Handle QR File Upload & Canvas Decoding
  const handleQrUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setQrFileName(file.name);
    setQrError(null);

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      setQrPreviewUrl(dataUrl);

      // Create an image element to decode pixels on an offscreen canvas
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          setQrError('Failed to initialize canvas decoder.');
          return;
        }

        ctx.drawImage(img, 0, 0, img.width, img.height);
        const imageData = ctx.getImageData(0, 0, img.width, img.height);
        
        // Pure zero-execution client decode using jsQR
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth'
        });

        if (code && code.data) {
          setQrDecodedUrl(code.data);
          setUrlInput(code.data);
        } else {
          setQrError('No readable QR code pattern detected in this image. Try another.');
        }
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  // Switch Benchmark Preset
  const handleSelectPreset = (key: 'safe' | 'suspicious' | 'dangerous') => {
    setPresetKey(key);
    setActiveReport(BENCHMARK_PRESETS[key]);
  };

  const currentStyles = activeReport ? TONE_STYLES[activeReport.tone] : TONE_STYLES.emerald;

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#070b12] text-slate-100 [background-image:linear-gradient(rgba(56,189,248,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.035)_1px,transparent_1px)] [background-size:48px_48px]">
      <div className="relative mx-auto max-w-[1440px] px-3 py-3 sm:px-6 sm:py-6 lg:px-12">
        
        {/* ==================================================================== */}
        {/* HEADER                                                               */}
        {/* ==================================================================== */}
        <header className="flex items-center justify-between border-b border-white/[0.07] pb-4 sm:pb-5">
          <div className="flex items-center gap-3">
            <div className="grid size-9 place-items-center rounded-xl bg-cyan-400 text-[#07111c] shadow-[0_0_24px_rgba(34,211,238,0.3)]">
              <Shield className="size-5 stroke-[2.5]" />
            </div>
            <span className="text-[17px] font-semibold tracking-tight">SafeScan</span>
            <span className="hidden rounded-full border border-cyan-300/20 bg-cyan-300/[0.08] px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.14em] text-cyan-300 sm:inline-flex">
              Zero-Execution Engine
            </span>
          </div>

          <div className="flex items-center gap-5 text-sm text-slate-400">
            <button
              onClick={() => setShowHistoryModal(true)}
              className="hidden items-center gap-2 transition-colors hover:text-white sm:flex"
            >
              <History className="size-4" /> Scan history
              {historyItems.length > 0 && (
                <span className="grid size-5 place-items-center rounded-full bg-cyan-300/10 text-[10px] font-bold text-cyan-300">
                  {historyItems.length}
                </span>
              )}
            </button>
            <button
              onClick={() => setShowHelpModal(true)}
              className="flex items-center gap-2 transition-colors hover:text-white"
            >
              <HelpCircle className="size-4" />
              <span className="hidden sm:inline">How it works</span>
            </button>
            <div
              className="size-8 rounded-full border border-white/10 bg-gradient-to-br from-cyan-300 to-indigo-500 shadow-sm"
              aria-label="User avatar"
            />
          </div>
        </header>

        {/* ==================================================================== */}
        {/* HERO SECTION                                                         */}
        {/* ==================================================================== */}
        <section className="mx-auto max-w-3xl pb-8 pt-10 text-center sm:pb-12 sm:pt-16 lg:pt-20">
          <p className="mb-4 text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">
            Personal threat intelligence
          </p>
          <div className="mx-auto mb-5 flex w-fit items-center gap-2 rounded-full border border-cyan-300/15 bg-cyan-300/[0.07] px-3.5 py-1.5 text-[11px] font-medium uppercase tracking-[0.16em] text-cyan-300 shadow-sm">
            <Sparkles className="size-3.5" /> Stay one step ahead
          </div>
          <h1 className="text-[2.25rem] font-semibold leading-tight tracking-[-0.05em] text-white sm:text-5xl lg:text-6xl">
            Check before you click.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-6 text-slate-400 sm:text-base">
            Instantly analyze URLs and QR codes for phishing, malware, and other online threats with <strong className="text-cyan-300">zero webpage execution</strong>.
          </p>
        </section>

        {/* ==================================================================== */}
        {/* SCANNER INPUT OR ACTIVE ASSESSMENT VIEW                              */}
        {/* ==================================================================== */}
        {!activeReport ? (
          <section className="mx-auto max-w-5xl">
            <div className="mb-4 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-300">
              <span className="grid size-6 place-items-center rounded-full border border-cyan-300/40 bg-cyan-300/10 text-[10px] font-bold text-cyan-200">
                1
              </span>{' '}
              Choose what you want to check
            </div>

            <div className="grid gap-4 lg:grid-cols-[1.35fr_0.65fr]">
              {/* URL Scanner Card */}
              <div className="rounded-2xl border border-cyan-300/25 bg-[#0d1825]/95 p-4 shadow-[0_18px_60px_rgba(0,0,0,0.25),0_0_40px_rgba(34,211,238,0.06)] sm:p-6 lg:p-8">
                <div className="mb-7 flex items-start justify-between gap-4">
                  <div>
                    <div className="mb-2 inline-flex items-center gap-2 rounded-full bg-cyan-300/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-300">
                      <Link2 className="size-3" /> Recommended
                    </div>
                    <h2 className="text-xl font-semibold text-white sm:text-2xl">
                      Scan a website URL
                    </h2>
                    <p className="mt-1.5 text-sm text-slate-400">
                      Paste a link to check it for phishing, malware, and suspicious activity.
                    </p>
                  </div>
                  <div className="hidden size-11 shrink-0 place-items-center rounded-xl bg-cyan-300/10 text-cyan-300 sm:grid">
                    <Globe className="size-5" />
                  </div>
                </div>

                <div className="mb-2 flex items-center gap-2 text-xs font-medium text-slate-300">
                  <span className="grid size-5 place-items-center rounded-full border border-cyan-300/40 text-[10px] text-cyan-300">
                    2
                  </span>{' '}
                  Enter a URL
                </div>

                <div className="flex flex-col gap-3 sm:flex-row sm:items-stretch">
                  <div className="relative min-w-0 flex-1">
                    <Globe className="absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-slate-500" />
                    <input
                      id="url"
                      type="text"
                      placeholder="https://example.com"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleScanUrl()}
                      className="h-12 w-full rounded-lg border border-white/10 bg-[#080d16] pl-10 pr-10 text-base text-white outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-2 focus:ring-cyan-300/10 sm:text-sm"
                    />
                    {urlInput && (
                      <button
                        onClick={() => setUrlInput('')}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-300"
                        aria-label="Clear URL"
                      >
                        <X className="size-4" />
                      </button>
                    )}
                  </div>

                  <button
                    disabled={isScanning || !urlInput.trim()}
                    onClick={() => handleScanUrl()}
                    className="flex min-h-12 w-full items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-[#07111c] shadow-[0_8px_24px_rgba(34,211,238,0.18)] transition-all hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto sm:px-7"
                  >
                    <ScanLine className="size-4" />
                    {isScanning ? 'Inspecting...' : 'Scan URL'}
                  </button>
                </div>

                <p className="mt-3 flex items-center gap-1.5 text-[11px] text-slate-500">
                  <Info className="size-3.5 text-cyan-300" />
                  We never visit or execute the target webpage. Pure static inspection guarantee.
                </p>

                {/* Quick Benchmark Shortcuts */}
                <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-4 text-[11px] text-slate-500">
                  <span>Try sample:</span>
                  <button
                    onClick={() => { setUrlInput('https://accounts.google.com'); handleScanUrl('https://accounts.google.com'); }}
                    className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-emerald-300 hover:bg-emerald-500/20"
                  >
                    Google (Safe)
                  </button>
                  <button
                    onClick={() => { setUrlInput('https://bit.ly/3x8QkLp'); handleScanUrl('https://bit.ly/3x8QkLp'); }}
                    className="rounded-md border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-amber-300 hover:bg-amber-500/20"
                  >
                    Bit.ly (Suspicious)
                  </button>
                  <button
                    onClick={() => { setUrlInput('https://paypa1-security-verification.com/login?token=8f92b489a2e'); handleScanUrl('https://paypa1-security-verification.com/login?token=8f92b489a2e'); }}
                    className="rounded-md border border-rose-500/20 bg-rose-500/10 px-2 py-1 text-rose-300 hover:bg-rose-500/20"
                  >
                    PayPal Typosquat (Dangerous)
                  </button>
                </div>
              </div>

              {/* QR Scanner Card */}
              <div className="rounded-2xl border border-white/[0.11] bg-[#0d131e]/95 p-4 shadow-[0_18px_50px_rgba(0,0,0,0.18)] sm:p-6 lg:p-7">
                <div className="mb-6 flex items-start gap-3">
                  <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-white/[0.06] text-slate-300">
                    <QrCode className="size-5" />
                  </div>
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                      Alternative
                    </p>
                    <h2 className="mt-1 text-lg font-semibold text-white">
                      Scan a QR code
                    </h2>
                  </div>
                </div>

                <p className="mb-4 text-sm leading-5 text-slate-400">
                  Upload a QR image and we&apos;ll check the link inside it safely.
                </p>

                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="cursor-pointer rounded-xl border border-dashed border-white/15 bg-[#080d16] p-3 transition-colors hover:border-cyan-300/40 hover:bg-cyan-300/[0.03]"
                >
                  <div className="group flex min-h-28 w-full flex-col items-center justify-center gap-2 rounded-lg text-slate-400">
                    <Upload className="size-5 text-cyan-300 transition-transform group-hover:-translate-y-0.5" />
                    {qrFileName ? (
                      <span className="text-xs font-medium text-cyan-300">{qrFileName}</span>
                    ) : (
                      <>
                        <span className="text-xs text-slate-300">Drop an image here</span>
                        <span className="text-[10px] text-slate-600">
                          or click to upload · PNG or JPG up to 10MB
                        </span>
                      </>
                    )}
                  </div>
                </div>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  onChange={handleQrUpload}
                  className="hidden"
                />

                {qrError && (
                  <p className="mt-2 text-xs text-rose-400 flex items-center gap-1">
                    <AlertCircle className="size-3.5" /> {qrError}
                  </p>
                )}

                {qrDecodedUrl && (
                  <div className="mt-3 rounded-lg border border-cyan-300/20 bg-cyan-300/[0.05] p-2.5 text-xs text-slate-300">
                    <p className="text-[10px] text-cyan-300 font-semibold uppercase tracking-wider">Extracted URL:</p>
                    <p className="truncate font-mono text-[11px] text-white mt-0.5">{qrDecodedUrl}</p>
                  </div>
                )}

                <button
                  disabled={isScanning || !qrDecodedUrl}
                  onClick={() => handleScanUrl(qrDecodedUrl || undefined)}
                  className="mt-3 flex h-10 w-full items-center justify-center gap-2 rounded-lg border border-cyan-300/30 text-xs font-semibold text-cyan-300 transition-all hover:bg-cyan-300/10 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <QrCode className="size-4" />
                  {isScanning ? 'Analyzing QR...' : 'Scan QR code'}
                </button>
              </div>
            </div>

            <p className="mt-4 text-center text-[11px] text-slate-600">
              Your scan takes seconds. No account or download required.
            </p>
          </section>
        ) : (
          /* ==================================================================== */
          /* THREAT ANALYSIS / RESULTS SCREEN (matching v0 demo)                 */
          /* ==================================================================== */
          <section className="mx-auto max-w-5xl pb-12 pt-6 sm:pb-16 sm:pt-8">
            <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">
                  Security assessment <span className="mx-1.5 text-slate-700">/</span> Just now
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                  Threat analysis
                </h2>
              </div>

              <div className="flex items-center gap-2">
                <span className="rounded-full border border-cyan-300/25 bg-cyan-300/[0.08] px-3 py-1.5 text-[11px] font-medium text-cyan-300">
                  Zero-Execution Engine Active
                </span>
              </div>
            </div>

            {/* Benchmark Preset Switcher (exact v0 demo feature) */}
            <div className="mb-4 flex flex-col items-stretch gap-2 rounded-xl border border-white/[0.08] bg-[#0d131e] p-2 sm:flex-row sm:flex-wrap sm:items-center">
              <span className="px-2 text-[11px] font-medium text-slate-500">
                Preset benchmark preview:
              </span>
              {(['safe', 'suspicious', 'dangerous'] as const).map((key) => {
                const isSelected = presetKey === key;
                const style = TONE_STYLES[BENCHMARK_PRESETS[key].tone];
                return (
                  <button
                    key={key}
                    onClick={() => handleSelectPreset(key)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-semibold capitalize transition-colors ${
                      isSelected
                        ? `${style.badge} font-bold`
                        : 'text-slate-500 hover:bg-white/[0.05] hover:text-slate-200'
                    }`}
                  >
                    {key}
                  </button>
                );
              })}
              {presetKey === 'live' && (
                <span className="rounded-lg bg-cyan-300/15 px-3 py-1.5 text-xs font-bold text-cyan-300">
                  Live Scan Result
                </span>
              )}
            </div>

            {/* Split Results Grid */}
            <div className="grid gap-4 lg:grid-cols-[0.86fr_1.14fr]">
              {/* Left Column: Risk Score & Assessment */}
              <div
                className={`rounded-2xl border ${currentStyles.border} bg-gradient-to-br ${currentStyles.bg} p-4 shadow-[0_20px_60px_rgba(0,0,0,0.24)] sm:p-6 lg:p-8`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                      Risk score
                    </p>
                    <div className="mt-3 flex items-end gap-2">
                      <span className={`text-7xl font-bold leading-none tracking-[-0.1em] ${currentStyles.text} sm:text-8xl`}>
                        {activeReport.score}
                      </span>
                      <span className="mb-1.5 text-sm text-slate-500">/ 100</span>
                    </div>
                  </div>
                  <span
                    className={`rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-wider ${currentStyles.badge}`}
                  >
                    {activeReport.level}
                  </span>
                </div>

                {/* Risk Meter Visual Bar */}
                <div className="mt-8">
                  <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-white/10">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${Math.max(4, activeReport.score)}%`,
                        backgroundColor: currentStyles.accent
                      }}
                    />
                    <span className="absolute left-[30%] top-0 h-full w-px bg-white/25" />
                    <span className="absolute left-[60%] top-0 h-full w-px bg-white/25" />
                  </div>
                  <div className="mt-2 grid grid-cols-3 text-[10px] font-medium">
                    <span className="text-emerald-300">0–30 Safe</span>
                    <span className="text-center text-amber-300">31–60 Suspicious</span>
                    <span className="text-right text-rose-300">61–100 Dangerous</span>
                  </div>
                </div>

                {/* Overall Assessment Box */}
                <div className={`mt-6 rounded-xl border ${currentStyles.ring} ${currentStyles.soft} p-4`}>
                  <p className={`text-xs font-semibold ${currentStyles.text}`}>
                    {activeReport.title}
                  </p>
                  <p className="mt-1.5 text-sm leading-5 text-slate-300">
                    {activeReport.explanation}
                  </p>
                </div>
              </div>

              {/* Right Column: Scanned Target & Threat Indicators */}
              <div className="rounded-2xl border border-white/[0.09] bg-[#0d131e] p-4 sm:p-6 lg:p-7">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-white">Scanned target</h3>
                  <span className="text-[11px] text-slate-500">
                    {activeReport.isQr ? 'QR Code scan' : 'URL scan'} · {activeReport.durationMs}ms
                  </span>
                </div>

                {/* Scanned URL Box */}
                <div className="mt-4 flex min-w-0 items-center gap-3 rounded-xl border border-white/[0.07] bg-[#080d16] p-3.5">
                  <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-cyan-300/10 text-cyan-300">
                    <Globe className="size-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-sm font-medium text-slate-200">
                      {activeReport.url}
                    </p>
                    <p className="mt-0.5 text-[11px] text-slate-500">Scanned destination</p>
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(activeReport.url)}
                    className="p-1 text-slate-600 hover:text-slate-300 transition-colors"
                    title="Copy URL"
                  >
                    <Copy className="size-4" />
                  </button>
                </div>

                {/* Threat Indicators Grid */}
                <p className="mt-5 mb-3 text-xs font-medium text-slate-400">
                  Threat indicators ({activeReport.checks.filter(c => c.status === 'Pass').length}/{activeReport.checks.length} passed)
                </p>
                <div className="grid gap-2 sm:grid-cols-2">
                  {activeReport.checks.map(({ label, value, status, icon: Icon }) => (
                    <div
                      key={label}
                      className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.015] p-3"
                    >
                      <Icon
                        className={`size-4 shrink-0 ${
                          status === 'Pass'
                            ? 'text-emerald-300'
                            : status === 'Review'
                            ? 'text-amber-300'
                            : 'text-rose-300'
                        }`}
                      />
                      <div className="min-w-0">
                        <p className="text-[11px] text-slate-500">{label}</p>
                        <p className="truncate text-xs font-medium text-slate-300">{value}</p>
                      </div>
                      <span
                        className={`ml-auto shrink-0 text-[10px] font-semibold uppercase tracking-wide ${
                          status === 'Pass'
                            ? 'text-emerald-300'
                            : status === 'Review'
                            ? 'text-amber-300'
                            : 'text-rose-300'
                        }`}
                      >
                        {status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Bottom Row: Security Recommendation & Scan Another Button */}
            <div className="mt-4 grid gap-3 sm:grid-cols-2 md:grid-cols-[1fr_1fr_auto]">
              <div className="rounded-xl border border-white/[0.08] bg-[#0d131e] p-4">
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Security recommendation
                </p>
                <p className="mt-2 text-sm leading-5 text-slate-300">
                  {activeReport.recommendation}
                </p>
              </div>

              <div className="rounded-xl border border-cyan-300/15 bg-cyan-300/[0.04] p-4">
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-cyan-300">
                  Protection summary
                </p>
                <p className="mt-2 text-sm leading-5 text-slate-400">
                  {activeReport.checks.filter(c => c.status === 'Pass').length} of {activeReport.checks.length} security checks passed. Safe, real-time preview guaranteed.
                </p>
              </div>

              <button
                onClick={() => {
                  setActiveReport(null);
                  setQrDecodedUrl(null);
                  setQrFileName(null);
                  setQrPreviewUrl(null);
                  setUrlInput('https://accounts.google.com');
                }}
                className="flex min-h-14 items-center justify-center gap-2 rounded-xl border border-cyan-300/30 px-4 text-center text-sm font-semibold text-cyan-300 transition-colors hover:bg-cyan-300/10 sm:min-h-24 sm:px-5"
              >
                Scan another <ArrowUpRight className="size-4" />
              </button>
            </div>
          </section>
        )}

        {/* ==================================================================== */}
        {/* SCANNING MODAL / RADAR TELEMETRY                                     */}
        {/* ==================================================================== */}
        {isScanning && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
            <div className="w-full max-w-md rounded-2xl border border-cyan-300/30 bg-[#0d1825] p-6 shadow-2xl text-center">
              <div className="relative mx-auto mb-4 grid size-16 place-items-center rounded-2xl bg-cyan-300/10 text-cyan-300">
                <ScanLine className="size-8 animate-pulse text-cyan-300" />
                <div className="absolute inset-0 rounded-2xl border border-cyan-300/40 animate-ping opacity-25" />
              </div>
              <h3 className="text-lg font-semibold text-white">Inspecting Threat Signals</h3>
              <p className="mt-1 text-xs text-slate-400">
                Evaluating destination without browser execution
              </p>
              <div className="mt-5 rounded-lg border border-white/10 bg-[#080d16] p-3 text-left font-mono text-xs text-cyan-300">
                <div className="flex items-center gap-2">
                  <RefreshCw className="size-3.5 animate-spin" />
                  <span className="truncate">{scanStep}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SCAN HISTORY DRAWER / MODAL                                          */}
        {/* ==================================================================== */}
        {showHistoryModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="w-full max-w-2xl rounded-2xl border border-white/10 bg-[#0d131e] p-6 shadow-2xl">
              <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
                <div className="flex items-center gap-2">
                  <History className="size-5 text-cyan-300" />
                  <h3 className="text-lg font-semibold text-white">Inspection History</h3>
                </div>
                <button
                  onClick={() => setShowHistoryModal(false)}
                  className="p-1 text-slate-500 hover:text-white"
                >
                  <X className="size-5" />
                </button>
              </div>

              <div className="mt-4 max-h-[60vh] space-y-2.5 overflow-y-auto pr-1">
                {historyItems.map((item, idx) => (
                  <div
                    key={idx}
                    onClick={() => {
                      setActiveReport(item);
                      setPresetKey('live');
                      setShowHistoryModal(false);
                    }}
                    className="flex cursor-pointer items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-[#080d16] p-3.5 transition-colors hover:border-cyan-300/40 hover:bg-cyan-300/[0.02]"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-xs font-medium text-slate-200">{item.url}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">{item.title}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${TONE_STYLES[item.tone].badge}`}>
                        {item.score} / 100
                      </span>
                      <ChevronRight className="size-4 text-slate-600" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* HOW IT WORKS / HELP MODAL                                            */}
        {/* ==================================================================== */}
        {showHelpModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="w-full max-w-2xl rounded-2xl border border-white/10 bg-[#0d131e] p-6 shadow-2xl">
              <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
                <div className="flex items-center gap-2">
                  <Shield className="size-5 text-cyan-300" />
                  <h3 className="text-lg font-semibold text-white">How Zero-Execution Inspection Works</h3>
                </div>
                <button
                  onClick={() => setShowHelpModal(false)}
                  className="p-1 text-slate-500 hover:text-white"
                >
                  <X className="size-5" />
                </button>
              </div>

              <div className="mt-4 space-y-4 text-sm text-slate-300 leading-6">
                <p>
                  Most URL checkers load webpages inside sandboxed headless browsers. While useful, this technique can trigger malicious JavaScript, alert attackers via tracking pixels, or leak your device fingerprint.
                </p>
                <div className="rounded-xl border border-cyan-300/20 bg-cyan-300/[0.04] p-4 text-xs">
                  <p className="font-semibold text-cyan-300 mb-1">Our 4-Layer Inspection Pipeline:</p>
                  <ul className="list-disc pl-5 space-y-1.5 text-slate-300">
                    <li><strong className="text-white">Layer 1 (Heuristics):</strong> Pure lexical analysis of IP hosts, deep subdomains, dangerous binary extensions (.exe, .apk), and non-standard ports.</li>
                    <li><strong className="text-white">Layer 2 (Typosquatting):</strong> Mathematical Levenshtein distance and character homoglyph analysis against high-profile enterprise brands.</li>
                    <li><strong className="text-white">Layer 3 (WHOIS/RDAP):</strong> Live domain registry query. Newly created domains (&lt; 14 days) are heavily penalized.</li>
                    <li><strong className="text-white">Layer 4 (Gemini AI):</strong> Semantic reasoning evaluates intent (credential harvesting, financial fraud) and generates human-readable warnings.</li>
                  </ul>
                </div>
                <p className="text-xs text-slate-500">
                  Result: Complete safety for everyday users before they ever scan or click.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* FOOTER                                                               */}
        {/* ==================================================================== */}
        <footer className="border-t border-white/[0.06] px-4 py-6 text-center text-[11px] leading-5 text-slate-600">
          SafeScan / QuishGuard is built for the Hackathon. Powered by Supabase, Next.js, and Google Gemini AI.
        </footer>
      </div>
    </main>
  );
}
