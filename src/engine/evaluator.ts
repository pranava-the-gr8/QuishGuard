/**
 * ZERO-EXECUTION MULTI-LAYER INSPECTION ENGINE
 * Aggregates all 4 layers to produce a 0-100% Risk Score and human-readable warnings.
 */

import { inspectUrlHeuristics, type HeuristicResult } from './heuristics';
import { inspectTyposquatting, type TyposquattingResult, type BrandTarget } from './typosquatting';
import { inspectDomainAge, type DomainAgeResult } from './domainAge';
import { inspectWithGemini, type GeminiAiResult } from './geminiAi';
import type { ScanVerdict, ThreatBreakdown } from '../../supabase/types';

export interface InspectionReport {
  extractedUrl: string;
  normalizedUrl: string;
  domain: string;
  protocol: string;
  path: string;
  queryParams: Record<string, string>;
  isShortenedUrl: boolean;
  riskScore: number; // 0 - 100
  verdict: ScanVerdict;
  threatTitle: string;
  summary: string;
  actionRecommendation: string;
  threatBreakdown: ThreatBreakdown;
  whoisData: Record<string, any>;
  aiAnalysis: Record<string, any>;
  zeroExecutionGuaranteed: boolean;
  scanDurationMs: number;
}

export async function runZeroExecutionInspection(
  rawPayload: string,
  options?: {
    customBrands?: BrandTarget[];
    geminiApiKey?: string;
  }
): Promise<InspectionReport> {
  const startTime = Date.now();

  // 1. Safe extraction and parsing without execution
  let extractedUrl = rawPayload.trim();
  const hasScheme = /^https?:\/\//i.test(extractedUrl);
  const normalizedCandidate = hasScheme ? extractedUrl : `https://${extractedUrl}`;

  let parsed: URL;
  try {
    parsed = new URL(normalizedCandidate);
  } catch {
    // If not a standard URL, treat raw payload as plain text / dangerous payload
    return {
      extractedUrl,
      normalizedUrl: extractedUrl,
      domain: 'unknown',
      protocol: 'raw',
      path: '',
      queryParams: {},
      isShortenedUrl: false,
      riskScore: 75,
      verdict: 'SUSPICIOUS',
      threatTitle: 'Unstructured / Obfuscated QR Payload',
      summary: 'The scanned QR code contains raw text or executable script rather than a standard web URL.',
      actionRecommendation: 'Do not run or copy this string into terminal or command prompts.',
      threatBreakdown: {
        heuristics: { score: 25, max: 25, flags: ['non_url_raw_payload'] },
        typosquatting: { score: 0, max: 25 },
        domain_age: { score: 25, max: 25 },
        ai_gemini: { score: 25, max: 25, verdict: 'SUSPICIOUS', intent: 'Non-URL Payload' }
      },
      whoisData: {},
      aiAnalysis: {},
      zeroExecutionGuaranteed: true,
      scanDurationMs: Date.now() - startTime
    };
  }

  const domain = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.replace(':', '');
  const path = parsed.pathname;
  const queryParams: Record<string, string> = {};
  parsed.searchParams.forEach((val, key) => {
    queryParams[key] = val;
  });

  // 2. Concurrently run Layer 1, Layer 2, Layer 3
  const heuristicsPromise = Promise.resolve(inspectUrlHeuristics(extractedUrl));
  const typosquattingPromise = Promise.resolve(inspectTyposquatting(domain, options?.customBrands));
  const domainAgePromise = inspectDomainAge(domain);

  const [heuristics, typosquatting, domainAge] = await Promise.all([
    heuristicsPromise,
    typosquattingPromise,
    domainAgePromise
  ]);

  // 3. Run Layer 4: Gemini AI analysis with computed telemetry
  const geminiAi = await inspectWithGemini(
    extractedUrl,
    heuristics,
    typosquatting,
    domainAge,
    options?.geminiApiKey
  );

  // 4. Compute Composite 0-100% Risk Score
  let compositeScore = heuristics.score + typosquatting.score + domainAge.score + geminiAi.score;

  // Enforce zero false positives on verified official domains with mature WHOIS
  if (typosquatting.isOfficialDomain && (domainAge.ageDays ?? 0) > 365) {
    compositeScore = Math.min(15, compositeScore);
  }

  compositeScore = Math.min(100, Math.max(0, compositeScore));

  // Determine Final Verdict
  let finalVerdict: ScanVerdict = 'SAFE';
  if (compositeScore >= 90) {
    finalVerdict = 'CRITICAL';
  } else if (compositeScore >= 70) {
    finalVerdict = 'MALICIOUS';
  } else if (compositeScore >= 50) {
    finalVerdict = 'SUSPICIOUS';
  } else if (compositeScore >= 30) {
    finalVerdict = 'LOW_RISK';
  } else {
    finalVerdict = 'SAFE';
  }

  const threatBreakdown: ThreatBreakdown = {
    heuristics: {
      score: heuristics.score,
      max: 25,
      flags: heuristics.flags,
      details: heuristics.details
    },
    typosquatting: {
      score: typosquatting.score,
      max: 25,
      target_brand: typosquatting.matchedBrand,
      is_official_match: typosquatting.isOfficialDomain,
      levenshtein_distance: typosquatting.levenshteinDistance,
      similarity_score: typosquatting.similarityScore,
      homoglyphs_detected: typosquatting.homoglyphSubstitutions
    },
    domain_age: {
      score: domainAge.score,
      max: 25,
      age_days: domainAge.ageDays,
      is_newly_registered: domainAge.isNewlyRegistered
    },
    ai_gemini: {
      score: geminiAi.score,
      max: 25,
      verdict: geminiAi.verdict,
      intent: geminiAi.intent,
      threat_indicators: geminiAi.threatIndicators
    }
  };

  const scanDurationMs = Date.now() - startTime;

  return {
    extractedUrl,
    normalizedUrl: `${domain}${path}`,
    domain,
    protocol,
    path,
    queryParams,
    isShortenedUrl: heuristics.details.isKnownShortener,
    riskScore: compositeScore,
    verdict: finalVerdict,
    threatTitle: geminiAi.threatTitle,
    summary: geminiAi.summary,
    actionRecommendation: geminiAi.actionRecommendation,
    threatBreakdown,
    whoisData: {
      registrar: domainAge.registrar,
      creation_date: domainAge.creationDate,
      age_days: domainAge.ageDays,
      flags: domainAge.flags
    },
    aiAnalysis: {
      intent: geminiAi.intent,
      threat_indicators: geminiAi.threatIndicators,
      raw: geminiAi.rawAnalysis
    },
    zeroExecutionGuaranteed: true,
    scanDurationMs
  };
}
