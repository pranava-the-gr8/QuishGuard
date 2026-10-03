/**
 * LAYER 4: GEMINI AI THREAT & INTENT EVALUATION ENGINE
 * Translates multi-layer signals and contextual URL semantics into a clear, 
 * human-readable risk verdict for everyday users.
 */

import type { HeuristicResult } from './heuristics';
import type { TyposquattingResult } from './typosquatting';
import type { DomainAgeResult } from './domainAge';

export interface GeminiAiResult {
  score: number; // 0 - 25
  max: number;
  verdict: 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL';
  intent: string;
  threatTitle: string;
  summary: string;
  actionRecommendation: string;
  threatIndicators: string[];
  rawAnalysis?: any;
}

export async function inspectWithGemini(
  url: string,
  heuristics: HeuristicResult,
  typosquatting: TyposquattingResult,
  domainAge: DomainAgeResult,
  geminiApiKey?: string
): Promise<GeminiAiResult> {
  const apiKey = geminiApiKey || process.env.GEMINI_API_KEY;

  // Fallback Rule-Based Synthesis if API Key is not yet configured by user
  if (!apiKey) {
    const rawPoints = heuristics.score + typosquatting.score + domainAge.score;
    let verdict: 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL' = 'SAFE';
    let intent = 'Standard Web Navigation';
    let threatTitle = 'Verified Domain Activity';
    let summary = 'Static inspection shows no deceptive indicators or homoglyph patterns.';
    let actionRecommendation = 'Safe to browse. Standard caution applies.';

    if (rawPoints >= 55) {
      verdict = 'CRITICAL';
      intent = 'Active Quishing / Credential Interception Campaign';
      threatTitle = 'High-Threat Quishing / Exploit URL';
      summary = `The inspected QR code combines deceptive brand mimicry with high-risk structural anomalies.`;
      actionRecommendation = 'BLOCK IMMEDIATELY. Do not scan, enter passwords, or interact with this destination.';
    } else if (rawPoints >= 35) {
      verdict = 'MALICIOUS';
      intent = typosquatting.matchedBrand ? `Impersonation of ${typosquatting.matchedBrand}` : 'Suspicious Redirect / Phishing';
      threatTitle = 'Probable Phishing Campaign';
      summary = 'Multiple indicators point to an unverified or recently registered entity spoofing legitimate services.';
      actionRecommendation = 'Do not provide account credentials, payment information, or personal identifiers.';
    } else if (rawPoints >= 18) {
      verdict = 'SUSPICIOUS';
      intent = 'Obfuscated Destination / Low Trust';
      threatTitle = 'Suspicious QR Target';
      summary = 'Contains ambiguous parameters or shortened links that disguise the ultimate destination.';
      actionRecommendation = 'Proceed with heightened vigilance. Verify the web address carefully.';
    }

    return {
      score: Math.min(25, Math.round((rawPoints / 75) * 25)),
      max: 25,
      verdict,
      intent,
      threatTitle,
      summary,
      actionRecommendation,
      threatIndicators: [...heuristics.flags, ...domainAge.flags]
    };
  }

  // Live Gemini Analysis via Google GenAI REST API
  try {
    const prompt = `
You are QuishGuard's AI Threat Intelligence Analyst. Your task is to perform a zero-execution inspection on an extracted QR code URL and produce clear, human-readable safety advice for everyday non-technical users.

EVALUATED URL: "${url}"

PRE-COMPUTED SIGNALS:
1. Static Heuristics:
   - Score: ${heuristics.score}/25
   - Flags: ${JSON.stringify(heuristics.flags)}
2. Brand Spoofing / Typosquatting:
   - Score: ${typosquatting.score}/25
   - Matched Brand: ${typosquatting.matchedBrand || 'None'}
   - Spoofing Type: ${typosquatting.spoofingType}
   - Explanation: ${typosquatting.explanation}
3. Domain Registry & Age:
   - Score: ${domainAge.score}/25
   - Age in Days: ${domainAge.ageDays ?? 'Unknown'}
   - Registrar: ${domainAge.registrar || 'Unknown'}
   - Explanation: ${domainAge.explanation}

Provide a JSON response with this exact structure:
{
  "score": <number between 0 and 25 assessing AI threat confidence>,
  "verdict": <"SAFE" | "LOW_RISK" | "SUSPICIOUS" | "MALICIOUS" | "CRITICAL">,
  "intent": <short phrase, e.g. "Credential Harvesting", "Brand Impersonation", "Legitimate Document", "Malware Dropper">,
  "threatTitle": <catchy 3-6 word title for user display>,
  "summary": <concise 2-sentence explanation of what is dangerous or safe about this URL in plain English>,
  "actionRecommendation": <direct actionable instructions for the user, e.g. "Do not enter passwords...">,
  "threatIndicators": [<array of strings highlighting specific red flags>]
}
`;

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            responseMimeType: 'application/json',
            temperature: 0.2
          }
        })
      }
    );

    if (!response.ok) {
      throw new Error(`Gemini API returned status ${response.status}`);
    }

    const data = await response.json();
    const textContent = data.candidates?.[0]?.content?.parts?.[0]?.text;
    const parsed = JSON.parse(textContent);

    return {
      score: Math.min(25, Math.max(0, parsed.score || 0)),
      max: 25,
      verdict: parsed.verdict || 'SUSPICIOUS',
      intent: parsed.intent || 'Unverified Intent',
      threatTitle: parsed.threatTitle || 'URL Security Assessment',
      summary: parsed.summary || 'Inspected via static machine learning heuristics.',
      actionRecommendation: parsed.actionRecommendation || 'Check domain details carefully before continuing.',
      threatIndicators: Array.isArray(parsed.threatIndicators) ? parsed.threatIndicators : [],
      rawAnalysis: parsed
    };
  } catch (err: any) {
    console.error('Gemini threat analysis fallback:', err);
    return {
      score: 10,
      max: 25,
      verdict: 'SUSPICIOUS',
      intent: 'Automated Heuristic Evaluation',
      threatTitle: 'Automated Inspection Alert',
      summary: 'Heuristics triggered attention flags. Inspect URL structure before opening.',
      actionRecommendation: 'Verify the domain name and never enter sensitive information on unverified sites.',
      threatIndicators: [...heuristics.flags]
    };
  }
}
