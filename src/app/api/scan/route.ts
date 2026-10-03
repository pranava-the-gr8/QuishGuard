import { NextResponse } from 'next/server';
import { runZeroExecutionInspection } from '@/engine/evaluator';
import { saveScanToSupabase, getScanById } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const rawPayload = body.url || body.rawPayload;

    if (!rawPayload || typeof rawPayload !== 'string') {
      return NextResponse.json({ error: 'URL or QR payload is required' }, { status: 400 });
    }

    // Run the zero-execution inspection pipeline across all 4 layers
    const report = await runZeroExecutionInspection(rawPayload, {
      geminiApiKey: process.env.GEMINI_API_KEY
    });

    // Attempt to persist in Supabase if configured
    let savedScan = null;
    if (process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) {
      savedScan = await saveScanToSupabase({
        raw_payload: rawPayload,
        extracted_url: report.extractedUrl,
        normalized_url: report.normalizedUrl,
        protocol: report.protocol,
        domain: report.domain,
        path: report.path,
        query_params: report.queryParams,
        is_shortened_url: report.isShortenedUrl,
        status: 'completed',
        risk_score: report.riskScore,
        verdict: report.verdict,
        threat_title: report.threatTitle,
        summary: report.summary,
        action_recommendation: report.actionRecommendation,
        threat_breakdown: report.threatBreakdown as any,
        whois_data: report.whoisData,
        ai_analysis: report.aiAnalysis as any,
        zero_execution_guaranteed: true,
        scan_duration_ms: report.scanDurationMs
      });
    }

    return NextResponse.json({
      success: true,
      report,
      savedScanId: savedScan?.id || null
    });
  } catch (err: any) {
    console.error('Scan API error:', err);
    return NextResponse.json(
      { error: err.message || 'Inspection failed' },
      { status: 500 }
    );
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (id) {
    const scan = await getScanById(id);
    if (!scan) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }
    return NextResponse.json({ scan });
  }

  return NextResponse.json({
    status: 'online',
    engine: 'QuishGuard Zero-Execution Inspection Engine v1.0',
    layers: [
      'Layer 1: Heuristic & Structural Static Analysis (0-25 pts)',
      'Layer 2: Typosquatting & Brand Spoofing (0-25 pts)',
      'Layer 3: Domain Age & WHOIS/RDAP Intelligence (0-25 pts)',
      'Layer 4: Gemini AI Threat Analysis (0-25 pts)'
    ]
  });
}
