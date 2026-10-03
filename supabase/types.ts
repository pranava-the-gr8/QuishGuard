/**
 * QUISHGUARD: ZERO-EXECUTION QR & URL THREAT INSPECTION ENGINE
 * Type definitions matching the Supabase PostgreSQL Database Schema
 */

export type ScanVerdict = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL';
export type ScanStatus = 'pending' | 'analyzing' | 'completed' | 'failed';
export type ReportType = 'false_positive' | 'verified_phishing' | 'broken_qr' | 'other';

export interface ThreatBreakdown {
  heuristics: {
    score: number;
    max: number;
    flags: string[];
    details?: Record<string, any>;
  };
  typosquatting: {
    score: number;
    max: number;
    target_brand?: string;
    is_official_match?: boolean;
    levenshtein_distance?: number;
    similarity_score?: number;
    homoglyphs_detected?: string[];
  };
  domain_age: {
    score: number;
    max: number;
    age_days?: number;
    is_newly_registered?: boolean;
    risk_multiplier?: string;
    established?: boolean;
  };
  ai_gemini: {
    score: number;
    max: number;
    verdict: ScanVerdict;
    intent: string;
    reasoning?: string;
    threat_indicators?: string[];
    confidence?: number;
  };
}

export interface WhoisData {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  age_days?: number;
  age_years?: number;
  country?: string;
  privacy_service?: string;
  asn?: string;
  isp?: string;
  is_vpn_or_bulletproof?: boolean;
}

export interface AiAnalysis {
  model: string;
  intent_classification: string;
  threat_indicators: string[];
  safety_advice: string;
  evasion_techniques_detected?: string[];
  phishing_type?: 'Credential Harvesting' | 'Financial/Banking' | 'Brand Impersonation' | 'Drive-by Malware' | 'Tech Support Scam' | 'Benign';
}

export interface Scan {
  id: string;
  user_id?: string | null;
  session_id?: string | null;
  
  // Input Payload
  qr_image_path?: string | null;
  qr_image_url?: string | null;
  raw_payload: string;
  
  // URL Deconstruction
  extracted_url: string;
  normalized_url?: string | null;
  protocol?: string | null;
  domain: string;
  path?: string | null;
  query_params?: Record<string, any>;
  is_shortened_url: boolean;
  resolved_redirect_url?: string | null;
  
  // Inspection Status & Final Score
  status: ScanStatus;
  risk_score: number; // 0 to 100
  verdict: ScanVerdict;
  
  // Human Presentation
  threat_title?: string | null;
  summary?: string | null;
  action_recommendation?: string | null;
  
  // Multi-Layer Evaluations
  threat_breakdown: ThreatBreakdown;
  whois_data: WhoisData;
  ai_analysis: AiAnalysis;
  
  // Engine Guarantee
  zero_execution_guaranteed: boolean;
  scan_duration_ms?: number;
  client_ip_hash?: string;
  
  // Timestamps
  created_at: string;
  updated_at: string;
}

export interface Profile {
  id: string;
  email?: string | null;
  display_name?: string | null;
  avatar_url?: string | null;
  total_scans_count: number;
  threats_detected_count: number;
  created_at: string;
  updated_at: string;
}

export interface TargetBrand {
  id: number;
  brand_name: string;
  category: string;
  official_domains: string[];
  logo_icon_url?: string | null;
  created_at: string;
}

export interface DomainReputationCache {
  domain: string;
  domain_age_days?: number;
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  dns_records?: Record<string, any>;
  is_known_phishing: boolean;
  is_verified_safe: boolean;
  reputation_score?: number;
  cached_whois_data?: WhoisData;
  last_analyzed_at: string;
  expires_at: string;
}

export interface UserFeedbackReport {
  id: string;
  scan_id: string;
  user_id?: string | null;
  report_type: ReportType;
  feedback_notes?: string | null;
  reported_at: string;
}
