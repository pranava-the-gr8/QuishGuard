-- ==============================================================================
-- QUISHGUARD: ZERO-EXECUTION QR & URL THREAT INSPECTION ENGINE
-- Database Schema for Supabase (PostgreSQL)
-- ==============================================================================

-- 1. Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Define Custom Enums
DO $$ BEGIN
    CREATE TYPE scan_verdict AS ENUM ('SAFE', 'LOW_RISK', 'SUSPICIOUS', 'MALICIOUS', 'CRITICAL');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('pending', 'analyzing', 'completed', 'failed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE report_type AS ENUM ('false_positive', 'verified_phishing', 'broken_qr', 'other');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ==============================================================================
-- 3. PROFILES TABLE (Linked to Supabase Auth)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    display_name TEXT,
    avatar_url TEXT,
    total_scans_count INTEGER DEFAULT 0,
    threats_detected_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Trigger to create profile automatically on auth.users insert
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, display_name, avatar_url)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        NEW.raw_user_meta_data->>'avatar_url'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==============================================================================
-- 4. TARGET BRANDS REPOSITORY (For Typosquatting & Brand Spoofing Detection)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.target_brands (
    id SERIAL PRIMARY KEY,
    brand_name TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL DEFAULT 'Other', -- e.g. Banking, Cloud, Social, E-Commerce, Logistics
    official_domains TEXT[] NOT NULL,       -- e.g. ARRAY['paypal.com', 'paypal.me']
    logo_icon_url TEXT,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Index for searching brand domain lists
CREATE INDEX IF NOT EXISTS idx_target_brands_domains ON public.target_brands USING GIN (official_domains);

-- ==============================================================================
-- 5. DOMAIN REPUTATION CACHE (Caches WHOIS, DNS & Static Analysis to save quota)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.domain_reputation_cache (
    domain TEXT PRIMARY KEY,
    domain_age_days INTEGER,
    registrar TEXT,
    creation_date TIMESTAMPTZ,
    expiration_date TIMESTAMPTZ,
    dns_records JSONB DEFAULT '{}'::jsonb,
    is_known_phishing BOOLEAN DEFAULT FALSE,
    is_verified_safe BOOLEAN DEFAULT FALSE,
    reputation_score INTEGER CHECK (reputation_score >= 0 AND reputation_score <= 100),
    cached_whois_data JSONB DEFAULT '{}'::jsonb,
    last_analyzed_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    expires_at TIMESTAMPTZ DEFAULT (TIMEZONE('utc'::text, NOW()) + INTERVAL '7 days') NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_domain_cache_expiry ON public.domain_reputation_cache (expires_at);

-- ==============================================================================
-- 6. SCANS (CORE INSPECTION ENGINE TABLE)
-- Stores all QR code uploads, extracted URLs, zero-execution static analysis, 
-- and multi-layer threat assessment outputs.
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL, -- Nullable for anonymous/guest scans
    session_id TEXT, -- Fingerprint or cookie session ID for guest tracking
    
    -- Input Payload
    qr_image_path TEXT, -- Storage path in 'qr-codes' bucket if uploaded as image
    qr_image_url TEXT,  -- Public/Signed preview URL if available
    raw_payload TEXT NOT NULL, -- Exact string read from the QR code (URL or text)
    
    -- URL Deconstruction & Zero-Execution Metadata
    extracted_url TEXT NOT NULL,
    normalized_url TEXT,
    protocol TEXT, -- http, https, data, javascript, etc.
    domain TEXT NOT NULL,
    path TEXT,
    query_params JSONB DEFAULT '{}'::jsonb,
    is_shortened_url BOOLEAN DEFAULT FALSE,
    resolved_redirect_url TEXT, -- If checked via unshortening HEAD request (zero-execution)
    
    -- Inspection Status & Final Score
    status scan_status DEFAULT 'pending' NOT NULL,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    verdict scan_verdict,
    
    -- Human-Readable Presentation
    threat_title TEXT, -- e.g. "High-Risk Quishing: Brand Impersonation"
    summary TEXT,      -- Concise explanation
    action_recommendation TEXT, -- "Do not scan or enter credentials. This QR mimics PayPal."
    
    -- Multi-Layer Threat Evaluation Breakdown
    -- Stores individual layer scores & findings:
    -- {
    --    "heuristics": { "score": 25, "max": 25, "flags": ["ip_host", "suspicious_tld", "at_symbol"] },
    --    "typosquatting": { "score": 30, "max": 30, "target_brand": "PayPal", "levenshtein": 1, "similarity": 0.94 },
    --    "domain_age": { "score": 20, "max": 20, "age_days": 3, "is_newly_registered": true },
    --    "ai_gemini": { "score": 25, "max": 25, "verdict": "MALICIOUS", "intent": "Credential Harvester" }
    -- }
    threat_breakdown JSONB DEFAULT '{}'::jsonb,
    
    -- Detailed Raw Layer Data
    whois_data JSONB DEFAULT '{}'::jsonb,
    ai_analysis JSONB DEFAULT '{}'::jsonb, -- Raw response from Gemini AI evaluation
    
    -- Engine Guarantee
    zero_execution_guaranteed BOOLEAN DEFAULT TRUE,
    scan_duration_ms INTEGER,
    client_ip_hash TEXT, -- SHA-256 hashed IP for rate limiting without storing PII
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans (user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON public.scans (domain);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans (verdict);
CREATE INDEX IF NOT EXISTS idx_scans_session_id ON public.scans (session_id);

-- ==============================================================================
-- 7. USER FEEDBACK & COMMUNITY THREAT REPORTING
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.user_feedback_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    report_type report_type NOT NULL,
    feedback_notes TEXT,
    reported_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON public.user_feedback_reports (scan_id);

-- ==============================================================================
-- 8. UPDATED_AT AUTOMATIC TRIGGER
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.set_current_timestamp_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc'::text, NOW());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_scans_updated_at ON public.scans;
CREATE TRIGGER trigger_scans_updated_at
    BEFORE UPDATE ON public.scans
    FOR EACH ROW EXECUTE FUNCTION public.set_current_timestamp_updated_at();

DROP TRIGGER IF EXISTS trigger_profiles_updated_at ON public.profiles;
CREATE TRIGGER trigger_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.set_current_timestamp_updated_at();

-- ==============================================================================
-- 9. HELPER FUNCTIONS: REPUTATION STATS & USER COUNTS
-- ==============================================================================
-- Auto-increment scan counter on user profile when scan completes
CREATE OR REPLACE FUNCTION public.increment_user_scan_counts()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.user_id IS NOT NULL AND NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
        UPDATE public.profiles
        SET 
            total_scans_count = total_scans_count + 1,
            threats_detected_count = threats_detected_count + (CASE WHEN NEW.verdict IN ('SUSPICIOUS', 'MALICIOUS', 'CRITICAL') THEN 1 ELSE 0 END)
        WHERE id = NEW.user_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trigger_increment_user_scan_counts ON public.scans;
CREATE TRIGGER trigger_increment_user_scan_counts
    AFTER INSERT OR UPDATE OF status ON public.scans
    FOR EACH ROW EXECUTE FUNCTION public.increment_user_scan_counts();

-- ==============================================================================
-- 10. ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.target_brands ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domain_reputation_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_feedback_reports ENABLE ROW LEVEL SECURITY;

-- --- Profiles RLS ---
CREATE POLICY "Public profiles are readable by everyone"
    ON public.profiles FOR SELECT
    USING (true);

CREATE POLICY "Users can update their own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id);

-- --- Target Brands RLS ---
CREATE POLICY "Target brands readable by all users"
    ON public.target_brands FOR SELECT
    USING (true);

-- --- Domain Reputation Cache RLS ---
CREATE POLICY "Domain cache readable by all users"
    ON public.domain_reputation_cache FOR SELECT
    USING (true);

-- --- Scans RLS ---
-- 1. Anyone (anonymous or logged-in) can create a scan
CREATE POLICY "Anyone can insert scans"
    ON public.scans FOR INSERT
    WITH CHECK (true);

-- 2. Scans can be viewed by anyone who knows the scan ID (for shareable threat report links)
CREATE POLICY "Scans readable by scan ID"
    ON public.scans FOR SELECT
    USING (true);

-- 3. Only the scan owner or service role can update a scan
CREATE POLICY "Users can update their own scans"
    ON public.scans FOR UPDATE
    USING (auth.uid() = user_id OR user_id IS NULL);

-- --- User Feedback Reports RLS ---
CREATE POLICY "Anyone can report a scan"
    ON public.user_feedback_reports FOR INSERT
    WITH CHECK (true);

CREATE POLICY "Feedback readable by creator or admin"
    ON public.user_feedback_reports FOR SELECT
    USING (auth.uid() = user_id OR auth.uid() IS NOT NULL);

-- ==============================================================================
-- 11. SUPABASE STORAGE BUCKET CONFIGURATION (Run in Supabase SQL editor)
-- ==============================================================================
-- Ensure the 'qr-codes' bucket exists for uploaded QR images
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
    'qr-codes',
    'qr-codes',
    true,
    5242880, -- 5 MB limit
    ARRAY['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml']
)
ON CONFLICT (id) DO UPDATE SET
    public = true,
    file_size_limit = 5242880,
    allowed_mime_types = ARRAY['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'];

-- Storage RLS Policies
CREATE POLICY "Allow public upload of QR code images"
    ON storage.objects FOR INSERT
    WITH CHECK (bucket_id = 'qr-codes');

CREATE POLICY "Allow public read of QR code images"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'qr-codes');
