-- ==============================================================================
-- QUISHGUARD SEED DATA: TARGET BRANDS & BENCHMARK THREAT SCANS
-- ==============================================================================

-- 1. SEED TARGET BRANDS REPOSITORY (Commonly impersonated in Quishing attacks)
INSERT INTO public.target_brands (brand_name, category, official_domains, logo_icon_url) VALUES
('PayPal', 'Financial Services', ARRAY['paypal.com', 'paypal.me', 'paypal-community.com'], 'https://cdn.simpleicons.org/paypal'),
('Microsoft 365', 'Tech & Productivity', ARRAY['microsoft.com', 'office.com', 'live.com', 'microsoftonline.com', 'sharepoint.com'], 'https://cdn.simpleicons.org/microsoft'),
('Google', 'Tech & Productivity', ARRAY['google.com', 'gmail.com', 'docs.google.com', 'drive.google.com'], 'https://cdn.simpleicons.org/google'),
('Apple', 'Tech & Devices', ARRAY['apple.com', 'icloud.com'], 'https://cdn.simpleicons.org/apple'),
('Chase Bank', 'Banking & Finance', ARRAY['chase.com', 'jpmorganchase.com'], 'https://cdn.simpleicons.org/chase'),
('Bank of America', 'Banking & Finance', ARRAY['bankofamerica.com', 'bofa.com'], 'https://cdn.simpleicons.org/bankofamerica'),
('Amazon', 'E-Commerce', ARRAY['amazon.com', 'amazon.co.uk', 'aws.amazon.com'], 'https://cdn.simpleicons.org/amazon'),
('Netflix', 'Entertainment', ARRAY['netflix.com'], 'https://cdn.simpleicons.org/netflix'),
('DocuSign', 'Business & Legal', ARRAY['docusign.com', 'docusign.net'], 'https://cdn.simpleicons.org/docusign'),
('DHL Express', 'Logistics & Delivery', ARRAY['dhl.com', 'dhl.de'], 'https://cdn.simpleicons.org/dhl'),
('FedEx', 'Logistics & Delivery', ARRAY['fedex.com'], 'https://cdn.simpleicons.org/fedex'),
('Wells Fargo', 'Banking & Finance', ARRAY['wellsfargo.com'], 'https://cdn.simpleicons.org/wellsfargo')
ON CONFLICT (brand_name) DO NOTHING;

-- 2. SEED SAMPLE SCANS (Benchmarking the 4 Evaluation Layers)

-- [Sample 1: Verified Safe QR Code]
INSERT INTO public.scans (
    id,
    raw_payload,
    extracted_url,
    normalized_url,
    protocol,
    domain,
    path,
    is_shortened_url,
    status,
    risk_score,
    verdict,
    threat_title,
    summary,
    action_recommendation,
    threat_breakdown,
    whois_data,
    ai_analysis,
    zero_execution_guaranteed,
    scan_duration_ms
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ/edit?usp=sharing',
    'https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ/edit?usp=sharing',
    'docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ/edit',
    'https',
    'docs.google.com',
    '/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ/edit',
    false,
    'completed',
    4,
    'SAFE',
    'Verified Legitimate Domain',
    'The extracted URL belongs directly to the official Google Docs infrastructure with valid SSL/TLS certificates and mature domain history.',
    'Safe to proceed. No credential interception or deceptive redirects detected.',
    jsonb_build_object(
        'heuristics', jsonb_build_object('score', 0, 'max', 25, 'flags', ARRAY[]::text[]),
        'typosquatting', jsonb_build_object('score', 0, 'max', 25, 'target_brand', 'Google', 'is_official_match', true),
        'domain_age', jsonb_build_object('score', 0, 'max', 25, 'age_days', 9800, 'established', true),
        'ai_gemini', jsonb_build_object('score', 4, 'max', 25, 'verdict', 'SAFE', 'intent', 'Collaborative Document Sharing')
    ),
    jsonb_build_object(
        'registrar', 'MarkMonitor Inc.',
        'creation_date', '1997-09-15T00:00:00Z',
        'age_years', 29,
        'country', 'US'
    ),
    jsonb_build_object(
        'model', 'gemini-1.5-pro',
        'intent_classification', 'Productivity / Document Sharing',
        'threat_indicators', ARRAY[]::text[],
        'safety_advice', 'Standard Google Docs URL. Always verify permissions before requesting access.'
    ),
    true,
    312
) ON CONFLICT (id) DO NOTHING;

-- [Sample 2: Suspicious Shortened URL]
INSERT INTO public.scans (
    id,
    raw_payload,
    extracted_url,
    normalized_url,
    protocol,
    domain,
    path,
    is_shortened_url,
    resolved_redirect_url,
    status,
    risk_score,
    verdict,
    threat_title,
    summary,
    action_recommendation,
    threat_breakdown,
    whois_data,
    ai_analysis,
    zero_execution_guaranteed,
    scan_duration_ms
) VALUES (
    '00000000-0000-0000-0000-000000000002',
    'https://bit.ly/3x8QkLp',
    'https://bit.ly/3x8QkLp',
    'bit.ly/3x8QkLp',
    'https',
    'bit.ly',
    '/3x8QkLp',
    true,
    'https://discount-offer-promo77.online/claim',
    'completed',
    52,
    'SUSPICIOUS',
    'Obfuscated URL Shortener with Opaque Redirect',
    'This QR code uses a generic shortener (bit.ly) that conceals the true destination domain discount-offer-promo77.online.',
    'Exercise caution. Inspect the destination domain carefully before proceeding.',
    jsonb_build_object(
        'heuristics', jsonb_build_object('score', 15, 'max', 25, 'flags', ARRAY['url_shortener_detected', 'opaque_target_redirect']),
        'typosquatting', jsonb_build_object('score', 5, 'max', 25, 'brand_affinity', 'Low'),
        'domain_age', jsonb_build_object('score', 18, 'max', 25, 'target_domain_age_days', 42),
        'ai_gemini', jsonb_build_object('score', 14, 'max', 25, 'verdict', 'SUSPICIOUS', 'intent', 'Marketing / Lead Generation Scam')
    ),
    jsonb_build_object(
        'registrar', 'Hostinger Operations, UAB',
        'creation_date', '2026-08-20T10:14:00Z',
        'age_days', 44,
        'country', 'LT'
    ),
    jsonb_build_object(
        'model', 'gemini-1.5-pro',
        'intent_classification', 'Affiliate Marketing / Potential Low-Trust Landing Page',
        'threat_indicators', ARRAY['Concealed destination via URL shortening', 'Recently registered promotional TLD (.online)'],
        'safety_advice', 'Do not enter phone numbers, credit card details, or install APKs/profiles from this link.'
    ),
    true,
    485
) ON CONFLICT (id) DO NOTHING;

-- [Sample 3: Malicious Typosquatted Brand Quish Attack]
INSERT INTO public.scans (
    id,
    raw_payload,
    extracted_url,
    normalized_url,
    protocol,
    domain,
    path,
    is_shortened_url,
    status,
    risk_score,
    verdict,
    threat_title,
    summary,
    action_recommendation,
    threat_breakdown,
    whois_data,
    ai_analysis,
    zero_execution_guaranteed,
    scan_duration_ms
) VALUES (
    '00000000-0000-0000-0000-000000000003',
    'https://paypa1-security-verification.com/login?token=8f92b489a2e',
    'https://paypa1-security-verification.com/login?token=8f92b489a2e',
    'paypa1-security-verification.com/login',
    'https',
    'paypa1-security-verification.com',
    '/login',
    false,
    'completed',
    89,
    'MALICIOUS',
    'Quishing: High-Confidence PayPal Brand Impersonation',
    'Detected intentional typosquatting replacing "l" with "1" (paypa1). The domain was registered only 3 days ago specifically for credential theft.',
    'DANGER: Do not open or authenticate! This is an active credential harvesting campaign targeting PayPal users.',
    jsonb_build_object(
        'heuristics', jsonb_build_object('score', 22, 'max', 25, 'flags', ARRAY['typosquatting_detected', 'security_token_parameter', 'credential_path_detected']),
        'typosquatting', jsonb_build_object('score', 25, 'max', 25, 'target_brand', 'PayPal', 'levenshtein_distance', 1, 'similarity_score', 0.95),
        'domain_age', jsonb_build_object('score', 23, 'max', 25, 'age_days', 3, 'risk_multiplier', 'CRITICAL_NEW_DOMAIN'),
        'ai_gemini', jsonb_build_object('score', 19, 'max', 25, 'verdict', 'MALICIOUS', 'intent', 'Banking Credential Theft')
    ),
    jsonb_build_object(
        'registrar', 'NameCheap Inc.',
        'creation_date', '2026-09-30T14:22:11Z',
        'age_days', 3,
        'country', 'IS',
        'privacy_service', 'Withheld for Privacy Purposes'
    ),
    jsonb_build_object(
        'model', 'gemini-1.5-pro',
        'intent_classification', 'Phishing & Credential Interception',
        'threat_indicators', ARRAY['Levenshtein Distance 1 against official PayPal domain', 'Newly registered disposable domain (3 days old)', 'Obfuscated character substitution ("l" -> "1")', 'Simulated security verification pathway'],
        'safety_advice', 'This QR code is a textbook Quishing attack. Never enter login credentials or two-factor codes.'
    ),
    true,
    520
) ON CONFLICT (id) DO NOTHING;

-- [Sample 4: Critical Zero-Day Raw IP / Zero Execution Intercept]
INSERT INTO public.scans (
    id,
    raw_payload,
    extracted_url,
    normalized_url,
    protocol,
    domain,
    path,
    is_shortened_url,
    status,
    risk_score,
    verdict,
    threat_title,
    summary,
    action_recommendation,
    threat_breakdown,
    whois_data,
    ai_analysis,
    zero_execution_guaranteed,
    scan_duration_ms
) VALUES (
    '00000000-0000-0000-0000-000000000004',
    'http://194.135.33.201:8080/auth/microsoft-login-payload.exe',
    'http://194.135.33.201:8080/auth/microsoft-login-payload.exe',
    '194.135.33.201:8080/auth/microsoft-login-payload.exe',
    'http',
    '194.135.33.201',
    '/auth/microsoft-login-payload.exe',
    false,
    'completed',
    98,
    'CRITICAL',
    'Severe Zero-Day: Raw IP Host & Malware Dropper',
    'Zero-execution engine intercepted a raw IP address hosting an unencrypted binary payload (.exe) masquerading as Microsoft authentication.',
    'CRITICAL THREAT: Immediately discard this QR code. Visiting would trigger an automated drive-by malware download.',
    jsonb_build_object(
        'heuristics', jsonb_build_object('score', 25, 'max', 25, 'flags', ARRAY['raw_ip_address_host', 'non_standard_port_8080', 'unencrypted_http', 'dangerous_file_extension_exe']),
        'typosquatting', jsonb_build_object('score', 24, 'max', 25, 'target_brand', 'Microsoft 365', 'masqueraded_service', 'Active Directory Auth'),
        'domain_age', jsonb_build_object('score', 24, 'max', 25, 'asn', 'AS49505', 'reputation', 'BULK_MALWARE_HOST'),
        'ai_gemini', jsonb_build_object('score', 25, 'max', 25, 'verdict', 'CRITICAL', 'intent', 'Automated Malware Dropper / Ransomware')
    ),
    jsonb_build_object(
        'asn', 'AS49505',
        'isp', 'Unknown Offshore Hosting Provider',
        'country', 'RU',
        'is_vpn_or_bulletproof', true
    ),
    jsonb_build_object(
        'model', 'gemini-1.5-pro',
        'intent_classification', 'Drive-by Malware Delivery & Exploitation',
        'threat_indicators', ARRAY['Raw IPv4 destination without FQDN', 'Direct executable payload extension (.exe)', 'Non-standard port 8080 without TLS encryption', 'Falsified Microsoft authentication naming'],
        'safety_advice', 'Direct zero-day payload delivery. Under no circumstances should this URL be opened on any mobile or desktop device.'
    ),
    true,
    289
) ON CONFLICT (id) DO NOTHING;
