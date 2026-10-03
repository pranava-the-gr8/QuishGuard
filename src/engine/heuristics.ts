/**
 * LAYER 1: HEURISTIC & STRUCTURAL STATIC URL INSPECTOR
 * Pure static analysis with zero network execution.
 */

export interface HeuristicResult {
  score: number; // 0 - 25
  max: number;
  flags: string[];
  details: {
    isIpAddress: boolean;
    hasNonStandardPort: boolean;
    isSuspiciousTld: boolean;
    hasAtSymbol: boolean;
    subdomainCount: number;
    hasExcessiveSubdomains: boolean;
    hasDangerousExtension: boolean;
    isUnencryptedHttp: boolean;
    hasEncodedHexChars: boolean;
    isKnownShortener: boolean;
  };
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'online', 'loan', 'club', 'click', 'work', 'gq', 'cf', 'ml', 'ga', 
  'tk', 'country', 'stream', 'download', 'racing', 'win', 'bid', 'vip', 'cam'
]);

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 
  'adf.ly', 'bl.ink', 'tiny.cc', 'rb.gy', 'cutt.ly', 'shorturl.at'
]);

const DANGEROUS_EXTENSIONS = [
  '.exe', '.scr', '.vbs', '.bat', '.cmd', '.msi', '.apk', '.dmg', '.iso', 
  '.ps1', '.hta', '.jar', '.dll', '.zip', '.tar.gz'
];

export function inspectUrlHeuristics(rawUrl: string): HeuristicResult {
  let score = 0;
  const flags: string[] = [];

  let parsed: URL;
  try {
    // Prefix http if missing for standard URL parsing
    const urlToParse = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    parsed = new URL(urlToParse);
  } catch {
    return {
      score: 25,
      max: 25,
      flags: ['malformed_url_syntax'],
      details: {
        isIpAddress: false,
        hasNonStandardPort: false,
        isSuspiciousTld: false,
        hasAtSymbol: false,
        subdomainCount: 0,
        hasExcessiveSubdomains: false,
        hasDangerousExtension: false,
        isUnencryptedHttp: false,
        hasEncodedHexChars: false,
        isKnownShortener: false,
      }
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname.toLowerCase();

  // 1. Check if Host is an IP Address (High Risk Indicator)
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  const isIpAddress = isIpv4 || isIpv6;
  if (isIpAddress) {
    score += 15;
    flags.push('raw_ip_address_host');
  }

  // 2. Check Unencrypted HTTP
  const isUnencryptedHttp = parsed.protocol === 'http:';
  if (isUnencryptedHttp && !isIpAddress) {
    score += 5;
    flags.push('unencrypted_http');
  }

  // 3. Non-standard port (e.g., :8080, :8888, :8443)
  const hasNonStandardPort = !!(parsed.port && parsed.port !== '80' && parsed.port !== '443');
  if (hasNonStandardPort) {
    score += 8;
    flags.push(`non_standard_port_${parsed.port}`);
  }

  // 4. '@' symbol in URL (Often used to disguise credentials and fake destinations)
  const hasAtSymbol = rawUrl.includes('@');
  if (hasAtSymbol) {
    score += 12;
    flags.push('at_symbol_credential_trick');
  }

  // 5. TLD Analysis
  const hostParts = hostname.split('.');
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  if (isSuspiciousTld) {
    score += 7;
    flags.push(`suspicious_tld_${tld}`);
  }

  // 6. Subdomain Depth (e.g. login.verification.account.paypal.evil-site.com)
  const subdomainCount = Math.max(0, hostParts.length - 2);
  const hasExcessiveSubdomains = subdomainCount >= 3;
  if (hasExcessiveSubdomains) {
    score += 8;
    flags.push(`deep_subdomains_depth_${subdomainCount}`);
  }

  // 7. Dangerous File Download Extension
  const hasDangerousExtension = DANGEROUS_EXTENSIONS.some(ext => path.endsWith(ext));
  if (hasDangerousExtension) {
    score += 15;
    flags.push('executable_binary_path');
  }

  // 8. Hex/Percent-encoding obfuscation in hostname or path
  const hasEncodedHexChars = /%[0-9a-fA-F]{2}/.test(hostname) || (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length > 3;
  if (hasEncodedHexChars) {
    score += 6;
    flags.push('heavy_character_encoding');
  }

  // 9. Known URL Shortener
  const isKnownShortener = KNOWN_SHORTENERS.has(hostname);
  if (isKnownShortener) {
    score += 6;
    flags.push('url_shortener_detected');
  }

  return {
    score: Math.min(25, score),
    max: 25,
    flags,
    details: {
      isIpAddress,
      hasNonStandardPort,
      isSuspiciousTld,
      hasAtSymbol,
      subdomainCount,
      hasExcessiveSubdomains,
      hasDangerousExtension,
      isUnencryptedHttp,
      hasEncodedHexChars,
      isKnownShortener,
    }
  };
}
