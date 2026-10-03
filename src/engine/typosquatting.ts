/**
 * LAYER 2: TYPOSQUATTING & BRAND SPOOFING INSPECTION ENGINE
 * Detects deceptive domain imitations, homoglyphs, and sub-domain brand masking.
 */

export interface TyposquattingResult {
  score: number; // 0 - 25
  max: number;
  matchedBrand?: string;
  isOfficialDomain: boolean;
  levenshteinDistance?: number;
  similarityScore?: number;
  homoglyphSubstitutions: string[];
  spoofingType?: 'exact_official' | 'subdomain_spoof' | 'levenshtein_typo' | 'homoglyph_substitution' | 'keyword_stuffing' | 'clean';
  explanation?: string;
}

export interface BrandTarget {
  name: string;
  officialDomains: string[];
  keywords: string[];
}

export const DEFAULT_HIGH_VALUE_BRANDS: BrandTarget[] = [
  { name: 'PayPal', officialDomains: ['paypal.com', 'paypal.me'], keywords: ['paypal', 'paypa1', 'pay-pal'] },
  { name: 'Microsoft', officialDomains: ['microsoft.com', 'office.com', 'live.com', 'sharepoint.com'], keywords: ['microsoft', 'office365', 'micros0ft', 'msauth'] },
  { name: 'Google', officialDomains: ['google.com', 'gmail.com', 'drive.google.com'], keywords: ['google', 'gmail', 'g00gle'] },
  { name: 'Apple', officialDomains: ['apple.com', 'icloud.com'], keywords: ['apple', 'icloud', 'app1e'] },
  { name: 'Bank of America', officialDomains: ['bankofamerica.com', 'bofa.com'], keywords: ['bankofamerica', 'bofa'] },
  { name: 'Chase Bank', officialDomains: ['chase.com'], keywords: ['chasebank', 'chase-online'] },
  { name: 'Amazon', officialDomains: ['amazon.com', 'aws.amazon.com'], keywords: ['amazon', 'amaz0n'] },
  { name: 'Netflix', officialDomains: ['netflix.com'], keywords: ['netflix', 'netf1ix'] },
  { name: 'DocuSign', officialDomains: ['docusign.com', 'docusign.net'], keywords: ['docusign', 'docus1gn'] },
  { name: 'DHL', officialDomains: ['dhl.com'], keywords: ['dhl-express', 'dhl-tracking'] },
  { name: 'FedEx', officialDomains: ['fedex.com'], keywords: ['fedex-delivery', 'fedex-tracking'] }
];

// Calculate Levenshtein Distance
export function computeLevenshtein(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// Homoglyph mappings
const HOMOGLYPH_MAP: Record<string, string[]> = {
  'o': ['0', 'o', 'ο', 'о'],
  'l': ['1', 'i', 'l', '|', 'ı'],
  'i': ['1', 'l', '!', 'í', 'ï'],
  'e': ['3', 'e', 'е'],
  'a': ['4', '@', 'a', 'а'],
  's': ['5', '$', 's'],
  'w': ['vv', 'w']
};

export function inspectTyposquatting(
  domain: string,
  targetBrands: BrandTarget[] = DEFAULT_HIGH_VALUE_BRANDS
): TyposquattingResult {
  const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
  const domainParts = cleanDomain.split('.');
  const secondLevelDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : cleanDomain;

  // 1. Check if domain exactly matches an official brand domain
  for (const brand of targetBrands) {
    if (brand.officialDomains.some(d => cleanDomain === d || cleanDomain.endsWith('.' + d))) {
      return {
        score: 0,
        max: 25,
        matchedBrand: brand.name,
        isOfficialDomain: true,
        homoglyphSubstitutions: [],
        spoofingType: 'exact_official',
        explanation: `Verified official domain for ${brand.name}`
      };
    }
  }

  // 2. Check for Subdomain Brand Masking (e.g., paypal.com.attacker.com)
  for (const brand of targetBrands) {
    for (const keyword of brand.keywords) {
      if (cleanDomain.includes(keyword) && !brand.officialDomains.some(d => cleanDomain.endsWith(d))) {
        // Keyword appears, but it's not the official root domain!
        const isSubdomain = domainParts.slice(0, -2).some(sub => sub.includes(keyword));
        if (isSubdomain) {
          return {
            score: 25,
            max: 25,
            matchedBrand: brand.name,
            isOfficialDomain: false,
            homoglyphSubstitutions: [],
            spoofingType: 'subdomain_spoof',
            explanation: `Brand name "${brand.name}" masked inside subdomain while pointing to an untrusted root domain (${domainParts.slice(-2).join('.')}).`
          };
        }
      }
    }
  }

  // 3. Check for Levenshtein Distance & Homoglyph Substitutions against official brand names
  for (const brand of targetBrands) {
    for (const official of brand.officialDomains) {
      const officialSld = official.split('.')[0];
      const dist = computeLevenshtein(secondLevelDomain, officialSld);
      const similarity = 1 - dist / Math.max(secondLevelDomain.length, officialSld.length);

      // Check homoglyphs
      const detectedSubstitutions: string[] = [];
      for (const [char, replacements] of Object.entries(HOMOGLYPH_MAP)) {
        if (officialSld.includes(char)) {
          for (const rep of replacements) {
            if (rep !== char && secondLevelDomain.includes(rep)) {
              detectedSubstitutions.push(`'${char}' replaced by '${rep}'`);
            }
          }
        }
      }

      // Close typo (distance 1 or 2 with high similarity)
      if (dist === 1 || (dist === 2 && similarity >= 0.75) || detectedSubstitutions.length > 0) {
        const score = dist === 1 ? 25 : detectedSubstitutions.length > 0 ? 22 : 18;
        return {
          score,
          max: 25,
          matchedBrand: brand.name,
          isOfficialDomain: false,
          levenshteinDistance: dist,
          similarityScore: Math.round(similarity * 100) / 100,
          homoglyphSubstitutions: detectedSubstitutions,
          spoofingType: detectedSubstitutions.length > 0 ? 'homoglyph_substitution' : 'levenshtein_typo',
          explanation: `High-risk typosquatting detected against ${brand.name} (SLD: "${secondLevelDomain}" vs Official: "${officialSld}").`
        };
      }
    }
  }

  return {
    score: 0,
    max: 25,
    isOfficialDomain: false,
    homoglyphSubstitutions: [],
    spoofingType: 'clean',
    explanation: 'No known high-value brand typosquatting detected.'
  };
}
