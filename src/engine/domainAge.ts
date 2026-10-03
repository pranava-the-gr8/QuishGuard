/**
 * LAYER 3: DOMAIN AGE & RDAP/WHOIS INTELLIGENCE ENGINE
 * Queries open RDAP standards (ICANN) with zero user-tracking and zero execution.
 */

export interface DomainAgeResult {
  score: number; // 0 - 25
  max: number;
  ageDays?: number;
  creationDate?: string;
  registrar?: string;
  isNewlyRegistered: boolean;
  isPrivacyProtected: boolean;
  flags: string[];
  explanation: string;
}

export async function inspectDomainAge(domain: string): Promise<DomainAgeResult> {
  const flags: string[] = [];
  const cleanDomain = domain.toLowerCase().replace(/^www\./, '');

  // Skip IP addresses
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(cleanDomain)) {
    return {
      score: 25,
      max: 25,
      isNewlyRegistered: true,
      isPrivacyProtected: false,
      flags: ['ip_address_no_whois'],
      explanation: 'Target is a raw IP address with no domain registry or legitimate WHOIS identity.'
    };
  }

  try {
    // Query public RDAP proxy (RFC 7482)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000); // 4s timeout

    const res = await fetch(`https://rdap.org/domain/${cleanDomain}`, {
      headers: { 'Accept': 'application/rdap+json' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!res.ok) {
      // 404 or lookup error
      return {
        score: 12,
        max: 25,
        isNewlyRegistered: false,
        isPrivacyProtected: false,
        flags: ['rdap_lookup_inconclusive'],
        explanation: 'Domain registration records could not be verified via public RDAP.'
      };
    }

    const data = await res.json();
    
    // Find registration event
    let registrationDateStr: string | undefined;
    if (Array.isArray(data.events)) {
      const regEvent = data.events.find((e: any) => e.eventAction === 'registration');
      if (regEvent && regEvent.eventDate) {
        registrationDateStr = regEvent.eventDate;
      }
    }

    // Find registrar name
    let registrarName: string | undefined;
    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find((e: any) => 
        Array.isArray(e.roles) && e.roles.includes('registrar')
      );
      if (registrarEntity?.vcardArray?.[1]) {
        const fn = registrarEntity.vcardArray[1].find((item: any) => item[0] === 'fn');
        registrarName = fn ? fn[3] : undefined;
      }
    }

    if (registrationDateStr) {
      const regDate = new Date(registrationDateStr);
      const now = new Date();
      const diffMs = now.getTime() - regDate.getTime();
      const ageDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

      let score = 0;
      let isNewlyRegistered = false;

      if (ageDays <= 7) {
        score = 25;
        isNewlyRegistered = true;
        flags.push('critical_newly_registered_under_7_days');
      } else if (ageDays <= 30) {
        score = 18;
        isNewlyRegistered = true;
        flags.push('newly_registered_under_30_days');
      } else if (ageDays <= 90) {
        score = 10;
        flags.push('young_domain_under_90_days');
      } else if (ageDays > 365) {
        score = 0;
      }

      return {
        score,
        max: 25,
        ageDays,
        creationDate: registrationDateStr,
        registrar: registrarName,
        isNewlyRegistered,
        isPrivacyProtected: false,
        flags,
        explanation: isNewlyRegistered
          ? `High-risk indicator: Domain was created only ${ageDays} day(s) ago (${regDate.toISOString().split('T')[0]}). Phishing campaigns frequently leverage disposable young domains.`
          : `Domain has an established history of ${Math.floor(ageDays / 365)} year(s) (${ageDays} days).`
      };
    }

    return {
      score: 8,
      max: 25,
      registrar: registrarName,
      isNewlyRegistered: false,
      isPrivacyProtected: false,
      flags: ['registration_date_omitted'],
      explanation: 'Domain active, but registration timestamp was withheld by the registrar.'
    };
  } catch (err) {
    return {
      score: 8,
      max: 25,
      isNewlyRegistered: false,
      isPrivacyProtected: false,
      flags: ['rdap_query_timeout'],
      explanation: 'RDAP query timed out. Static heuristic evaluation maintained.'
    };
  }
}
