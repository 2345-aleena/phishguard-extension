/**
 * Heuristic phishing detection rules.
 * Each rule returns { triggered: bool, weight: number, reason: string }
 * Weighted sum -> risk score (0-100). This runs instantly, no network call.
 */

const KNOWN_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
  "hbl", "meezanbank", "ubl", "linkedin", "github"
];

const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
];

function isIPAddress(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function hasPunycode(hostname) {
  return hostname.includes("xn--");
}

function countSubdomains(hostname) {
  return hostname.split(".").length - 2;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array(b.length + 1).fill(0).map((_, j) => (i === 0 ? j : 0))
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

function brandImpersonation(hostname) {
  const domain = hostname.replace(/^www\./, "").split(".")[0];
  for (const brand of KNOWN_BRANDS) {
    if (domain === brand) return null; // legit exact match
    const dist = levenshtein(domain, brand);
    if (dist > 0 && dist <= 2 && domain.length > 3) {
      return brand; // close typo-squat, e.g. "paypa1" vs "paypal"
    }
  }
  return null;
}

export function analyzeUrl(rawUrl) {
  const rules = [];
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { score: 0, rules: [], verdict: "unknown" };
  }

  const hostname = url.hostname.toLowerCase();

  if (isIPAddress(hostname)) {
    rules.push({ triggered: true, weight: 25, reason: "URL uses a raw IP address instead of a domain name" });
  }

  if (url.protocol !== "https:") {
    rules.push({ triggered: true, weight: 15, reason: "Connection is not encrypted (no HTTPS)" });
  }

  if (hasPunycode(hostname)) {
    rules.push({ triggered: true, weight: 30, reason: "Domain uses punycode — possible homograph/lookalike attack" });
  }

  if (countSubdomains(hostname) >= 3) {
    rules.push({ triggered: true, weight: 15, reason: "Excessive number of subdomains" });
  }

  if (rawUrl.includes("@")) {
    rules.push({ triggered: true, weight: 20, reason: "URL contains '@', which can hide the real destination" });
  }

  if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
    rules.push({ triggered: true, weight: 15, reason: "Domain uses a TLD commonly abused for phishing" });
  }

  if (URL_SHORTENERS.some(s => hostname === s)) {
    rules.push({ triggered: true, weight: 10, reason: "URL is shortened — real destination is hidden" });
  }

  const impersonated = brandImpersonation(hostname);
  if (impersonated) {
    rules.push({ triggered: true, weight: 40, reason: `Domain closely mimics "${impersonated}" — likely typo-squatting` });
  }

  if (hostname.length > 40) {
    rules.push({ triggered: true, weight: 10, reason: "Unusually long domain name" });
  }

  const score = Math.min(100, rules.reduce((sum, r) => sum + r.weight, 0));
  const verdict = score >= 50 ? "dangerous" : score >= 25 ? "suspicious" : "safe";

  return { score, rules, verdict, hostname };
}
