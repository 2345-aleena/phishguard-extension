/**
 * Runs the phishing-URL classifier fully on-device using ONNX Runtime Web.
 * No URL or browsing data is ever sent to a server for this step.
 *
 * Model: trained offline (see /ml/train_model.py) on lexical URL features,
 * exported to ONNX, and bundled with the extension in /extension/model/.
 *
 * NOTE: ONNX Runtime Web is loaded lazily (not as a top-level static import)
 * because Chrome cannot resolve bare package names like "onnxruntime-web"
 * without a bundler (Vite/webpack). A static top-level import here would
 * crash the whole service worker on load. Once you run `npm run build`
 * (see extension/package.json), a bundled copy will exist at
 * extension/vendor/ort.min.js and loadModel() below will use it.
 * Until then, getMlRiskScore() safely falls back to 0 (heuristics-only mode).
 */

let session = null;
let ort = null;

async function loadModel() {
  if (session) return session;

  // Only attempt to load ONNX Runtime if it's been bundled (see note above).
  if (typeof self.ort === "undefined") {
    throw new Error(
      "onnxruntime-web not bundled yet — run `npm install && npm run build` in extension/"
    );
  }
  ort = self.ort;
  session = await ort.InferenceSession.create(
    chrome.runtime.getURL("model/phishing_url_model.onnx")
  );
  return session;
}

/**
 * Extract the same lexical features used at training time.
 * MUST stay in sync with ml/train_model.py's feature extraction.
 */
function extractFeatures(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return new Float32Array(10).fill(0);
  }
  const hostname = url.hostname;
  const full = rawUrl;

  return Float32Array.from([
    full.length,                                   // total URL length
    hostname.length,                                // hostname length
    (full.match(/\./g) || []).length,               // dot count
    (full.match(/-/g) || []).length,                // hyphen count
    (full.match(/@/g) || []).length,                // @ count
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0, // is IP
    url.protocol === "https:" ? 1 : 0,              // is HTTPS
    hostname.split(".").length - 2,                 // subdomain count
    (full.match(/[?&=]/g) || []).length,             // query param signal
    hostname.includes("xn--") ? 1 : 0,               // punycode flag
  ]);
}

export async function getMlRiskScore(rawUrl) {
  try {
    const sess = await loadModel();
    const features = extractFeatures(rawUrl);
    const tensor = new ort.Tensor("float32", features, [1, features.length]);
    const output = await sess.run({ input: tensor });
    const [prob] = output.output.data; // probability of "phishing" class, 0-1
    return prob * 100;
  } catch (err) {
    console.warn("PhishGuard: ML inference unavailable, falling back to heuristics only.", err);
    return null; // null = "no ML opinion", NOT "0 = definitely safe"
  }
}
