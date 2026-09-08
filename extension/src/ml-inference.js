/**
 * Evaluates the trained Random Forest phishing classifier using plain
 * JavaScript -- no ONNX, no WASM, no offscreen document required.
 *
 * Why this instead of ONNX Runtime Web: MV3 service workers block the
 * dynamic import() that ONNX Runtime Web's WASM loader depends on, and
 * moving that to an offscreen document still hit unresolved import
 * failures in testing. A plain-JS decision-tree walk needs none of
 * that -- it's just object property lookups -- so it runs directly in
 * the background service worker, fast and reliably.
 *
 * The model file (model/forest_model.json) is exported from the same
 * trained sklearn RandomForestClassifier (see ml/export_forest_json.py)
 * -- same training pipeline, comparison across 6 algorithms, cross-
 * validation and hyperparameter tuning -- just a different, simpler
 * runtime format for the browser.
 */

let forestModel = null;

async function loadForestModel() {
  if (forestModel) return forestModel;
  const url = chrome.runtime.getURL("model/forest_model.json");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load forest_model.json: ${res.status}`);
  forestModel = await res.json();
  return forestModel;
}

function walkTree(node, features) {
  if (node.l === 1) return node.p; // leaf: probability of phishing
  const value = features[node.f];
  return value <= node.t ? walkTree(node.L, features) : walkTree(node.R, features);
}

function shannonEntropy(s) {
  if (!s) return 0;
  const counts = {};
  for (const c of s) counts[c] = (counts[c] || 0) + 1;
  const len = s.length;
  return -Object.values(counts).reduce(
    (sum, c) => sum + (c / len) * Math.log2(c / len), 0
  );
}

const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".loan"];

// Must stay in sync with ml/train_model.py's extract_features() /
// FEATURE_NAMES ordering.
function extractFeatures(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return new Array(16).fill(0);
  }
  const hostname = url.hostname;
  const path = url.pathname || "";
  const full = rawUrl;
  const digitCount = (full.match(/\d/g) || []).length;
  const specialChars = [...full].filter(c => !/[a-zA-Z0-9:/.]/.test(c)).length;
  const vowels = (hostname.toLowerCase().match(/[aeiou]/g) || []).length;
  const consonants = (hostname.toLowerCase().match(/[a-z]/g) || []).length - vowels;

  return [
    full.length,
    hostname.length,
    (full.match(/\./g) || []).length,
    (full.match(/-/g) || []).length,
    (full.match(/@/g) || []).length,
    /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    hostname.split(".").length - 2,
    (full.match(/[?&=]/g) || []).length,
    hostname.includes("xn--") ? 1 : 0,
    digitCount / Math.max(full.length, 1),
    path.length,
    (path.match(/\//g) || []).length,
    shannonEntropy(hostname),
    specialChars / Math.max(full.length, 1),
    SUSPICIOUS_TLDS.some(t => hostname.endsWith(t)) ? 1 : 0,
    vowels / Math.max(consonants, 1),
  ];
}

export async function getMlRiskScore(rawUrl) {
  try {
    const model = await loadForestModel();
    const features = extractFeatures(rawUrl);
    const probs = model.trees.map(tree => walkTree(tree, features));
    const avgProb = probs.reduce((a, b) => a + b, 0) / probs.length;
    return avgProb * 100; // 0-100 risk score, same scale as heuristics
  } catch (err) {
    console.warn("PhishGuard: ML inference unavailable, falling back to heuristics only.", err);
    return null;
  }
}
