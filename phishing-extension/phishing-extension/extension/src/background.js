import { analyzeUrl } from "./heuristics.js";
import { getMlRiskScore } from "./ml-inference.js";

// Simple in-memory + storage-backed stats for the popup dashboard
async function incrementStat(key) {
  const data = await chrome.storage.local.get(["stats"]);
  const stats = data.stats || { sitesChecked: 0, threatsBlocked: 0 };
  stats[key] = (stats[key] || 0) + 1;
  await chrome.storage.local.set({ stats });
}

async function checkSafeBrowsing(url) {
  // Placeholder: wire up your own Google Safe Browsing API v4 key here.
  // Left as a stub so the extension works fully offline out of the box.
  // const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {...})
  return { flagged: false };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_PAGE") {
    (async () => {
      const heuristicResult = analyzeUrl(message.url);
      const mlScore = await getMlRiskScore(message.url); // number 0-100, or null if ML not available yet
      const safeBrowsing = await checkSafeBrowsing(message.url);

      // Combine: if ML is available, blend heuristics (60%) + ML (40%).
      // If ML hasn't been set up yet (null), trust heuristics 100% —
      // never let a missing ML score silently drag a real risk score down.
      let combinedScore =
        mlScore === null
          ? heuristicResult.score
          : heuristicResult.score * 0.6 + mlScore * 0.4;
      if (safeBrowsing.flagged) combinedScore = 100;

      const verdict = combinedScore >= 50 ? "dangerous" : combinedScore >= 25 ? "suspicious" : "safe";

      await incrementStat("sitesChecked");
      if (verdict === "dangerous") await incrementStat("threatsBlocked");

      await chrome.storage.local.set({
        lastResult: { url: message.url, score: combinedScore, verdict, rules: heuristicResult.rules },
      });

      sendResponse({ verdict, score: combinedScore, rules: heuristicResult.rules });
    })();
    return true; // keep the message channel open for async sendResponse
  }
});
