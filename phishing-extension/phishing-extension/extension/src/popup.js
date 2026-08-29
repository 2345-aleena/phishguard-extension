async function render() {
  const { stats, lastResult } = await chrome.storage.local.get(["stats", "lastResult"]);

  document.getElementById("sitesChecked").textContent = stats?.sitesChecked || 0;
  document.getElementById("threatsBlocked").textContent = stats?.threatsBlocked || 0;

  const statusEl = document.getElementById("status");
  const reasonsEl = document.getElementById("reasons");

  if (!lastResult) {
    statusEl.textContent = "No data yet — browse to a page.";
    return;
  }

  statusEl.className = `status ${lastResult.verdict}`;
  statusEl.textContent =
    lastResult.verdict === "dangerous"
      ? `⚠️ Dangerous (score ${Math.round(lastResult.score)}/100)`
      : lastResult.verdict === "suspicious"
      ? `⚠ Suspicious (score ${Math.round(lastResult.score)}/100)`
      : `✅ Looks safe (score ${Math.round(lastResult.score)}/100)`;

  reasonsEl.innerHTML = "";
  (lastResult.rules || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r.reason;
    reasonsEl.appendChild(li);
  });
}

render();
