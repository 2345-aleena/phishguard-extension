/**
 * Content script: runs in the page context.
 * Scans the DOM for login/credential forms and flags suspicious patterns,
 * then asks the background worker for the current risk verdict.
 */

function scanForCredentialForms() {
  const forms = document.querySelectorAll("form");
  let hasPasswordField = false;

  forms.forEach((form) => {
    const passwordInput = form.querySelector('input[type="password"]');
    if (passwordInput) hasPasswordField = true;
  });

  return {
    hasPasswordField,
    formCount: forms.length,
    isHttps: window.location.protocol === "https:",
  };
}

function injectWarningBanner(reasons, verdict, score) {
  if (document.getElementById("phishguard-banner")) return;

  const isDangerous = verdict === "dangerous";
  const bgColor = isDangerous ? "#dc2626" : "#d97706"; // red vs amber
  const darkColor = isDangerous ? "#7f1d1d" : "#78350f";
  const icon = isDangerous ? "🚫" : "⚠️";
  const label = isDangerous ? "Dangerous site detected" : "Suspicious site detected";

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.setAttribute("style", `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${bgColor}; color: white; font-family: system-ui, sans-serif;
    padding: 12px 20px; font-size: 14px; text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    animation: phishguard-slide-down 0.25s ease-out;
  `);
  banner.innerHTML = `
    <style>
      @keyframes phishguard-slide-down {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
      }
    </style>
    ${icon} <strong>PhishGuard — ${label} (risk score ${Math.round(score)}/100):</strong>
    ${reasons.slice(0, 2).join("; ")}.
    <button id="phishguard-dismiss" style="margin-left:12px; background:white; color:${bgColor}; border:none; padding:4px 10px; border-radius:4px; cursor:pointer; font-weight:600;">Dismiss</button>
    <button id="phishguard-leave" style="margin-left:6px; background:${darkColor}; color:white; border:1px solid white; padding:4px 10px; border-radius:4px; cursor:pointer;">Leave site</button>
  `;
  document.documentElement.prepend(banner);

  document.getElementById("phishguard-dismiss").onclick = () => banner.remove();
  document.getElementById("phishguard-leave").onclick = () => {
    window.location.href = "https://www.google.com";
  };
}

(async function main() {
  const pageInfo = scanForCredentialForms();

  chrome.runtime.sendMessage(
    { type: "ANALYZE_PAGE", url: window.location.href, pageInfo },
    (response) => {
      if (!response) return;
      const { verdict, rules, score } = response;
      // Show the banner immediately for ANY suspicious or dangerous verdict —
      // no click required, and no longer gated behind a password field.
      if (verdict === "dangerous" || verdict === "suspicious") {
        injectWarningBanner(rules.map((r) => r.reason), verdict, score);
      }
    }
  );
})();
