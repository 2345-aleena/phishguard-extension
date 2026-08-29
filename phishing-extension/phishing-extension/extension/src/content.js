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

function injectWarningBanner(reasons) {
  if (document.getElementById("phishguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.setAttribute("style", `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #dc2626; color: white; font-family: system-ui, sans-serif;
    padding: 12px 20px; font-size: 14px; text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  `);
  banner.innerHTML = `
    ⚠️ <strong>PhishGuard Warning:</strong> This site shows signs of phishing
    (${reasons.slice(0, 2).join("; ")}).
    <button id="phishguard-dismiss" style="margin-left:12px; background:white; color:#dc2626; border:none; padding:4px 10px; border-radius:4px; cursor:pointer; font-weight:600;">Dismiss</button>
    <button id="phishguard-leave" style="margin-left:6px; background:#7f1d1d; color:white; border:1px solid white; padding:4px 10px; border-radius:4px; cursor:pointer;">Leave site</button>
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
      const { verdict, rules } = response;
      if (verdict === "dangerous" || (verdict === "suspicious" && pageInfo.hasPasswordField)) {
        injectWarningBanner(rules.map((r) => r.reason));
      }
    }
  );
})();
