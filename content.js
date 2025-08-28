
const lolbinPatterns = [
  /p[\W_]*o[\W_]*w[\W_]*e[\W_]*r[\W_]*s[\W_]*h[\W_]*e[\W_]*l[\W_]*l/i,
  /c[\W_]*m[\W_]*d(\.exe)?/i,
  /w[\W_]*s[\W_]*c[\W_]*r[\W_]*i[\W_]*p[\W_]*t/i,
  /c[\W_]*s[\W_]*c[\W_]*r[\W_]*i[\W_]*p[\W_]*t/i,
  /m[\W_]*s[\W_]*h[\W_]*t[\W_]*a/i,
  /r[\W_]*u[\W_]*n[\W_]*d[\W_]*l[\W_]*l/i,
  /c[\W_]*u[\W_]*r[\W_]*l(\.exe)?/i,
  /c[\W_]*u[\W_]*r[\W_]*l[\W_]?/i,      
  /m[\W_]*s[\W_]*i[\W_]*e[\W_]*x[\W_]*e[\W_]*c(\.exe)?/i  
];

const commandLineSwitches = [
  /-nop\s+/i,              
  /-w\s+hidden\s+/i,       
  /-encodedcommand\s+/i,
  /-enc\s+/i,   
  /-exec\s+bypass\s+/i,    
  /-noni/i,             
  /\/c\s+/i,            
  /-noexit\s+/i,
  /Invoke-Expression/i,
  /iex\s+/i,
  /Invoke-WebRequest/i,
  /iwr\s+/i,
  /Start-Process/i,
  /-enc\s+/i,
  /\/i\s+http/i,
  /-Ss\s+/,
  /base64\s+(-d|--decode)/i
  
];

const Blogs = [
  /iocs\s+/i,
  /yara\s+/i,
  /mitre\s+/i,
  /Indicators of Compromise/i
]


const clipboardPatterns = [
 /navigator\.clipboard\.writeText/i,
  /document\.execCommand\s*\(\s*['"]copy['"]\s*\)/i,
  /copyTextSilently\s*\(/i,
  /autoCopy/i
];


function containsLOLBin(text) {
  return lolbinPatterns.some(regex => regex.test(text));
}

function containsClipboardAbuse(text) {
  return clipboardPatterns.some(regex => regex.test(text));
}

function containsCommandLineSwitch(text) {
  return commandLineSwitches.some(regex => regex.test(text));
}

function filterBlogs(text) {
  return Blogs.some(regex => regex.test(text));
}



function blockPage(reason) {
  document.documentElement.innerHTML = `
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');

      body {
        margin: 0;
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: black;
        color: #e63946;
        font-family: 'Roboto', sans-serif;
        text-align: center;
        overflow: hidden;
      }

      /* Starfield (still background) */
      .stars {
        position: absolute;
        width: 100%;
        height: 100%;
        background: black url('https://www.transparenttextures.com/patterns/stardust.png') repeat;
        z-index: 0;
        opacity: 0.8;
      }

      /* Vader's ship - recolored inline SVG */
      .vader-ship {
        position: absolute;
        top: 15%;
        left: 65%;
        width: 260px;
        opacity: 0.5;
        z-index: 1;
        animation: drift 50s ease-in-out infinite;
        filter: drop-shadow(0 0 20px rgba(255, 0, 0, 0.6));
      }

      @keyframes drift {
        0%   { transform: translate(0, 0) scale(1); }
        50%  { transform: translate(-40px, 25px) scale(1.05); }
        100% { transform: translate(0, 0) scale(1); }
      }

      /* Block message container */
      .container {
        position: relative;
        z-index: 2;
        max-width: 600px;
        padding: 40px;
        background: rgba(0, 0, 0, 0.75);
        border-radius: 12px;
        box-shadow: 0 0 30px rgba(255, 0, 0, 0.4);
      }

      h1 {
        font-size: 32px;
        font-weight: 700;
        margin-bottom: 20px;
        display: inline-block;
        position: relative;
      }

      /* Properly aligned lightsaber underline */
      h1::after {
        content: "";
        display: block;
        height: 4px;
        margin: 8px auto 0;
        background: #ff0000;
        width: 100%;
        box-shadow: 0 0 8px #ff0000, 0 0 16px #ff0000;
        animation: saber-shake 1s infinite;
      }

      p {
        font-size: 18px;
        margin-top: 10px;
        color: #f1f1f1;
      }

      @keyframes saber-shake {
        0%, 100% { transform: translateX(0); }
        20% { transform: translateX(-2px); }
        40% { transform: translateX(2px); }
        60% { transform: translateX(-1px); }
        80% { transform: translateX(1px); }
      }
    </style>

    <!-- Background layers -->
    <div class="stars"></div>

    <!-- Foreground block message -->
    <div class="container">
      <h1>⛔ SithScanner Blocked This Page</h1>
      <p>Reason: ${reason}</p>
    </div>
  `;
}

// --- Whitelist ---
function isWhitelisted(host) {
  return new Promise(resolve => {
    chrome.storage.local.get("whitelist", data => {
      const list = data.whitelist || [
        "google.com",
        "microsoft.com",
        "github.com",
        "stackoverflow.com",
        "mozilla.org"
      ];
      resolve(list.some(domain => host.endsWith(domain)));
    });
  });
}


async function scanPage(doc = document) {
  let foundLOLBin = false;
  let foundClipboard = false;
  let foundCommandLineSwitch = false;
  let foundBlogs = false;

  
  doc.querySelectorAll("script:not([src])").forEach(script => {
    if (containsLOLBin(script.textContent)) foundLOLBin = true;
    if (containsClipboardAbuse(script.textContent)) foundClipboard = true;
    if (containsCommandLineSwitch(script.textContent)) foundCommandLineSwitch = true;
    if (filterBlogs(script.textContent)) foundBlogs = true;
  });

  
  const externalScripts = Array.from(doc.querySelectorAll("script[src]"));
  for (let script of externalScripts) {
    try {
      const res = await fetch(script.src);
      const code = await res.text();
      if (containsLOLBin(code)) foundLOLBin = true;
      if (containsClipboardAbuse(code)) foundClipboard = true;
      if (containsCommandLineSwitch(code)) foundCommandLineSwitch = true;
      if (filterBlogs(code)) foundBlogs = true;
    } catch (e) {}
  }

  
  const rawHTML = document.documentElement.outerHTML;
  if (containsClipboardAbuse(rawHTML)) foundClipboard = true;
  if (containsLOLBin(rawHTML)) foundLOLBin = true;
  if (containsCommandLineSwitch(rawHTML)) foundCommandLineSwitch = true;
  if (filterBlogs(rawHTML)) foundBlogs = true;

  
  if (foundLOLBin && foundClipboard && foundCommandLineSwitch && !foundBlogs ) {
  blockPage("ClickFix detected!\n Please report this site to your organization's Security Operations Center (SOC)");
}
}


function scanIframesAndEmbeds() {
  document.querySelectorAll("iframe, embed, object").forEach(frame => {
    try {
      const doc = frame.contentDocument || frame.contentWindow.document;
      if (doc) scanPage(doc);
    } catch (e) {}
  });
}


function watchForScripts() {
  const observer = new MutationObserver(mutations => {
    mutations.forEach(m => {
      m.addedNodes.forEach(node => {
        if (node.tagName === "SCRIPT") {
          const text = node.textContent || "";
          if (containsLOLBin(text)) var hasLOL = true;
          if (containsClipboardAbuse(text)) var hasClip = true;
          if (containsCommandLineSwitch(text)) var hasSwitch = true;
          if (hasLOL && hasClip && hasSwitch) {
            blockPage("ClickFix detected!\n Please report this site to your organization's Security Operations Center (SOC)");
          }
        }
      });
    });
  });
  observer.observe(document, { childList: true, subtree: true });
}


(async () => {
  const host = window.location.hostname;

  if (await isWhitelisted(host)) {
    console.log("[SithScanner] Skipping scan — whitelisted domain:", host);
    return;
  }

  await scanPage();
  scanIframesAndEmbeds();
  watchForScripts();
})();