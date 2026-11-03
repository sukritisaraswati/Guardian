const NAMES = ["safebrowsing", "virustotal"];
const $ = (id) => document.getElementById(id);

function status(keys) {
  for (const n of NAMES) {
    const s = $("s-" + n);
    s.textContent = keys[n] ? "✓ saved" : "not set";
    s.className = "status " + (keys[n] ? "ok" : "no");
  }
}

async function load() {
  const { keys = {} } = await chrome.storage.local.get("keys");
  for (const n of NAMES) $(n).value = keys[n] || "";
  status(keys);
}

$("save").addEventListener("click", async () => {
  const keys = {};
  for (const n of NAMES) keys[n] = $(n).value.trim();
  await chrome.storage.local.set({ keys });
  status(keys);
  $("saved").textContent = "Saved";
  setTimeout(() => ($("saved").textContent = ""), 2000);
});

load();
