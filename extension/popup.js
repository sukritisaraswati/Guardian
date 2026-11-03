const $ = (id) => document.getElementById(id);

async function render() {
  const { enabled, stats = {}, keys = {} } = await chrome.storage.local.get(["enabled", "stats", "keys"]);
  const on = enabled !== false;
  $("toggle").checked = on;
  $("state").textContent = on ? "Protection ON" : "Protection OFF";
  $("state").classList.toggle("off", !on);
  $("hint").textContent = on ? "Checking every page you open." : "Guardian is not checking anything.";
  $("blocked").textContent = stats.blocked || 0;
  $("warned").textContent = stats.warned || 0;
  $("keywarn").hidden = !!(keys.virustotal && keys.safebrowsing);
}

$("toggle").addEventListener("change", (e) => chrome.storage.local.set({ enabled: e.target.checked }));
$("settings").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); window.close(); });
chrome.storage.onChanged.addListener(render);
render();
