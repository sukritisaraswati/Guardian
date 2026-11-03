// The page a user sees instead of a site Guardian has not vouched for.
const target = new URLSearchParams(location.search).get("u") || "";
const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...kids) {
  const e = Object.assign(document.createElement(tag), props);
  for (const k of kids) e.append(k);
  return e;
}

function goBack() {
  if (history.length > 1) history.back();
  else chrome.tabs.update({ url: "chrome://newtab" });
}

function buttons() {
  const back = el("button", { className: "btn primary", textContent: "Go back", onclick: goBack });
  const cont = el("button", {
    className: "btn secondary", textContent: "Continue anyway",
    onclick: async () => {
      await chrome.runtime.sendMessage({ type: "proceed", url: target });
      location.replace(target);
    },
  });
  $("buttons").replaceChildren(back, cont);
}

function show(title, ...body) {
  $("title").textContent = title;
  $("body").replaceChildren(...body);
  buttons();
}

function notChecked(list) {
  if (!list.length) return null;
  const settings = el("a", { href: "#", textContent: "settings", onclick: (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); } });
  const online = list.filter((s) => s !== "PhishTank");
  const p = el("p", {}, el("b", { textContent: `Not checked: ${list.join(", ")}. ` }));
  if (online.length) {
    p.append("An API key may be missing (open Guardian ", settings, "), the service was too slow, or its rate limit was reached. ");
  }
  if (list.includes("PhishTank")) p.append("PhishTank's list is still downloading; try again in a minute.");
  return p;
}

async function main() {
  let u;
  try { u = new URL(target); } catch { return show("Invalid link", el("p", { textContent: "This link cannot be checked." })); }
  if (!/^https?:$/.test(u.protocol)) return show("Invalid link", el("p", { textContent: "Only web links are checked." }));
  $("url").textContent = target;

  const v = await chrome.runtime.sendMessage({ type: "check", url: target });
  if (!v || v.action === "error") {
    return show("Guardian could not check this link",
      el("p", { textContent: "Something went wrong while checking. You can go back or continue at your own risk." }));
  }
  if (v.action === "allow") return location.replace(target);

  const missing = notChecked(v.unavailable);
  if (v.action === "block") {
    show("Link is malicious",
      el("p", { className: "risk" }, el("b", { textContent: v.risk + "%" }), " chance of being malicious"),
      el("p", {}, `Flagged by ${v.sources.length} of 3 sources: `, el("b", { textContent: v.sources.join(", ") }), "."),
      ...(missing ? [missing] : []));
  } else {
    const found = v.checked.length ? ` and was not found in ${v.checked.join(" or ")}` : "";
    show("Alert: May be malicious",
      el("p", { textContent: `This site is not on Guardian's trusted list${found}. It may still be dangerous.` }),
      ...(missing ? [missing] : []));
  }
}

main();
