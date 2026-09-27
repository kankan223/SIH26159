/* SecureMailScope — visual sweep: every page × both themes.
   Asserts per page: theme bg applied, no horizontal overflow, key element renders;
   captures full-page screenshots into shots/sweep/{dark,light}/. */
const { firefox } = require("playwright");
const fs = require("fs");

const BASE = "http://localhost:5000";
const results = [];
function check(name, cond, extra) {
  results.push({ name, ok: !!cond, extra: extra || "" });
  console.log((cond ? "  ✓ " : "  ✗ ") + name + (extra ? "  → " + extra : ""));
}

(async () => {
  fs.mkdirSync("shots/sweep/dark", { recursive: true });
  fs.mkdirSync("shots/sweep/light", { recursive: true });
  const browser = await firefox.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });

  const consoleErrors = [];
  page.on("console", m => { if (m.type() === "error") consoleErrors.push(m.text()); });
  page.on("pageerror", e => consoleErrors.push("PAGEERROR: " + e.message));

  await page.goto(BASE, { waitUntil: "networkidle" });
  // reset to known baseline (settings persist across restarts)
  await page.evaluate(() => fetch("/api/settings", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data_mode: "evaluation", retention: "session" }),
  }));
  await page.reload({ waitUntil: "networkidle" });

  // load an analysis so every page has content — via the app's own deep-link
  // (runs the pipeline client-side and ingests, like a real session)
  await page.goto(BASE + "/?autostart=starttls_downgrade", { waitUntil: "networkidle" });
  await page.waitForFunction(() =>
    document.querySelector("#gaugeScore")?.innerText.trim() !== "—", null, { timeout: 15000 });
  await page.waitForTimeout(900);   // let the gauge animation settle

  // generate the HTML report so the Reporting preview has content
  await page.evaluate(() => fetch("/api/report/html").then(r => r.text())
    .then(html => { document.querySelector("#repFrame").srcdoc = html; }));

  const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const overflow = () => page.evaluate(() =>
    document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
  const views = [
    ["dashboard", "#dashContent"],
    ["analysis", ".term-head"],
    ["sessions", "#sessRows"],
    ["remediation", "#remList"],
    ["report", "#repFrame"],
    ["settings", "#modeNote"],
  ];

  async function sweepTheme(theme) {
    console.log(`\n===== THEME: ${theme.toUpperCase()} =====`);
    // set theme through the UI toggle
    const current = await page.evaluate(() =>
      document.documentElement.getAttribute("data-theme") || "dark");
    if (current !== theme) await page.click("#themeToggle");
    check(`${theme}: bg applied`, await bg() ===
      (theme === "light" ? "rgb(244, 246, 250)" : "rgb(11, 15, 26)"), await bg());

    for (const [view, selector] of views) {
      await page.click(`nav button[data-view=${view}]`);
      await page.waitForTimeout(250);
      const el = page.locator(selector).first();
      check(`${theme}/${view}: renders`, await el.isVisible()
        || (view === "report" && await page.evaluate(() =>
          (document.querySelector("#repFrame").srcdoc || "").length > 2000)));
      check(`${theme}/${view}: no horizontal overflow`, !(await overflow()));
      await page.screenshot({ path: `shots/sweep/${theme}/${view}.png`, fullPage: true });
    }

    // overlays that need their own captures
    if (theme === "light") {
      await page.click("nav button[data-view=sessions]");
      await page.click('#sessRows tr[data-sid="SES-014"]');
      await page.waitForSelector("#drawerBack.open");
      check(`${theme}/session drawer: opens`, await page.locator("#drawer").isVisible());
      check(`${theme}/session drawer: content`, (await page.locator("#drawer").innerText()).includes("TLS 1.0"));
      await page.screenshot({ path: `shots/sweep/${theme}/drawer.png` });
      await page.keyboard.press("Escape");

      await page.click("nav button[data-view=findings]");
      await page.locator("#findRows tr.clickable").first().click();
      await page.waitForTimeout(150);
      check(`${theme}/findings detail: expands`, await page.locator('#findRows tr[id^="fd-"]').count() === 1);
      await page.screenshot({ path: `shots/sweep/${theme}/findings_detail.png`, fullPage: true });
    }

    // dashboard charts must be painted in this theme
    await page.click("nav button[data-view=dashboard]");
    const painted = await page.evaluate(() => {
      for (const id of ["chartProto", "chartTls", "chartCipher", "chartTrend", "gaugeCanvas"]) {
        const c = document.getElementById(id);
        const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
        let n = 0;
        for (let i = 3; i < d.length; i += 40) if (d[i] > 0) n++;
        if (n < 10) return false;
      }
      return true;
    });
    check(`${theme}/dashboard: all charts painted`, painted);
    await page.screenshot({ path: `shots/sweep/${theme}/dashboard_final.png`, fullPage: true });
  }

  await sweepTheme("dark");
  await sweepTheme("light");

  // leave the app in the demo-recommended state: dark theme
  const t = await page.evaluate(() => document.documentElement.getAttribute("data-theme") || "dark");
  if (t !== "dark") await page.click("#themeToggle");
  check("restored dark theme for demo", (await page.evaluate(() =>
    document.documentElement.getAttribute("data-theme") || "dark")) === "dark");

  console.log("\nCONSOLE CHECK");
  check("no console/page errors across the whole sweep", consoleErrors.length === 0,
    consoleErrors.slice(0, 3).join(" | "));

  await browser.close();

  const failed = results.filter(r => !r.ok);
  console.log("\n================= SWEEP RESULT =================");
  console.log(`${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) { console.log("FAILED:", failed.map(f => f.name).join(", ")); process.exit(1); }
  console.log("SWEEP CLEAN ✅");
})().catch(e => { console.error("SWEEP CRASHED:", e); process.exit(2); });
