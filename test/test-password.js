import { chromium } from "playwright";
import { pathToFileURL } from "url";
import path from "path";

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const pageUrl = pathToFileURL(path.join(process.cwd(), "password", "index.html")).href + "?test=1";

  page.on("console", (message) => {
    console.log(message.text());
  });

  page.on("pageerror", (error) => {
    console.error("PAGE ERROR:", error.message);
  });

  console.log(`Opening ${pageUrl}`);
  await page.goto(pageUrl);
  await page.waitForFunction(() => window.TESTS_DONE === true, { timeout: 30000 });
  await browser.close();
}

main().catch((error) => {
  console.error(error && error.stack || error);
  process.exit(1);
});
