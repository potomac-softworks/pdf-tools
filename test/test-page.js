import fs from "fs";
import path from "path";
import { chromium } from "playwright";
import { startStaticServer } from "../static-server.js";

function normalizeTestFile(value) {
  const testFile = (value || "password/index.html").replace(/\\/g, "/").replace(/^\.?\//, "");

  if (!testFile) {
    throw new Error("Provide a test file with TEST_FILE or the first CLI argument.");
  }

  return testFile;
}

function encodePathname(testFile) {
  return testFile
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

function parseViewport(value) {
  const match = /^(\d+)x(\d+)$/i.exec(value || "");

  if (!match) {
    throw new Error(`Viewport must look like 1440x1400. Received "${value}".`);
  }

  return {
    width: Number(match[1]),
    height: Number(match[2]),
  };
}

function parseArgs(argv) {
  const options = {
    screenshot: true,
    screenshotPath: null,
    skipTests: false,
    testFile: null,
    viewport: { width: 1440, height: 1400 },
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === "--skip-tests") {
      options.skipTests = true;
      continue;
    }

    if (argument === "--no-screenshot") {
      options.screenshot = false;
      continue;
    }

    if (argument === "--screenshot") {
      const next = argv[index + 1];

      options.screenshot = true;

      if (next && !next.startsWith("--")) {
        options.screenshotPath = next;
        index += 1;
      }

      continue;
    }

    if (argument.startsWith("--screenshot=")) {
      options.screenshot = true;
      options.screenshotPath = argument.slice("--screenshot=".length);
      continue;
    }

    if (argument === "--viewport") {
      options.viewport = parseViewport(argv[index + 1]);
      index += 1;
      continue;
    }

    if (argument.startsWith("--viewport=")) {
      options.viewport = parseViewport(argument.slice("--viewport=".length));
      continue;
    }

    if (!options.testFile) {
      options.testFile = argument;
      continue;
    }

    throw new Error(`Unexpected argument "${argument}".`);
  }

  return options;
}

function defaultScreenshotPath(testFile) {
  const baseName = testFile
    .replace(/\.html$/i, "")
    .replace(/[\\/]+/g, "-")
    .replace(/[^a-z0-9._-]/gi, "-");

  return path.join("tmp", `${baseName || "page"}.png`);
}

function buildPageUrl(origin, testFile, skipTests) {
  const query = skipTests ? "" : "?test=1";
  return `${origin}/${encodePathname(testFile)}${query}`;
}

function ensureParentDirectory(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

async function saveScreenshot(page, screenshotPath) {
  ensureParentDirectory(screenshotPath);
  await page.waitForTimeout(350);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  console.log(`Saved screenshot to ${screenshotPath}`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const testFile = normalizeTestFile(options.testFile || process.env.TEST_FILE);
  const screenshotPath = options.screenshot
    ? path.resolve(options.screenshotPath || defaultScreenshotPath(testFile))
    : null;
  const { origin, close } = await startStaticServer({ port: 0, rootDir: process.cwd() });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: options.viewport });
  const pageUrl = buildPageUrl(origin, testFile, options.skipTests);

  page.on("console", (message) => {
    console.log(message.text());
  });

  page.on("pageerror", (error) => {
    console.error("PAGE ERROR:", error.message);
  });

  page.on("requestfailed", (request) => {
    const url = request.url();

    if (url.includes("cdn.jsdelivr.net")) {
      console.warn(`REQUEST FAILED: ${url}`);
    }
  });

  let pendingError = null;

  try {
    console.log(`Opening ${pageUrl}`);
    await page.goto(pageUrl, { waitUntil: "domcontentloaded" });
    await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});

    if (!options.skipTests) {
      await page.waitForFunction(() => window.TESTS_DONE === true, { timeout: 30000 });
    }
  } catch (error) {
    pendingError = error;
  }

  try {
    if (screenshotPath) {
      await saveScreenshot(page, screenshotPath);
    }
  } finally {
    await browser.close();
    await close();
  }

  if (pendingError) {
    throw pendingError;
  }
}

main().catch((error) => {
  console.error(error && error.stack || error);
  process.exit(1);
});
