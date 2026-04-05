import fs from "fs";
import path from "path";
import { chromium } from "playwright";
import { startStaticServer } from "../static-server.js";

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

function readNumber(name, value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`Expected a non-negative number for ${name}. Received "${value}".`);
  }

  return parsed;
}

function normalizePagePath(value) {
  const pagePath = (value || "index.html").replace(/\\/g, "/").replace(/^\.?\//, "");

  if (!pagePath) {
    throw new Error("Provide a page path like index.html or password/index.html.");
  }

  return pagePath;
}

function encodePathname(pagePath) {
  return pagePath
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

function parseArgs(argv) {
  if (argv.length < 2) {
    throw new Error("Usage: node scripts/crop-page.js <page> <output.png> [--selector .hero] [--x 0 --y 0 --width 400 --height 300] [--viewport 1440x1400] [--test-query]");
  }

  const options = {
    output: path.resolve(argv[1]),
    pagePath: normalizePagePath(argv[0]),
    selector: null,
    testQuery: false,
    viewport: { width: 1440, height: 1400 },
    x: null,
    y: null,
    width: null,
    height: null,
  };

  for (let index = 2; index < argv.length; index += 1) {
    const flag = argv[index];

    if (flag === "--selector") {
      options.selector = argv[index + 1];
      index += 1;
      continue;
    }

    if (flag === "--viewport") {
      options.viewport = parseViewport(argv[index + 1]);
      index += 1;
      continue;
    }

    if (flag === "--test-query") {
      options.testQuery = true;
      continue;
    }

    if (flag === "--x") {
      options.x = readNumber("x", argv[index + 1]);
      index += 1;
      continue;
    }

    if (flag === "--y") {
      options.y = readNumber("y", argv[index + 1]);
      index += 1;
      continue;
    }

    if (flag === "--width") {
      options.width = readNumber("width", argv[index + 1]);
      index += 1;
      continue;
    }

    if (flag === "--height") {
      options.height = readNumber("height", argv[index + 1]);
      index += 1;
      continue;
    }

    throw new Error(`Unknown flag "${flag}".`);
  }

  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const clipReady = [options.x, options.y, options.width, options.height].every((value) => value !== null);
  const browser = await chromium.launch();
  const { origin, close } = await startStaticServer({ port: 0, rootDir: process.cwd() });
  const page = await browser.newPage({ viewport: options.viewport });
  const query = options.testQuery ? "?test=1" : "";
  const pageUrl = `${origin}/${encodePathname(options.pagePath)}${query}`;

  fs.mkdirSync(path.dirname(options.output), { recursive: true });

  try {
    await page.goto(pageUrl, { waitUntil: "domcontentloaded" });
    await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
    await page.waitForTimeout(350);

    if (options.selector) {
      const target = page.locator(options.selector).first();
      await target.waitFor({ state: "visible", timeout: 10000 });
      await target.screenshot({ path: options.output });
    } else if (clipReady) {
      await page.screenshot({
        path: options.output,
        clip: {
          x: Math.floor(options.x),
          y: Math.floor(options.y),
          width: Math.floor(options.width),
          height: Math.floor(options.height),
        },
      });
    } else {
      await page.screenshot({ path: options.output, fullPage: true });
    }

    console.log(`Saved crop to ${options.output}`);
  } finally {
    await browser.close();
    await close();
  }
}

main().catch((error) => {
  console.error(error && error.stack || error);
  process.exit(1);
});
