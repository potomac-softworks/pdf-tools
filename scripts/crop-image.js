import fs from "fs";
import path from "path";
import { chromium } from "playwright";

function readNumber(name, value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`Expected a non-negative number for ${name}. Received "${value}".`);
  }

  return parsed;
}

function parseArgs(argv) {
  if (argv.length < 2) {
    throw new Error("Usage: node scripts/crop-image.js <input.png> <output.png> --x 0 --y 0 --width 400 --height 300");
  }

  const options = {
    input: path.resolve(argv[0]),
    output: path.resolve(argv[1]),
    x: null,
    y: null,
    width: null,
    height: null,
  };

  for (let index = 2; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];

    if (!value) {
      throw new Error(`Missing value for ${flag}.`);
    }

    if (flag === "--x") options.x = readNumber("x", value);
    else if (flag === "--y") options.y = readNumber("y", value);
    else if (flag === "--width") options.width = readNumber("width", value);
    else if (flag === "--height") options.height = readNumber("height", value);
    else throw new Error(`Unknown flag "${flag}".`);
  }

  if ([options.x, options.y, options.width, options.height].some((value) => value === null)) {
    throw new Error("Provide --x, --y, --width, and --height.");
  }

  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(options.input)) {
    throw new Error(`Input image not found: ${options.input}`);
  }

  fs.mkdirSync(path.dirname(options.output), { recursive: true });

  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: {
      width: Math.max(1, Math.ceil(options.width)),
      height: Math.max(1, Math.ceil(options.height)),
    },
  });

  try {
    const extension = path.extname(options.input).toLowerCase();
    const mimeType = extension === ".jpg" || extension === ".jpeg"
      ? "image/jpeg"
      : extension === ".webp"
        ? "image/webp"
        : "image/png";
    const dataUrl = `data:${mimeType};base64,${fs.readFileSync(options.input).toString("base64")}`;

    await page.setContent(`
      <!DOCTYPE html>
      <html lang="en">
      <body style="margin:0;background:#111;">
        <img id="source" src="${dataUrl}" alt="">
      </body>
      </html>
    `);

    await page.waitForFunction(() => {
      const image = document.getElementById("source");
      return image && image.complete && image.naturalWidth > 0 && image.naturalHeight > 0;
    });

    const dimensions = await page.$eval("#source", (image) => ({
      width: image.naturalWidth,
      height: image.naturalHeight,
    }));

    const clip = {
      x: Math.floor(options.x),
      y: Math.floor(options.y),
      width: Math.floor(options.width),
      height: Math.floor(options.height),
    };

    if (clip.x + clip.width > dimensions.width || clip.y + clip.height > dimensions.height) {
      throw new Error(`Crop rectangle exceeds image bounds ${dimensions.width}x${dimensions.height}.`);
    }

    await page.setViewportSize(dimensions);
    await page.$eval(
      "#source",
      (image, nextDimensions) => {
        image.style.display = "block";
        image.style.width = `${nextDimensions.width}px`;
        image.style.height = `${nextDimensions.height}px`;
      },
      dimensions
    );

    await page.screenshot({ path: options.output, clip });
    console.log(`Saved crop to ${options.output}`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error && error.stack || error);
  process.exit(1);
});
