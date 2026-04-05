import fs from "fs";
import path from "path";
import { pathToFileURL } from "url";
import { PDFDocument, StandardFonts } from "pdf-lib";

async function loadPasswordApi() {
  return import(pathToFileURL(path.join(process.cwd(), "lib", "password", "pdf-password.js")).href);
}

async function loadPdfJs() {
  return import("../node_modules/pdfjs-dist/legacy/build/pdf.mjs");
}

async function ensureDir(dirPath) {
  await fs.promises.mkdir(dirPath, { recursive: true });
}

async function createFixturePdf(outputPath, title, pageTexts) {
  const document = await PDFDocument.create();
  const font = await document.embedFont(StandardFonts.Helvetica);

  pageTexts.forEach((text, index) => {
    const page = document.addPage([500, 300]);
    page.drawText(title, {
      x: 40,
      y: 240,
      size: 22,
      font,
    });
    page.drawText(`Page ${index + 1}`, {
      x: 40,
      y: 200,
      size: 16,
      font,
    });
    page.drawText(text, {
      x: 40,
      y: 150,
      size: 18,
      font,
    });
  });

  const bytes = new Uint8Array(await document.save({ useObjectStreams: false }));
  await fs.promises.writeFile(outputPath, bytes);
  return bytes;
}

async function openPdf(pdfjs, bytes, password) {
  const options = {
    data: Uint8Array.from(bytes),
    disableWorker: true,
    standardFontDataUrl: "./node_modules/pdfjs-dist/standard_fonts/",
  };

  if (typeof password === "string") {
    options.password = password;
  }

  const loadingTask = pdfjs.getDocument(options);
  const document = await loadingTask.promise;

  return document;
}

async function readPageText(pdfDocument, pageNumber) {
  const page = await pdfDocument.getPage(pageNumber);
  const textContent = await page.getTextContent();

  return textContent.items
    .map((item) => ("str" in item ? item.str : ""))
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

async function assertPasswordRejected(pdfjs, bytes, password) {
  try {
    const document = await openPdf(pdfjs, bytes, password);
    await document.destroy();
  } catch (error) {
    if (error && error.name === "PasswordException") {
      return;
    }

    throw error;
  }

  throw new Error("Expected the PDF reader to reject the wrong password.");
}

async function validateEncryptedPdf(pdfjs, source, options) {
  const bytes =
    typeof source === "string"
      ? Uint8Array.from(await fs.promises.readFile(source))
      : Uint8Array.from(source);
  const document = await openPdf(pdfjs, bytes, options.userPassword);

  try {
    if (document.numPages !== options.expectedPageTexts.length) {
      throw new Error(`Expected ${options.expectedPageTexts.length} pages, received ${document.numPages}.`);
    }

    for (let pageIndex = 0; pageIndex < options.expectedPageTexts.length; pageIndex += 1) {
      const text = await readPageText(document, pageIndex + 1);

      if (!text.includes(options.expectedPageTexts[pageIndex])) {
        throw new Error(
          `Expected page ${pageIndex + 1} to contain "${options.expectedPageTexts[pageIndex]}". Received "${text}".`
        );
      }
    }
  } finally {
    await document.destroy();
  }

  await assertPasswordRejected(pdfjs, bytes, options.rejectedPassword);
  const ownerDocument = await openPdf(pdfjs, bytes, options.ownerPassword);

  try {
    if (ownerDocument.numPages !== options.expectedPageTexts.length) {
      throw new Error(`Owner password did not open the expected number of pages.`);
    }

    for (let pageIndex = 0; pageIndex < options.expectedPageTexts.length; pageIndex += 1) {
      const text = await readPageText(ownerDocument, pageIndex + 1);

      if (!text.includes(options.expectedPageTexts[pageIndex])) {
        throw new Error(
          `Expected owner password view of page ${pageIndex + 1} to contain "${options.expectedPageTexts[pageIndex]}". Received "${text}".`
        );
      }
    }
  } finally {
    await ownerDocument.destroy();
  }
}

async function validatePlainPdf(pdfjs, source, expectedPageTexts) {
  const bytes =
    typeof source === "string"
      ? Uint8Array.from(await fs.promises.readFile(source))
      : Uint8Array.from(source);
  const document = await openPdf(pdfjs, bytes);

  try {
    if (document.numPages !== expectedPageTexts.length) {
      throw new Error(`Expected ${expectedPageTexts.length} pages, received ${document.numPages}.`);
    }

    for (let pageIndex = 0; pageIndex < expectedPageTexts.length; pageIndex += 1) {
      const text = await readPageText(document, pageIndex + 1);

      if (!text.includes(expectedPageTexts[pageIndex])) {
        throw new Error(
          `Expected plain page ${pageIndex + 1} to contain "${expectedPageTexts[pageIndex]}". Received "${text}".`
        );
      }
    }
  } finally {
    await document.destroy();
  }
}

async function main() {
  const passwordApi = await loadPasswordApi();
  const pdfjs = await loadPdfJs();
  const fixturesDir = path.join(process.cwd(), "docs", "test", "generated");
  const plainDir = path.join(fixturesDir, "plain");
  const encryptedDir = path.join(fixturesDir, "encrypted");
  const updatedDir = path.join(fixturesDir, "updated");
  const unlockedDir = path.join(fixturesDir, "unlocked");
  const fixtureDefinitions = [
    {
      name: "simple",
      title: "Fixture Simple",
      pageTexts: ["alpha-secret-line"],
    },
    {
      name: "multipage",
      title: "Fixture Multi",
      pageTexts: ["bravo-first-page", "charlie-second-page"],
    },
    {
      name: "symbols",
      title: "Fixture Symbols",
      pageTexts: ["delta & echo / 42", "foxtrot-underline_value"],
    },
  ];

  await ensureDir(plainDir);
  await ensureDir(encryptedDir);
  await ensureDir(updatedDir);
  await ensureDir(unlockedDir);

  for (const fixture of fixtureDefinitions) {
    const plainPath = path.join(plainDir, `${fixture.name}.pdf`);
    const plainBytes = await createFixturePdf(plainPath, fixture.title, fixture.pageTexts);
    await validatePlainPdf(pdfjs, plainBytes, fixture.pageTexts);

    for (const algorithm of ["aes-128", "aes-256"]) {
      const encryptedBytes = await passwordApi.addPasswordToPdfBytes(plainBytes, {
        encrypt: algorithm,
        userPassword: "secret",
        ownerPassword: "owner",
      });
      const encryptedPath = path.join(encryptedDir, `${fixture.name}-${algorithm}.pdf`);
      const updatedPath = path.join(updatedDir, `${fixture.name}-${algorithm}.pdf`);
      const unlockedPath = path.join(unlockedDir, `${fixture.name}-${algorithm}.pdf`);
      const updatedBytes = await passwordApi.updatePasswordOnPdfBytes(encryptedBytes, {
        currentPassword: "secret",
        encrypt: algorithm,
        newUserPassword: "fresh-secret",
        newOwnerPassword: "owner-next",
      });
      const unlockedBytes = await passwordApi.removePasswordFromPdfBytes(updatedBytes, {
        password: "fresh-secret",
      });

      await fs.promises.writeFile(encryptedPath, encryptedBytes);
      await fs.promises.writeFile(updatedPath, updatedBytes);
      await fs.promises.writeFile(unlockedPath, unlockedBytes);

      await validateEncryptedPdf(pdfjs, encryptedPath, {
        userPassword: "secret",
        ownerPassword: "owner",
        rejectedPassword: "wrong-password",
        expectedPageTexts: fixture.pageTexts,
      });
      await validateEncryptedPdf(pdfjs, updatedPath, {
        userPassword: "fresh-secret",
        ownerPassword: "owner-next",
        rejectedPassword: "secret",
        expectedPageTexts: fixture.pageTexts,
      });
      await validatePlainPdf(pdfjs, unlockedPath, fixture.pageTexts);
    }
  }

  console.log("All password workflow reader tests passed.");
}

main().catch((error) => {
  console.error(error && error.stack || error);
  process.exit(1);
});
