import fs from "fs";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".svg": "image/svg+xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
};

function send(response, statusCode, body, contentType = "text/plain; charset=utf-8") {
  response.writeHead(statusCode, { "Content-Type": contentType });
  response.end(body);
}

async function readFileIfExists(filePath) {
  try {
    return await fs.promises.readFile(filePath);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") {
      return null;
    }

    throw error;
  }
}

async function resolveRequestPath(rootDir, requestPath) {
  const pathname = decodeURIComponent((requestPath || "/").split("?")[0]);
  const safePath = pathname === "/" ? "/index.html" : pathname;
  const absolutePath = path.resolve(rootDir, `.${safePath}`);
  const relativePath = path.relative(rootDir, absolutePath);
  const fallbackPath = path.join(rootDir, "index.html");

  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    return null;
  }

  const stats = await fs.promises.stat(absolutePath).catch((error) => {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") {
      return null;
    }

    throw error;
  });

  if (!stats) {
    if (!path.extname(absolutePath)) {
      return fallbackPath;
    }

    return absolutePath;
  }

  if (stats.isDirectory()) {
    return path.join(absolutePath, "index.html");
  }

  return absolutePath;
}

async function handleRequest(rootDir, request, response) {
  const absolutePath = await resolveRequestPath(rootDir, request.url);

  if (!absolutePath) {
    send(response, 403, "Forbidden");
    return;
  }

  const file = await readFileIfExists(absolutePath);

  if (!file) {
    send(response, 404, "Not Found");
    return;
  }

  const extension = path.extname(absolutePath).toLowerCase();
  const contentType = MIME_TYPES[extension] || "application/octet-stream";

  response.writeHead(200, { "Content-Type": contentType });
  response.end(file);
}

function startStaticServer({ port = 4173, rootDir = process.cwd() } = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      handleRequest(rootDir, request, response).catch((error) => {
        console.error(error && error.stack || error);
        send(response, 500, "Internal Server Error");
      });
    });

    server.on("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : port;

      resolve({
        origin: `http://127.0.0.1:${actualPort}`,
        server,
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((error) => {
              if (error) {
                closeReject(error);
                return;
              }

              closeResolve();
            });
          }),
      });
    });
  });
}

async function main() {
  const port = Number(process.env.PORT || "4173");
  const { origin } = await startStaticServer({ port, rootDir: process.cwd() });

  console.log(`Serving ${process.cwd()} at ${origin}`);
}

const entryPath = fileURLToPath(import.meta.url);

if (process.argv[1] && path.resolve(process.argv[1]) === entryPath) {
  main().catch((error) => {
    console.error(error && error.stack || error);
    process.exit(1);
  });
}

export { startStaticServer };
