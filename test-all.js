import { spawn } from "child_process";

function runNodeScript(scriptPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath], {
      cwd: process.cwd(),
      stdio: "inherit",
    });

    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`${scriptPath} exited with code ${code}.`));
    });
  });
}

async function main() {
  await runNodeScript("test-encryption.js");
  await runNodeScript("test-page.js");
}

main().catch((error) => {
  console.error(error && error.stack || error);
  process.exit(1);
});
