import { PDFDocument, StandardFonts } from "../node_modules/pdf-lib/dist/pdf-lib.esm.js";
import * as passwordApi from "../lib/password/pdf-password.js";
import { $, $$, setHidden } from "./html.js";

const form = $("#passwordForm");
const statusMessage = $("#statusMessage");
const submitButton = $("#submitButton");
const newUserPasswordLabel = $("#newUserPasswordLabel");
const newUserPasswordInput = $("#newUserPassword");
const ownerPasswordDetails = $("#newOwnerPasswordRow details");
const rows = {
  currentPassword: $("#currentPasswordRow"),
  newUserPassword: $("#newUserPasswordRow"),
  newOwnerPassword: $("#newOwnerPasswordRow"),
  algorithm: $("#algorithmRow"),
};
const actions = {
  add: {
    label: "Add Password",
    passwordLabel: "Password",
    passwordPlaceholder: "Required to open the PDF.",
    visible: ["newUserPassword", "newOwnerPassword", "algorithm"],
  },
  update: {
    label: "Update Password",
    passwordLabel: "New Password",
    passwordPlaceholder: "Required to open the updated PDF.",
    visible: ["currentPassword", "newUserPassword", "newOwnerPassword", "algorithm"],
  },
  remove: {
    label: "Remove Password",
    passwordLabel: "Password",
    passwordPlaceholder: "Required to open the PDF.",
    visible: ["currentPassword"],
  },
};

form.addEventListener("submit", submit);

for (const input of form.elements.action) {
  input.addEventListener("change", syncFormState);
}

for (const tab of $$("[data-action-tab]")) {
  tab.addEventListener("click", () => {
    form.elements.action.value = tab.dataset.actionTab;
    syncFormState();
  });
}

for (const toggle of $$("[data-toggle-type]")) {
  const syncToggle = () => {
    const [selector, hiddenType, visibleType] = toggle.dataset.toggleType.split(":");
    const visible = toggle.getAttribute("aria-pressed") === "true";
    $(selector).type = visible ? visibleType : hiddenType;
    toggle.dataset.icon = visible ? "eye-open" : "eye-closed";
    toggle.setAttribute("aria-label", `${visible ? "Hide" : "Show"} ${toggle.querySelector(".visually-hidden").textContent.toLowerCase().replace(/^(show|hide)\s+/, "")}`);
  };

  toggle.addEventListener("click", () => {
    const visible = toggle.getAttribute("aria-pressed") === "true";
    toggle.setAttribute("aria-pressed", String(!visible));
    syncToggle();
  });

  syncToggle();
}

syncFormState();

function getSelectedAction() {
  return form.elements.action.value;
}

function syncFormState() {
  const action = actions[getSelectedAction()];

  for (const [name, row] of Object.entries(rows)) {
    setHidden(row, !action.visible.includes(name));
  }

  if (!action.visible.includes("newOwnerPassword")) {
    ownerPasswordDetails.open = false;
  }

  for (const tab of $$("[data-action-tab]")) {
    const active = tab.dataset.actionTab === getSelectedAction();
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  }

  submitButton.textContent = action.label;
  newUserPasswordLabel.textContent = action.passwordLabel;
  newUserPasswordInput.placeholder = action.passwordPlaceholder;
}

function setStatus(message, tone = "info") {
  statusMessage.textContent = message;
  statusMessage.dataset.tone = tone;
  statusMessage.classList.toggle("d-none", !message);
}

function getFormValues() {
  return {
    action: getSelectedAction(),
    algorithm: form.elements.algorithm.value,
    currentPassword: form.elements.currentPassword.value,
    newOwnerPassword: form.elements.newOwnerPassword.value,
    newUserPassword: form.elements.newUserPassword.value,
    pdfFile: form.elements.pdfFile.files[0] ?? null,
  };
}

function validateRequest(request) {
  if (!request.pdfFile) {
    throw new Error("Choose a PDF first.");
  }

  if ((request.action === "add" || request.action === "update") && !request.newUserPassword) {
    throw new Error(`Enter a ${request.action === "update" ? "new " : ""}password.`);
  }

  if ((request.action === "update" || request.action === "remove") && !request.currentPassword) {
    throw new Error("Enter the current password.");
  }
}

function validatePdfState(request, passwordState) {
  if (request.action === "add" && passwordState.encrypted) {
    throw new Error("This PDF already has a password. Use Update Password instead.");
  }

  if ((request.action === "update" || request.action === "remove") && !passwordState.encrypted) {
    throw new Error(`This PDF does not have a password to ${request.action}.`);
  }
}

function getOwnerPassword(request) {
  return request.newOwnerPassword || request.newUserPassword;
}

function getOutputName(fileName, action) {
  const baseName = fileName.replace(/\.pdf$/i, "");

  return (
    action === "remove" ? `${baseName}-unlocked.pdf` :
    action === "update" ? `${baseName}-updated-password.pdf` :
    `${baseName}-protected.pdf`
  );
}

function downloadBytes(bytes, name) {
  const file = new File([bytes], name, { type: "application/pdf" });
  const url = URL.createObjectURL(file);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = file.name;
  anchor.click();
  URL.revokeObjectURL(url);

  return file;
}

async function processRequest(request) {
  const pdfBytes = new Uint8Array(await request.pdfFile.arrayBuffer());
  validatePdfState(request, passwordApi.inspectPdfPasswordState(pdfBytes));

  if (request.action === "remove") {
    return passwordApi.removePasswordFromPdfBytes(pdfBytes, {
      password: request.currentPassword,
    });
  }

  if (request.action === "update") {
    return passwordApi.updatePasswordOnPdfBytes(pdfBytes, {
      currentPassword: request.currentPassword,
      encrypt: request.algorithm,
      newOwnerPassword: getOwnerPassword(request),
      newUserPassword: request.newUserPassword,
    });
  }

  return passwordApi.addPasswordToPdfBytes(pdfBytes, {
    encrypt: request.algorithm,
    ownerPassword: getOwnerPassword(request),
    userPassword: request.newUserPassword,
  });
}

async function submit(event) {
  event.preventDefault();

  try {
    const request = getFormValues();
    validateRequest(request);
    setStatus("Processing PDF...");

    const outputBytes = await processRequest(request);
    const outputFile = downloadBytes(outputBytes, getOutputName(request.pdfFile.name, request.action));

    setStatus(`Downloaded ${outputFile.name}.`, "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function assertRejects(action, expectedMessage) {
  try {
    await action();
  } catch (error) {
    assert(error.message.includes(expectedMessage), `Expected "${expectedMessage}", received "${error.message}".`);
    return;
  }

  throw new Error(`Expected failure containing "${expectedMessage}".`);
}

async function createTestPdf(name) {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 200]);
  const font = await document.embedFont(StandardFonts.Helvetica);

  page.drawText("Top Secret", { x: 32, y: 120, size: 24, font });

  return new File([await document.save({ useObjectStreams: false })], name || "sample.pdf", {
    type: "application/pdf",
  });
}

async function loadUnencryptedPdf(bytes) {
  return PDFDocument.load(bytes, { updateMetadata: false });
}

async function runTests() {
  const fakePdf = await createTestPdf();

  validateRequest({ action: "add", pdfFile: fakePdf, newUserPassword: "secret" });
  await assertRejects(async () => validateRequest({ action: "add", pdfFile: null, newUserPassword: "secret" }), "Choose a PDF first.");
  await assertRejects(async () => validateRequest({ action: "add", pdfFile: fakePdf, newUserPassword: "" }), "Enter a password.");
  await assertRejects(async () => validateRequest({ action: "remove", pdfFile: fakePdf, currentPassword: "" }), "Enter the current password.");

  form.elements.action.value = "remove";
  syncFormState();
  assert(rows.currentPassword.hidden === false, "Remove mode should show the current password.");
  assert(rows.newUserPassword.hidden === true, "Remove mode should hide the new password field.");
  assert(rows.algorithm.hidden === true, "Remove mode should hide the algorithm selector.");
  assert(form.elements.currentPassword.disabled === false, "Visible fields should remain enabled.");
  assert(form.elements.newUserPassword.disabled === true, "Hidden fields should be disabled.");
  assert(statusMessage.classList.contains("d-none"), "Status should start hidden.");

  $("#actionTabAdd").click();
  assert(getSelectedAction() === "add", "Add tab should select add mode.");
  assert(rows.currentPassword.hidden === true, "Add mode should hide the current password.");
  assert(rows.newUserPassword.hidden === false, "Add mode should show the new password field.");
  assert(newUserPasswordLabel.textContent === "Password", "Add mode should use the simple password label.");

  $("#actionTabUpdate").click();
  assert(getSelectedAction() === "update", "Update tab should select update mode.");
  assert(rows.currentPassword.hidden === false, "Update mode should show the current password.");
  assert(rows.newOwnerPassword.hidden === false, "Update mode should show the owner password.");
  assert(newUserPasswordLabel.textContent === "New Password", "Update mode should use the new password label.");

  const newUserToggle = $('[data-toggle-type="#newUserPassword:password:text"]');
  assert(form.elements.newUserPassword.type === "password", "Password field should start hidden.");
  newUserToggle.click();
  assert(form.elements.newUserPassword.type === "text", "Pressed toggle should reveal the password.");
  newUserToggle.click();
  assert(form.elements.newUserPassword.type === "password", "Pressed toggle again should hide the password.");

  const plainBytes = new Uint8Array(await fakePdf.arrayBuffer());
  const protectedBytes = await passwordApi.addPasswordToPdfBytes(plainBytes, {
    encrypt: "aes-256",
    ownerPassword: "owner-secret",
    userPassword: "secret",
  });
  const protectedState = passwordApi.inspectPdfPasswordState(protectedBytes);

  assert(protectedState.encrypted === true, "Protected PDF should report as encrypted.");
  assert(protectedState.algorithm === "aes-256", "Protected PDF should report AES-256.");
  await assertRejects(
    async () => processRequest({ action: "add", algorithm: "aes-256", newUserPassword: "next-secret", pdfFile: new File([protectedBytes], "protected.pdf", { type: "application/pdf" }) }),
    "This PDF already has a password. Use Update Password instead."
  );
  await assertRejects(async () => passwordApi.removePasswordFromPdfBytes(protectedBytes, { password: "wrong-password" }), "Incorrect password.");

  const unprotectedBytes = await passwordApi.removePasswordFromPdfBytes(protectedBytes, { password: "secret" });
  const unprotectedState = passwordApi.inspectPdfPasswordState(unprotectedBytes);
  const unprotectedDocument = await loadUnencryptedPdf(unprotectedBytes);

  assert(unprotectedState.encrypted === false, "Removed password PDF should no longer be encrypted.");
  assert(unprotectedDocument.getPageCount() === 1, "Unlocked PDF should still have one page.");
  await assertRejects(
    async () => processRequest({ action: "remove", currentPassword: "secret", pdfFile: new File([unprotectedBytes], "plain.pdf", { type: "application/pdf" }) }),
    "This PDF does not have a password to remove."
  );

  const updatedBytes = await passwordApi.updatePasswordOnPdfBytes(protectedBytes, {
    currentPassword: "secret",
    encrypt: "aes-128",
    newOwnerPassword: "owner-next",
    newUserPassword: "fresh-secret",
  });
  const updatedState = passwordApi.inspectPdfPasswordState(updatedBytes);

  assert(updatedState.encrypted === true, "Updated PDF should remain encrypted.");
  assert(updatedState.algorithm === "aes-128", "Updated PDF should switch to AES-128.");
  await assertRejects(async () => passwordApi.removePasswordFromPdfBytes(updatedBytes, { password: "secret" }), "Incorrect password.");

  const updatedPlainBytes = await passwordApi.removePasswordFromPdfBytes(updatedBytes, { password: "fresh-secret" });
  const updatedPlainDocument = await loadUnencryptedPdf(updatedPlainBytes);

  assert(updatedPlainDocument.getPageCount() === 1, "Updated password PDF should still decrypt cleanly.");
  setStatus("Visible message");
  assert(statusMessage.classList.contains("d-none") === false, "Status should become visible when it has a message.");
  setStatus("");
  assert(statusMessage.classList.contains("d-none") === true, "Status should hide again when cleared.");
  assert(getOutputName("sample.pdf", "add") === "sample-protected.pdf", "Add action should use the protected suffix.");
  assert(getOutputName("sample.pdf", "update") === "sample-updated-password.pdf", "Update action should use the update suffix.");
  assert(getOutputName("sample.pdf", "remove") === "sample-unlocked.pdf", "Remove action should use the unlocked suffix.");

  console.log("All password page tests passed.");
}

if (new URLSearchParams(window.location.search).get("test") === "1") {
  runTests()
    .then(() => {
      window.TESTS_DONE = true;
    })
    .catch((error) => {
      setTimeout(() => {
        throw error;
      }, 0);
    });
}

