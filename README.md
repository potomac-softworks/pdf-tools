# PDF Tools

Most online PDF tools begin by asking you to upload a file.

This one is going in the other direction.

`pdf-tools` is a browser-first PDF toolbox with a simple static UI and local processing where we can get away with it. Right now the real feature is password management: add a password, change it, remove it, and verify the result without shipping the document off to a server. The rest of the shell is in place for OCR, split/merge, and editing, but those pages are still placeholders.

## What Works

- Add, update, and remove PDF passwords in the browser
- AES-128 and AES-256 encryption options
- Password-state validation in the UI before running an operation
- Shared multi-page frontend with a lightweight Bootstrap theme
- Reader tests and browser tests under `test/`

## Run It

```bash
npm install
npm start
```

Then open `http://127.0.0.1:4173`.

Public site: `https://potomacsoftworks.com/pdf-tools/`

## Test It

```bash
npm test
```

That runs both the reader workflow checks and the browser-level password page test.

## Project Shape

- `password/` contains the password tool UI
- `lib/password/` contains the PDF password implementation
- `styles/bootstrap-theme.css` is the shared site theme
- `test/` contains tests plus screenshot/crop helpers

## Notes

- Normal use is local. The password tool is designed to run in the browser.
- `docs/` and `tmp/` are ignored and are not part of the tracked project state.
- OCR, split/merge, and editing are planned surfaces, not finished tools yet.
