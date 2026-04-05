export function $(selector, scope = document) {
  return scope.querySelector(selector);
}

export function $$(selector, scope = document) {
  return Array.from(scope.querySelectorAll(selector));
}

export function setHidden(element, hidden) {
  element.hidden = hidden;

  for (const field of $$("input, select, textarea, button", element)) {
    field.disabled = hidden;
  }
}

