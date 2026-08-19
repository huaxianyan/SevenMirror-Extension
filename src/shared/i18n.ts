export type MessageSubstitutions = string | string[];

export function message(key: string, substitutions?: MessageSubstitutions): string {
  const value = chrome.i18n.getMessage(key, substitutions);
  if (value.length === 0) throw new Error(`Missing localized message: ${key}`);
  return value;
}

export function localizeDocument(root: Document = document): void {
  root.documentElement.lang = chrome.i18n.getUILanguage().replace('_', '-');
  root.querySelectorAll<HTMLElement>('[data-i18n]').forEach((element) => {
    element.textContent = message(requireAttribute(element, 'data-i18n'));
  });
  root.querySelectorAll<HTMLElement>('[data-i18n-placeholder]').forEach((element) => {
    element.setAttribute(
      'placeholder',
      message(requireAttribute(element, 'data-i18n-placeholder')),
    );
  });
}

function requireAttribute(element: Element, name: string): string {
  const value = element.getAttribute(name);
  if (value === null || value.length === 0) throw new Error(`Missing ${name}`);
  return value;
}
