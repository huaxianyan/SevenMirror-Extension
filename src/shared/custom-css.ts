/**
 * A sheet the user pastes in the options page, applied to every extension page. Typography this
 * specific (a font the browser cannot reference, a text shadow that thickens strokes) has no place
 * in the shipped theme, but the user should not need a browser extension they cannot use here.
 */
const STORAGE_KEY = 'customCss';

export async function loadCustomCss(): Promise<string> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const value: unknown = stored[STORAGE_KEY];
  return typeof value === 'string' ? value : '';
}

export async function saveCustomCss(css: string): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: css });
}

/** Injects the saved sheet and keeps it in step with edits made in the options page. */
export async function applyCustomCss(): Promise<void> {
  const style = document.createElement('style');
  style.id = 'custom-css';
  document.head.append(style);
  const paint = (css: string): void => {
    style.textContent = css;
  };
  paint(await loadCustomCss());
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    const change = changes[STORAGE_KEY];
    if (change === undefined) return;
    paint(typeof change.newValue === 'string' ? change.newValue : '');
  });
}
