import { localizeDocument, message } from '../shared/i18n';
import type {
  NotificationShortcutPreferences,
  NotificationShortcutRule,
} from '../background/notification-shortcuts';

interface ApplicationOption {
  id: string;
  name: string;
}

const form = requireDocumentElement<HTMLFormElement>('shortcut-form');
const pinDismiss = requireDocumentElement<HTMLInputElement>('pin-dismiss');
const rulesList = requireDocumentElement<HTMLOListElement>('rules');
const emptyRules = requireDocumentElement<HTMLElement>('empty-rules');
const addRule = requireDocumentElement<HTMLButtonElement>('add-rule');
const save = requireDocumentElement<HTMLButtonElement>('save');
const status = requireDocumentElement<HTMLElement>('status');
const template = requireDocumentElement<HTMLTemplateElement>('rule-template');
let rules: NotificationShortcutRule[] = [];
let applications: ApplicationOption[] = [];
let loaded = false;

localizeDocument();
void load();

pinDismiss.addEventListener('change', markDirty);
addRule.addEventListener('click', () => {
  const id = randomId();
  rules.push({ id, match: { kind: 'reply' } });
  renderRules(id);
  markDirty();
});
form.addEventListener('submit', (event) => {
  event.preventDefault();
  void saveChanges();
});

async function load(): Promise<void> {
  const response = await chrome.runtime.sendMessage({
    type: 'get-notification-shortcut-settings',
  }) as {
    preferences: NotificationShortcutPreferences;
    applications: ApplicationOption[];
  } | undefined;
  if (response === undefined) {
    setStatus(message('shortcutLoadFailed'));
    setFormDisabled(true);
    return;
  }
  pinDismiss.checked = response.preferences.pinDismiss;
  rules = response.preferences.rules;
  applications = response.applications;
  loaded = true;
  setFormDisabled(false);
  document.documentElement.dataset.shortcutsReady = 'true';
}

async function saveChanges(): Promise<void> {
  if (!validateRules()) return;
  setFormDisabled(true);
  setStatus(message('shortcutSaving'));
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'save-notification-shortcut-settings',
      preferences: { pinDismiss: pinDismiss.checked, rules },
    }) as { saved?: boolean } | undefined;
    if (!response?.saved) throw new Error('Shortcut save failed');
    setStatus(message('shortcutSaved'));
  } catch {
    setStatus(message('shortcutSaveFailed'));
  } finally {
    setFormDisabled(false);
  }
}

function renderRules(focusRuleId?: string): void {
  rulesList.replaceChildren();
  emptyRules.hidden = rules.length !== 0;
  for (const [index, rule] of rules.entries()) {
    const fragment = template.content.cloneNode(true) as DocumentFragment;
    localizeDocument(fragment);
    const item = requireElement<HTMLLIElement>(fragment, '.rule');
    item.dataset.ruleId = rule.id;
    const title = requireElement<HTMLHeadingElement>(fragment, '.rule-title');
    const kind = requireElement<HTMLSelectElement>(fragment, '.match-kind');
    const titleField = requireElement<HTMLElement>(fragment, '.title-field');
    const value = requireElement<HTMLInputElement>(fragment, '.match-value');
    const fieldError = requireElement<HTMLElement>(fragment, '.field-error');
    const application = requireElement<HTMLSelectElement>(fragment, '.application');
    const moveUp = requireElement<HTMLButtonElement>(fragment, '.move-up');
    const moveDown = requireElement<HTMLButtonElement>(fragment, '.move-down');
    const remove = requireElement<HTMLButtonElement>(fragment, '.remove');
    const position = (index + 1).toString();

    title.textContent = message('shortcutRuleTitle', position);
    kind.value = rule.match.kind;
    value.value = rule.match.kind === 'reply' ? '' : rule.match.value;
    titleField.hidden = rule.match.kind === 'reply';
    fieldError.hidden = true;
    renderApplicationOptions(application, rule);
    moveUp.disabled = index === 0;
    moveDown.disabled = index === rules.length - 1;
    moveUp.setAttribute('aria-label', message('shortcutMoveUpRule', position));
    moveDown.setAttribute('aria-label', message('shortcutMoveDownRule', position));
    remove.setAttribute('aria-label', message('shortcutRemoveRuleNumber', position));

    kind.addEventListener('change', () => {
      const current = requireRule(rule.id);
      current.match = kind.value === 'reply'
        ? { kind: 'reply' }
        : { kind: kind.value as 'title-exact' | 'title-contains', value: value.value };
      titleField.hidden = kind.value === 'reply';
      clearFieldError(value, fieldError);
      markDirty();
    });
    value.addEventListener('input', () => {
      const current = requireRule(rule.id);
      if (current.match.kind !== 'reply') current.match.value = value.value;
      clearFieldError(value, fieldError);
      markDirty();
    });
    application.addEventListener('change', () => {
      const current = requireRule(rule.id);
      const selected = applications.find((candidate) => candidate.id === application.value);
      if (selected === undefined) {
        delete current.sourceApplicationId;
        delete current.sourceApplicationName;
      } else {
        current.sourceApplicationId = selected.id;
        current.sourceApplicationName = selected.name;
      }
      markDirty();
    });
    moveUp.addEventListener('click', () => moveRule(index, index - 1, rule.id));
    moveDown.addEventListener('click', () => moveRule(index, index + 1, rule.id));
    remove.addEventListener('click', () => {
      rules = rules.filter((candidate) => candidate.id !== rule.id);
      renderRules();
      markDirty();
    });
    rulesList.append(fragment);
  }
  if (focusRuleId !== undefined) {
    rulesList.querySelector<HTMLElement>(`[data-rule-id="${focusRuleId}"] .match-kind`)?.focus();
  }
}

function validateRules(): boolean {
  for (const item of Array.from(rulesList.querySelectorAll<HTMLLIElement>('.rule'))) {
    const kind = requireElement<HTMLSelectElement>(item, '.match-kind');
    const value = requireElement<HTMLInputElement>(item, '.match-value');
    const error = requireElement<HTMLElement>(item, '.field-error');
    if (kind.value !== 'reply' && value.value.trim().length === 0) {
      value.setAttribute('aria-invalid', 'true');
      error.hidden = false;
      value.focus();
      setStatus(message('shortcutRuleInvalid'));
      return false;
    }
  }
  return true;
}

function renderApplicationOptions(
  select: HTMLSelectElement,
  rule: NotificationShortcutRule,
): void {
  const all = document.createElement('option');
  all.value = '';
  all.textContent = message('shortcutAnyApplication');
  select.append(all);
  const options = [...applications];
  if (rule.sourceApplicationId !== undefined &&
      !options.some((candidate) => candidate.id === rule.sourceApplicationId)) {
    options.push({
      id: rule.sourceApplicationId,
      name: rule.sourceApplicationName ?? message('shortcutUnavailableApplication'),
    });
  }
  for (const application of options) {
    const option = document.createElement('option');
    option.value = application.id;
    option.textContent = application.name;
    select.append(option);
  }
  select.value = rule.sourceApplicationId ?? '';
}

function moveRule(from: number, to: number, id: string): void {
  if (from < 0 || from >= rules.length || to < 0 || to >= rules.length || from === to) return;
  const [moved] = rules.splice(from, 1);
  rules.splice(to, 0, moved);
  renderRules(id);
  markDirty();
}

function requireRule(id: string): NotificationShortcutRule {
  const found = rules.find((rule) => rule.id === id);
  if (found === undefined) throw new Error('Shortcut rule no longer exists');
  return found;
}

function clearFieldError(input: HTMLInputElement, error: HTMLElement): void {
  input.removeAttribute('aria-invalid');
  error.hidden = true;
}

function markDirty(): void {
  if (loaded) setStatus(message('shortcutUnsavedChanges'));
}

function setFormDisabled(disabled: boolean): void {
  for (const control of Array.from(form.elements)) {
    if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement ||
        control instanceof HTMLSelectElement) control.disabled = disabled;
  }
  if (!disabled) renderRules();
}

function requireDocumentElement<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`Missing shortcut element: ${id}`);
  return found as T;
}

function requireElement<T extends Element>(root: ParentNode, selector: string): T {
  const found = root.querySelector<T>(selector);
  if (found === null) throw new Error(`Missing ${selector}`);
  return found;
}

function randomId(): string {
  const value = crypto.getRandomValues(new Uint8Array(16));
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function setStatus(value: string): void {
  status.textContent = value;
}
