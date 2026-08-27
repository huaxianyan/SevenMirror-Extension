import { localizeDocument, message } from '../shared/i18n';
import type {
  NotificationShortcutPreferences,
  NotificationShortcutRule,
} from '../background/notification-shortcuts';

interface ApplicationOption {
  id: string;
  name: string;
}

const pinDismiss = document.querySelector<HTMLInputElement>('#pin-dismiss');
const rulesList = document.querySelector<HTMLOListElement>('#rules');
const emptyRules = document.querySelector<HTMLElement>('#empty-rules');
const addRule = document.querySelector<HTMLButtonElement>('#add-rule');
const save = document.querySelector<HTMLButtonElement>('#save');
const status = document.querySelector<HTMLElement>('#status');
const template = document.querySelector<HTMLTemplateElement>('#rule-template');
let rules: NotificationShortcutRule[] = [];
let applications: ApplicationOption[] = [];
let draggedRuleId: string | undefined;

localizeDocument();
void load();

addRule?.addEventListener('click', () => {
  rules.push({ id: randomId(), match: { kind: 'reply' } });
  renderRules();
});

save?.addEventListener('click', () => {
  if (!pinDismiss || !save) return;
  save.disabled = true;
  setStatus(message('shortcutSaving'));
  void chrome.runtime.sendMessage({
    type: 'save-notification-shortcut-settings',
    preferences: { pinDismiss: pinDismiss.checked, rules },
  }).then((response: { saved?: boolean } | undefined) => {
    setStatus(response?.saved ? message('shortcutSaved') : message('shortcutSaveFailed'));
  }).catch(() => setStatus(message('shortcutSaveFailed')))
    .finally(() => { save.disabled = false; });
});

async function load(): Promise<void> {
  const response = await chrome.runtime.sendMessage({
    type: 'get-notification-shortcut-settings',
  }) as {
    preferences: NotificationShortcutPreferences;
    applications: ApplicationOption[];
  } | undefined;
  if (response === undefined || !pinDismiss) {
    setStatus(message('shortcutLoadFailed'));
    return;
  }
  pinDismiss.checked = response.preferences.pinDismiss;
  rules = response.preferences.rules;
  applications = response.applications;
  renderRules();
}

function renderRules(): void {
  if (!rulesList || !template || !emptyRules) return;
  rulesList.replaceChildren();
  emptyRules.hidden = rules.length !== 0;
  for (const [index, rule] of rules.entries()) {
    const fragment = template.content.cloneNode(true) as DocumentFragment;
    localizeDocument(fragment);
    const item = requireElement<HTMLLIElement>(fragment, '.rule');
    item.dataset.ruleId = rule.id;
    const kind = requireElement<HTMLSelectElement>(fragment, '.match-kind');
    const titleField = requireElement<HTMLElement>(fragment, '.title-field');
    const value = requireElement<HTMLInputElement>(fragment, '.match-value');
    const application = requireElement<HTMLSelectElement>(fragment, '.application');
    const moveUp = requireElement<HTMLButtonElement>(fragment, '.move-up');
    const moveDown = requireElement<HTMLButtonElement>(fragment, '.move-down');
    const remove = requireElement<HTMLButtonElement>(fragment, '.remove');

    kind.value = rule.match.kind;
    value.value = rule.match.kind === 'reply' ? '' : rule.match.value;
    titleField.hidden = rule.match.kind === 'reply';
    renderApplicationOptions(application, rule);
    moveUp.disabled = index === 0;
    moveDown.disabled = index === rules.length - 1;

    kind.addEventListener('change', () => {
      const current = requireRule(rule.id);
      current.match = kind.value === 'reply'
        ? { kind: 'reply' }
        : { kind: kind.value as 'title-exact' | 'title-contains', value: value.value };
      titleField.hidden = kind.value === 'reply';
    });
    value.addEventListener('input', () => {
      const current = requireRule(rule.id);
      if (current.match.kind !== 'reply') current.match.value = value.value;
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
    });
    moveUp.addEventListener('click', () => moveRule(index, index - 1));
    moveDown.addEventListener('click', () => moveRule(index, index + 1));
    remove.addEventListener('click', () => {
      rules = rules.filter((candidate) => candidate.id !== rule.id);
      renderRules();
    });
    item.addEventListener('dragstart', () => { draggedRuleId = rule.id; });
    item.addEventListener('dragend', () => { draggedRuleId = undefined; });
    item.addEventListener('dragover', (event) => event.preventDefault());
    item.addEventListener('drop', (event) => {
      event.preventDefault();
      if (draggedRuleId === undefined || draggedRuleId === rule.id) return;
      const from = rules.findIndex((candidate) => candidate.id === draggedRuleId);
      const to = rules.findIndex((candidate) => candidate.id === rule.id);
      if (from >= 0 && to >= 0) moveRule(from, to);
    });
    rulesList.append(fragment);
  }
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

function moveRule(from: number, to: number): void {
  if (from < 0 || from >= rules.length || to < 0 || to >= rules.length || from === to) return;
  const [moved] = rules.splice(from, 1);
  rules.splice(to, 0, moved);
  renderRules();
}

function requireRule(id: string): NotificationShortcutRule {
  const found = rules.find((rule) => rule.id === id);
  if (found === undefined) throw new Error('Shortcut rule no longer exists');
  return found;
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
  if (status) status.textContent = value;
}
