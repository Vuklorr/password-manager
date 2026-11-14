import {api} from './lib/api.js';
import {deriveKeys, decryptEntry, b64, unb64, normalizeEmail} from './lib/crypto.js';
import {trustedOrigin, assertMatch} from './lib/origin.js';

const BASE = 'http://localhost:8080'; // Production: HTTPS URL + matching host_permissions.
const IDLE = 5 * 60 * 1000;
const storageReady = chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
let epoch = 0;
async function lock() {
  epoch++;
  const {vault} = await chrome.storage.session.get('vault');
  await chrome.storage.session.remove('vault');
  await chrome.action.setBadgeText({text:''});
  await chrome.alarms.clear('lock');
  if (vault) await api(BASE, '/auth/logout', {}, vault.token).catch(() => {});
}
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'lock') lock(); });
async function state(touch = false) {
  await storageReady;
  const {vault} = await chrome.storage.session.get('vault');
  if (!vault || Date.now() >= vault.until || Date.now() >= Date.parse(vault.expiresAt)) {
    if (vault) await lock();
    throw new Error('Сеанс завершён. Войдите в расширении.');
  }
  if (touch) {
    vault.until = Math.min(Date.now() + IDLE, Date.parse(vault.expiresAt));
    await chrome.storage.session.set({vault});
    await chrome.alarms.create('lock', {when:vault.until});
  }
  return vault;
}
async function readEntries(vault) {
  const encrypted = await api(BASE, '/entries', undefined, vault.token);
  const key = await crypto.subtle.importKey('raw', unb64(vault.key), 'AES-GCM', false, ['decrypt']);
  return Promise.all(encrypted.map(entry => decryptEntry(key, vault.email, entry)));
}
async function checkedTab(tabId, origin) {
  const tab = await chrome.tabs.get(tabId);
  assertMatch(origin, tab.url);
  if (tab.pendingUrl) assertMatch(origin, tab.pendingUrl);
  return tab;
}
async function handle(message, sender) {
  await storageReady;
  if (sender.id !== chrome.runtime.id) throw new Error('Недоверенный отправитель.');
  if (sender.tab) {
    if (sender.frameId !== 0 || !['suggest','fill'].includes(message.type)) throw new Error('Операция запрещена.');
    const origin = trustedOrigin(sender.url);
    const vault = await state(message.type === 'fill');
    await checkedTab(sender.tab.id, origin);
    const entries = await readEntries(vault);
    if (message.type === 'suggest') {
      const matches = entries.filter(e => { try { return assertMatch(e.origin, origin); } catch { return false; } });
      await chrome.action.setBadgeText({tabId:sender.tab.id, text:matches.length ? String(matches.length) : ''});
      return matches.map(e => ({id:e.id, title:e.title}));
    }
    const entry = entries.find(e => e.id === message.id);
    if (!entry) throw new Error('Запись не найдена.');
    assertMatch(entry.origin, origin);
    await checkedTab(sender.tab.id, origin);
    await state();
    return {origin, login:entry.login, password:entry.password};
  }
  if (sender.url !== chrome.runtime.getURL('popup.html')) throw new Error('Операция разрешена только в окне расширения.');
  if (message.type === 'unlock') {
    const attempt = ++epoch;
    const email = normalizeEmail(message.email);
    const {salt} = await api(BASE, '/auth/params', {email});
    const keys = await deriveKeys(message.master, message.secret.trim(), salt, email, true);
    const session = await api(BASE, '/auth/login', {email, authKey:keys.authKey});
    if (attempt !== epoch) { await api(BASE, '/auth/logout', {}, session.token).catch(() => {}); throw new Error('Вход отменён.'); }
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.key));
    const vault = {...session, email, key:b64(raw), until:Math.min(Date.now()+IDLE, Date.parse(session.expiresAt))};
    raw.fill(0);
    await chrome.storage.session.set({vault});
    await chrome.alarms.create('lock', {when:vault.until});
    return true;
  }
  if (message.type === 'lock') { await lock(); return true; }
  const vault = await state(message.type === 'manual-fill');
  if (message.type === 'list') {
    return (await readEntries(vault)).map(e => ({id:e.id, title:e.title, origin:e.origin, login:e.login}));
  }
  if (message.type === 'manual-fill') {
    const [tab] = await chrome.tabs.query({active:true, currentWindow:true});
    if (!tab?.id) throw new Error('Нет активной вкладки.');
    const entry = (await readEntries(vault)).find(e => e.id === message.id);
    if (!entry) throw new Error('Запись не найдена.');
    await checkedTab(tab.id, entry.origin);
    await state();
    const result = await chrome.tabs.sendMessage(tab.id, {type:'guard-fill', origin:entry.origin, login:entry.login, password:entry.password}, {frameId:0});
    if (!result?.ok) throw new Error(result?.error || 'Не найдена безопасная форма входа.');
    return true;
  }
  throw new Error('Неизвестная команда.');
}
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  handle(message, sender).then(data => reply({ok:true,data})).catch(error => reply({ok:false,error:error.message}));
  return true;
});
