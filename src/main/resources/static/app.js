import {api} from './lib/api.js';
import {deriveKeys, encryptEntry, decryptEntry, generatePassword, passwordEntropy, newSecret, randomSalt, normalizeEmail} from './lib/crypto.js';
import {trustedOrigin} from './lib/origin.js';

const $ = id => document.getElementById(id);
let registering = false, session = null, key = null, email = '', salt = '', entries = [], editing = null, recoverySecret = '';
let secretVerifier = null, pendingSecretAction = null, generatedAlphabet = null;
let idleTimer, expiryTimer, messageTimer;
function message(text, error = false) { $('message').textContent = text; $('message').className = error ? 'error' : ''; $('message').hidden = false; clearTimeout(messageTimer); messageTimer = setTimeout(() => $('message').hidden = true, 9000); }
function download(value, filename, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([value], {type})); const a = document.createElement('a'); a.href = url; a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function request(path, body, method) {
  try { return await api('', path, body, session?.token, method); }
  catch (error) { if (error.status === 401) await lock(); throw error; }
}
function activity() { if (!session) return; clearTimeout(idleTimer); idleTimer = setTimeout(() => lock(), 5 * 60 * 1000); }
for (const event of ['pointerdown','keydown']) document.addEventListener(event, activity, {passive:true});
async function lock() {
  const token = session?.token;
  session = null; key = null; entries = []; editing = null; recoverySecret = '';
  secretVerifier = null; closeSecretDialog(); resetEditor();
  clearTimeout(idleTimer); clearTimeout(expiryTimer);
  $('auth-form').reset(); $('recovery-key').textContent = ''; $('entries').replaceChildren(); $('search').value = '';
  for (const id of ['vault','editor','recovery','lock']) $(id).hidden = true;
  $('auth').hidden = $('welcome').hidden = false;
  if (token) await api('', '/auth/logout', {}, token).catch(() => {});
}
$('lock').onclick = () => lock();
function mode(register) {
  registering = register;
  $('login-tab').className = register ? 'secondary' : 'selected'; $('register-tab').className = register ? 'selected' : 'secondary';
  $('secret-label').hidden = register; $('secret').required = !register; $('confirm-label').hidden = !register; $('confirm-master').required = register;
  $('master').autocomplete = register ? 'new-password' : 'current-password';
  $('register-note').hidden = !register; $('auth-title').textContent = register ? 'Создать хранилище' : 'Открыть хранилище';
  $('auth-submit').textContent = register ? 'Создать хранилище →' : 'Открыть хранилище →';
}
$('login-tab').onclick = () => mode(false); $('register-tab').onclick = () => mode(true); mode(false);
$('auth-form').onsubmit = async event => {
  event.preventDefault(); $('auth-submit').disabled = true;
  const creating = registering;
  $('login-tab').disabled = $('register-tab').disabled = true;
  try {
    if (creating && $('master').value !== $('confirm-master').value) throw new Error('Мастер-пароли не совпадают.');
    email = normalizeEmail($('email').value);
    const secret = creating ? newSecret() : $('secret').value.trim();
    salt = creating ? randomSalt() : (await api('', '/auth/params', {email})).salt;
    const derived = await deriveKeys($('master').value, secret, salt, email);
    const verifier = await digestSecret(secret);
    session = await api('', creating ? '/auth/register' : '/auth/login', {email, authKey:derived.authKey, ...(creating ? {salt} : {})});
    key = derived.key; secretVerifier = verifier;
    $('auth-form').reset(); $('auth').hidden = $('welcome').hidden = true; $('lock').hidden = false;
    expiryTimer = setTimeout(() => lock(), Math.max(0, Date.parse(session.expiresAt) - Date.now())); activity();
    if (creating) {
      recoverySecret = secret; $('recovery-key').textContent = secret; $('key-saved').checked = false; $('continue').disabled = true; $('recovery').hidden = false;
    } else await openVault();
  } catch (error) { message(error.message, true); } finally { $('auth-submit').disabled = false; $('login-tab').disabled = $('register-tab').disabled = false; }
};
$('download-key').onclick = () => download(`GUARD — аварийный комплект\nEmail: ${email}\nСекретный ключ: ${recoverySecret}\n\nТакже нужен ваш мастер-пароль. Сервер не может восстановить эти секреты.\n`, 'guard-emergency-kit.txt', 'text/plain;charset=utf-8');
$('key-saved').onchange = () => $('continue').disabled = !$('key-saved').checked;
$('continue').onclick = async () => { recoverySecret = ''; $('recovery-key').textContent = ''; $('recovery').hidden = true; try { await openVault(); } catch (e) { message(e.message,true); } };
async function openVault() {
  const activeKey = key, activeSession = session;
  const encrypted = await request('/entries');
  const result = await Promise.all(encrypted.map(entry => decryptEntry(activeKey, email, entry)));
  if (session !== activeSession) return;
  entries = result; $('vault').hidden = false; render();
}
function button(text, action) { const node = document.createElement('button'); node.className = 'secondary'; node.textContent = text; node.onclick = () => Promise.resolve().then(action).catch(e => message(e.message,true)); return node; }
function render() {
  $('entries').replaceChildren(); $('count').textContent = entries.length;
  const query = $('search').value.toLowerCase();
  const visible = entries.filter(e => `${e.title} ${e.origin} ${e.login}`.toLowerCase().includes(query));
  $('empty').hidden = visible.length > 0; $('empty').querySelector('h2').textContent = entries.length ? 'Ничего не найдено' : 'Здесь будут ваши пароли';
  for (const entry of visible) {
    const card = document.createElement('article'); card.className = 'panel entry';
    const icon = document.createElement('div'); icon.className = 'entry-icon'; icon.textContent = entry.title[0]?.toUpperCase() || '◈';
    const title = document.createElement('h3'); title.textContent = entry.title;
    const origin = document.createElement('div'); origin.className = 'origin'; origin.textContent = entry.origin;
    const login = document.createElement('div'); login.className = 'login muted'; login.textContent = entry.login;
    const actions = document.createElement('div'); actions.className = 'actions';
    actions.append(button('Копировать логин', () => copy(entry.login)),
      button('Копировать пароль', () => askForSecret('Копировать пароль', () => copy(entry.password))),
      button('Изменить', () => edit(entry)), button('Удалить', async () => {
        if (!confirm(`Удалить «${entry.title}»?`)) return;
        await request(`/entries/${entry.id}`, undefined, 'DELETE'); await openVault();
      }));
    card.append(icon,title,origin,login,actions); $('entries').append(card);
  }
}
async function copy(value) { await navigator.clipboard.writeText(value); message('Скопировано. Буфер обмена доступен другим приложениям; очистите его после использования.'); }
async function digestSecret(secret) {
  const data = new TextEncoder().encode(secret.trim().toLowerCase());
  try { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); }
  finally { data.fill(0); }
}
function closeSecretDialog() {
  pendingSecretAction = null;
  $('secret-form').reset();
  $('secret-error').hidden = true;
  $('secret-submit').disabled = false;
  $('secret-dialog').close();
}
function askForSecret(title, action) {
  if (!secretVerifier || $('secret-dialog').open) return;
  pendingSecretAction = action;
  $('secret-dialog-title').textContent = title;
  $('secret-dialog').showModal();
}
$('secret-cancel').onclick = closeSecretDialog;
$('secret-dialog').oncancel = event => { event.preventDefault(); closeSecretDialog(); };
$('secret-form').onsubmit = async event => {
  event.preventDefault();
  const action = pendingSecretAction;
  if (!action) return;
  const secret = $('confirm-secret').value;
  $('secret-form').reset();
  $('secret-submit').disabled = true;
  $('secret-error').hidden = true;
  try {
    const digest = await digestSecret(secret);
    if (action !== pendingSecretAction) return;
    if (!digest.every((byte, i) => byte === secretVerifier[i])) throw new Error('Неверный секретный ключ.');
  } catch (error) {
    if (action !== pendingSecretAction) return;
    $('secret-error').textContent = error.message;
    $('secret-error').hidden = false;
    $('secret-submit').disabled = false;
    $('confirm-secret').focus();
    return;
  }
  closeSecretDialog();
  try { await action(); } catch (error) { message(error.message, true); }
};

$('search').oninput = render;
function setPasswordVisible(visible) {
  $('entry-password').type = visible ? 'text' : 'password';
  $('show-password').textContent = visible ? 'Скрыть пароль' : 'Показать пароль';
}
function resetEditor() {
  setPasswordVisible(false);
  $('entry-form').reset();
  generatedAlphabet = null;
  $('entropy').hidden = true;
}
function showEntropy() {
  const password = $('entry-password').value;
  if (!password) { message('Введите пароль для расчёта энтропии.', true); return; }
  const {length, alphabetSize, bits} = passwordEntropy(password, generatedAlphabet);
  const result = bits.toLocaleString('ru-RU', {minimumFractionDigits:2, maximumFractionDigits:2});
  $('entropy').textContent = `Энтропия по формуле L × log₂ A = ${length} × log₂ ${alphabetSize} = ${result} бит.` +
    (generatedAlphabet ? '' : ' Оценка для введённого пароля при случайном выборе символов.');
  $('entropy').hidden = false;
}
function generate() {
  const alphabet = $('alphabet').value;
  const password = generatePassword($('length').valueAsNumber, entries.map(e => e.password), alphabet);
  setPasswordVisible(false);
  $('entry-password').value = password;
  generatedAlphabet = alphabet;
  showEntropy();
}
function edit(entry) {
  editing = entry || null; resetEditor();
  $('editor-title').textContent = entry ? 'Изменить запись' : 'Новая запись';
  if (entry) {
    for (const [id, field] of [['title','title'],['site','origin'],['entry-login','login'],['entry-password','password'],['notes','notes']]) $(id).value = entry[field] || '';
    if ([...$('alphabet').options].some(option => option.value === entry.generatedAlphabet)) {
      generatedAlphabet = entry.generatedAlphabet;
      $('alphabet').value = generatedAlphabet;
      $('length').value = entry.password.length;
    }
  } else generate();
  $('vault').hidden = true; $('editor').hidden = false; $('title').focus();
}
$('add').onclick = () => { try { edit(); } catch (error) { message(error.message, true); } };
$('cancel').onclick = () => { resetEditor(); editing = null; $('editor').hidden = true; $('vault').hidden = false; };
$('show-password').onclick = () => {
  if ($('entry-password').type === 'text') setPasswordVisible(false);
  else askForSecret('Показать пароль', () => setPasswordVisible(true));
};
$('entry-password').oninput = () => { generatedAlphabet = null; $('entropy').hidden = true; };
$('generate').onclick = () => { try { generate(); } catch (error) { message(error.message, true); } };
$('calculate-entropy').onclick = showEntropy;
$('entry-form').onsubmit = async event => {
  event.preventDefault(); const submit = event.submitter; submit.disabled = true;
  try {
    const origin = trustedOrigin($('site').value);
    const password = $('entry-password').value;
    if (entries.some(e => e.id !== editing?.id && e.password === password)) throw new Error('Этот пароль уже есть в хранилище. Создайте уникальный.');
    const value = {title:$('title').value.trim(), origin, login:$('entry-login').value, password, notes:$('notes').value,
      ...(generatedAlphabet ? {generatedAlphabet} : {})};
    const id = editing?.id || crypto.randomUUID();
    const encrypted = await encryptEntry(key, email, id, value);
    await request(`/entries/${id}`, {...encrypted, revision:editing?.revision || 0}, 'PUT');
    resetEditor(); editing = null; $('editor').hidden = true; await openVault(); message('Запись зашифрована и сохранена.');
  } catch (error) { message(error.message,true); } finally { submit.disabled = false; }
};
$('export').onclick = async () => {
  try { const data = await request('/entries'); download(JSON.stringify({format:'guard-v1', email, salt, iterations:600000, entries:data},null,2), 'guard-encrypted-backup.json'); }
  catch(e) { message(e.message,true); }
};
// Best-effort revocation; server sessions also have an absolute 30-minute expiry.
window.addEventListener('pagehide', () => {
  if (session) fetch('/api/auth/logout', {method:'POST', headers:{Authorization:`Bearer ${session.token}`}, credentials:'omit', keepalive:true}).catch(() => {});
});
