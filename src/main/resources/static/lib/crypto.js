const encoder = new TextEncoder();
export const ITERATIONS = 600000;
export const normalizeEmail = value => value.trim().toLowerCase();
export const b64 = bytes => btoa(String.fromCharCode(...bytes));
export const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
export const randomSalt = () => b64(crypto.getRandomValues(new Uint8Array(32)));
export const newSecret = () => [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('');

export async function deriveKeys(master, secret, salt, email, extractable = false) {
  if (master.length < 14 || master.length > 1024) throw new Error('Мастер-пароль: от 14 до 1024 символов. Лучше длинная фраза.');
  if (!/^[a-f0-9]{64}$/i.test(secret)) throw new Error('Секретный ключ должен содержать 64 шестнадцатеричных символа.');
  const saltBytes = unb64(salt);
  if (saltBytes.length !== 32) throw new Error('Неверная соль аккаунта.');
  const material = await crypto.subtle.importKey('raw', encoder.encode(master), 'PBKDF2', false, ['deriveBits']);
  const root = new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2', salt:saltBytes, iterations:ITERATIONS, hash:'SHA-256'}, material, 256));
  const hkdf = await crypto.subtle.importKey('raw', root, 'HKDF', false, ['deriveBits', 'deriveKey']);
  root.fill(0);
  const secretBytes = Uint8Array.from(secret.match(/../g), hex => parseInt(hex, 16));
  const params = label => ({name:'HKDF', hash:'SHA-256', salt:secretBytes, info:encoder.encode(`guard:v1:${label}:${normalizeEmail(email)}`)});
  const key = await crypto.subtle.deriveKey(params('vault'), hkdf, {name:'AES-GCM', length:256}, extractable, ['encrypt','decrypt']);
  const authBytes = new Uint8Array(await crypto.subtle.deriveBits(params('auth'), hkdf, 256));
  const authKey = b64(authBytes);
  authBytes.fill(0); secretBytes.fill(0);
  return {key, authKey};
}
const aad = (email, id) => encoder.encode(`guard:v1:${normalizeEmail(email)}:${id}`);
export async function encryptEntry(key, email, id, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:aad(email,id), tagLength:128}, key, encoder.encode(JSON.stringify(value)));
  return {iv:b64(iv), ciphertext:b64(new Uint8Array(ciphertext))};
}
export async function decryptEntry(key, email, entry) {
  const plaintext = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(entry.iv), additionalData:aad(email,entry.id), tagLength:128}, key, unb64(entry.ciphertext));
  const value = JSON.parse(new TextDecoder().decode(plaintext));
  if (!value || typeof value.title !== 'string' || typeof value.origin !== 'string' || typeof value.login !== 'string' || typeof value.password !== 'string')
    throw new Error('Повреждён формат записи.');
  return {...value, id:entry.id, revision:entry.revision};
}
const DIGITS = '0123456789';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ASCII = Array.from({length:95}, (_, i) => String.fromCharCode(32 + i)).join('');
const ALPHANUMERIC = DIGITS + LOWERCASE + UPPERCASE;
const SYMBOLS = [...ASCII].filter(character => !ALPHANUMERIC.includes(character)).join('');
const ALPHABETS = {digits:DIGITS, lowercase:LOWERCASE, alphanumeric:ALPHANUMERIC, ascii:ASCII};

export function passwordEntropy(password, alphabetId) {
  const characters = new Set(password);
  const alphabet = Object.hasOwn(ALPHABETS, alphabetId) ? ALPHABETS[alphabetId] : '';
  let alphabetSize = alphabet.length;
  if (!alphabet || [...characters].some(character => !alphabet.includes(character))) {
    alphabetSize = [DIGITS, LOWERCASE, UPPERCASE, SYMBOLS]
      .filter(group => [...group].some(character => characters.has(character)))
      .reduce((size, group) => size + group.length, 0);
    alphabetSize += [...characters].filter(character => !ASCII.includes(character)).length;
  }
  const length = [...password].length;
  return {length, alphabetSize, bits: length === 0 ? 0 : length * Math.log2(alphabetSize)};
}

function randomIndex(max) {
  const limit = 256 - (256 % max);
  let value;
  do { value = crypto.getRandomValues(new Uint8Array(1))[0]; } while (value >= limit);
  return value % max;
}
export function generatePassword(length = 24, used = [], alphabetId = 'ascii') {
  if (!Number.isInteger(length) || length < 6 || length > 128) throw new Error('Введите целую длину от 6 до 128 символов.');
  if (!Object.hasOwn(ALPHABETS, alphabetId)) throw new Error('Выберите алфавит пароля.');
  const alphabet = ALPHABETS[alphabetId];
  const existing = new Set(used);
  for (let attempt = 0; attempt < 10000; attempt++) {
    const password = Array.from({length}, () => alphabet[randomIndex(alphabet.length)]).join('');
    if (!existing.has(password)) return password;
  }
  throw new Error('Не удалось сгенерировать уникальный пароль.');
}
