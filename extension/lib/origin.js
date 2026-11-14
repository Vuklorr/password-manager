export const DOMAIN_ERROR = 'Данный домен не соответствует сохранённому, ОШИБКА';
export function trustedOrigin(value) {
  if (typeof value !== 'string' || value !== value.trim() || /[\\\s]/u.test(value)) throw new Error('Введите полный HTTPS-адрес без пробелов.');
  const authority = value.match(/^https:\/\/([^/?#]+)/i)?.[1];
  if (!authority || /[^\x21-\x7e]|[%@]/u.test(authority)) throw new Error('Разрешены только обычные ASCII-домены без userinfo.');
  let url;
  try { url = new URL(value); } catch { throw new Error('Неверный адрес сайта.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hostname.endsWith('.') ||
      url.hostname.split('.').some(part => part.startsWith('xn--')) || !/^[a-z0-9.-]+$/.test(url.hostname) ||
      !url.hostname.includes('.') || url.hostname.split('.').some(part => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)))
    throw new Error('Нужен HTTPS-домен. IDN/Punycode и неоднозначные адреса заблокированы.');
  return url.origin;
}
export function assertMatch(saved, actual) {
  try { if (trustedOrigin(saved) === trustedOrigin(actual)) return true; } catch { /* fail closed */ }
  throw new Error(DOMAIN_ERROR);
}
