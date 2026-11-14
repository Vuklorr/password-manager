const $ = id => document.getElementById(id);
async function send(message) { const result = await chrome.runtime.sendMessage(message); if (!result?.ok) throw new Error(result?.error || 'Расширение недоступно.'); return result.data; }
async function list() {
  const entries = await send({type:'list'});
  $('unlock').hidden = true; $('vault').hidden = false; $('lock').hidden = false; $('entries').replaceChildren();
  const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
  try { $('current').textContent = `Текущий сайт: ${new URL(tab.url).origin}`; } catch { $('current').textContent = 'Текущий сайт недоступен'; }
  if (!entries.length) $('entries').textContent = 'Добавьте запись в веб-приложении.';
  for (const entry of entries) {
    const card = document.createElement('div'); card.className = 'entry';
    const title = document.createElement('b'); title.textContent = entry.title;
    const origin = document.createElement('small'); origin.textContent = entry.origin;
    const login = document.createElement('small'); login.textContent = entry.login;
    const button = document.createElement('button'); button.textContent = 'Заполнить на этой вкладке';
    button.onclick = async () => { button.disabled = true; try { await send({type:'manual-fill',id:entry.id}); $('status').textContent = 'Заполнено. Проверьте форму перед отправкой.'; } catch(e) { $('status').textContent = e.message; } finally { button.disabled = false; } };
    card.append(title,origin,login,button); $('entries').append(card);
  }
}
$('unlock').onsubmit = async event => {
  event.preventDefault(); $('submit').disabled = true; $('status').textContent = '';
  try { await send({type:'unlock',email:$('email').value,master:$('master').value,secret:$('secret').value}); $('unlock').reset(); await list(); }
  catch(e) { $('status').textContent = e.message; } finally { $('submit').disabled = false; }
};
$('lock').onclick = async () => { await send({type:'lock'}); $('entries').replaceChildren(); $('vault').hidden = $('lock').hidden = true; $('unlock').hidden = false; $('status').textContent = ''; };
list().catch(() => {});
