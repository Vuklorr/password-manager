(() => {
  if (window.top !== window || location.protocol !== 'https:') return;
  const DOMAIN_ERROR = 'Данный домен не соответствует сохранённому, ОШИБКА';
  let suggestionHost;
  function safeForm() {
    const passwords = [...document.querySelectorAll('input[type="password"]')].filter(input => !input.disabled && !input.readOnly && input.getClientRects().length);
    // Explicit username-only and password-only steps are supported; ambiguous forms fail closed.
    if (passwords.length > 1) throw new Error('На странице несколько полей пароля. Выберите обычную форму входа.');
    const password = passwords[0];
    if (password?.autocomplete === 'new-password') throw new Error('Автозаполнение формы регистрации запрещено.');
    const usernames = [...document.querySelectorAll('input[autocomplete="username"]')].filter(input => !input.disabled && !input.readOnly && input.getClientRects().length && ['email','text'].includes(input.type));
    const form = password?.form || (usernames.length === 1 ? usernames[0].form : null);
    if (!form || form.method.toLowerCase() !== 'post') throw new Error('Нужна форма входа с методом POST.');
    const controls = [...form.elements];
    if (controls.some(el => el.hasAttribute('formmethod') && el.formMethod.toLowerCase() !== 'post')) throw new Error('Небезопасный метод отправки формы.');
    const actions = [form.action, ...controls.filter(el => el.hasAttribute('formaction')).map(el => el.formAction)];
    for (const action of actions) {
      const target = new URL(action, location.href);
      if (target.protocol !== 'https:' || target.origin !== location.origin || target.username || target.password) throw new Error(DOMAIN_ERROR);
    }
    const fields = [...form.querySelectorAll('input')].filter(input => !input.disabled && !input.readOnly && input.getClientRects().length && ['email','text'].includes(input.type));
    const login = fields.find(input => input.autocomplete === 'username') || fields.find(input => input.type === 'email') || fields.at(-1);
    if (!password && (!login || login.autocomplete !== 'username')) throw new Error('Не найдена однозначная форма входа.');
    return {form, login, password};
  }
  function fill(data) {
    if (location.origin !== data.origin || location.protocol !== 'https:') throw new Error(DOMAIN_ERROR);
    const {login,password} = safeForm();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
    if (login) setter.call(login, data.login);
    if (password) setter.call(password, data.password);
    for (const field of [login,password].filter(Boolean)) {
      field.dispatchEvent(new Event('input',{bubbles:true})); field.dispatchEvent(new Event('change',{bubbles:true}));
    }
    suggestionHost?.remove(); // Never submit the form automatically.
  }
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id || message.type !== 'guard-fill') return;
    try { fill(message); reply({ok:true}); } catch(error) { reply({ok:false,error:error.message}); }
  });
  async function suggest() {
    if (suggestionHost?.isConnected) return;
    let form;
    try { form = safeForm().form; } catch { return; }
    let response;
    try { response = await chrome.runtime.sendMessage({type:'suggest'}); } catch { return; }
    if (!response?.ok || !response.data.length) return;
    suggestionHost = document.createElement('div');
    const shadow = suggestionHost.attachShadow({mode:'closed'});
    const status = document.createElement('span');
    for (const entry of response.data) {
      const button = document.createElement('button'); button.type = 'button';
      button.textContent = `◈ Guard: заполнить «${entry.title}»`;
      button.style.cssText = 'background:#126849;color:white;border:0;border-radius:8px;padding:10px 14px;margin:8px;font:13px system-ui;cursor:pointer';
      button.onclick = async event => {
        if (!event.isTrusted) return;
        button.disabled = true;
        try {
          safeForm();
          const result = await chrome.runtime.sendMessage({type:'fill',id:entry.id});
          if (!result?.ok) throw new Error(result?.error || 'Хранилище недоступно.');
          fill(result.data);
        } catch(error) { status.textContent = error.message; } finally { button.disabled = false; }
      };
      shadow.append(button);
    }
    shadow.append(status); form.after(suggestionHost);
  }
  let timer;
  new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(suggest, 700); }).observe(document.documentElement,{childList:true,subtree:true});
  document.addEventListener('focusin', () => { clearTimeout(timer); timer = setTimeout(suggest, 150); });
  suggest();
})();
