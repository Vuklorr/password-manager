export async function api(base, path, body, token, method) {
  const response = await fetch(`${base}/api${path}`, {
    method: method || (body === undefined ? 'GET' : 'POST'), credentials:'omit', cache:'no-store',
    headers:{...(body === undefined ? {} : {'Content-Type':'application/json'}), ...(token ? {Authorization:`Bearer ${token}`} : {})},
    body:body === undefined ? undefined : JSON.stringify(body), signal:AbortSignal.timeout(15000)
  });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(data.error || `Ошибка сервера (${response.status})`); error.status = response.status; throw error; }
  return data;
}
