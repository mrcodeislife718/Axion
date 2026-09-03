const $ = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { 'content-type': 'application/json', ...(options.headers ?? {}) }, ...options });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? 'request failed');
  return payload;
}

function text(value) { return document.createTextNode(String(value ?? '')); }
function row(label, value) { const p = document.createElement('p'); const strong = document.createElement('strong'); strong.append(text(label)); p.append(strong, text(` ${value ?? ''}`)); return p; }

function identityCard(identity) {
  const card = document.createElement('div'); card.className = 'card';
  card.append(row('ID', identity.id), row('Publisher', identity.publisher), row('Type', identity.type), row('Version', identity.currentVersion), row('Status', identity.status));
  const controls = document.createElement('div'); controls.className = 'actions';
  for (const status of ['active','superseded','revoked','retired']) {
    if (identity.status === status) continue;
    const button = document.createElement('button'); button.type = 'button'; button.textContent = status;
    button.addEventListener('click', async () => { await api(`/api/identities/${encodeURIComponent(identity.id)}/lifecycle`, { method: 'POST', body: JSON.stringify({ status }) }); await refresh(); });
    controls.append(button);
  }
  card.append(controls); return card;
}

function credentialCard(credential) {
  const card = document.createElement('div'); card.className = 'card';
  card.append(row('Credential', credential.credentialId), row('Subject', credential.subjectId), row('Issuer', credential.issuerId), row('Status', credential.status));
  const verify = document.createElement('button'); verify.type = 'button'; verify.textContent = 'Verify';
  verify.addEventListener('click', async () => { const result = await api(`/api/credentials/${encodeURIComponent(credential.credentialId)}/verify`); alert(result.verified ? 'Credential verified' : `Verification failed: ${result.reason}`); });
  const revoke = document.createElement('button'); revoke.type = 'button'; revoke.textContent = 'Revoke';
  revoke.addEventListener('click', async () => { const reason = prompt('Revocation reason'); if (!reason) return; await api(`/api/credentials/${encodeURIComponent(credential.credentialId)}/revoke`, { method: 'POST', body: JSON.stringify({ reason, revokedBy: 'axion:operator:console' }) }); await refresh(); });
  const actions = document.createElement('div'); actions.className = 'actions'; actions.append(verify, revoke); card.append(actions); return card;
}

async function refresh() {
  const dashboard = await api('/api/dashboard');
  const metrics = $('#metrics'); metrics.replaceChildren();
  for (const [label, value] of Object.entries({ Identities: dashboard.systems?.length ?? 0, Credentials: dashboard.credentials?.length ?? 0, Audit: dashboard.audit?.length ?? 0 })) {
    const card = document.createElement('article'); card.className = 'metric'; const h = document.createElement('strong'); h.textContent = value; const p = document.createElement('span'); p.textContent = label; card.append(h,p); metrics.append(card);
  }
  const identities = $('#identities'); identities.replaceChildren(...(dashboard.systems ?? []).map(identityCard));
  const credentials = $('#credentials'); credentials.replaceChildren(...(dashboard.credentials ?? []).map(credentialCard));
  const audit = $('#audit'); audit.replaceChildren(...(dashboard.audit ?? []).slice().reverse().map((event) => { const item = document.createElement('div'); item.className = 'audit'; item.append(row(event.type, `${event.identityId ?? ''} · ${event.at}`)); return item; }));
}

$('#identity-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget));
  const manifest = { axion_version: '1.0', identity: { id: data.id, name: data.name, version: data.version, publisher: data.publisher, type: data.type }, capabilities: data.capabilities.split(',').map(x => x.trim()).filter(Boolean), permissions: [] };
  await api('/api/identities', { method: 'POST', body: JSON.stringify(manifest) }); event.currentTarget.reset(); await refresh();
});

$('#credential-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget));
  await api('/api/credentials', { method: 'POST', body: JSON.stringify({ subjectId: data.subjectId, issuerId: data.issuerId, claims: { [data.claim]: data.value }, evidence: [{ type: 'operator-console', at: new Date().toISOString() }] }) });
  event.currentTarget.reset(); await refresh();
});

$('#refresh').addEventListener('click', refresh);
refresh().catch((error) => { document.body.dataset.error = error.message; console.error(error); });
