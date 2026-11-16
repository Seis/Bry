const signForm = document.querySelector('#sign-form');
const verifyForm = document.querySelector('#verify-form');
const verifyGenerated = document.querySelector('#verify-generated');
let generatedSignature;
let downloadUrls = [];

function showMessage(id, text, error = false) {
  const element = document.querySelector(id);
  element.textContent = text;
  element.dataset.state = error ? 'error' : '';
}

async function request(path, data) {
  const response = await fetch(path, { method: 'POST', body: data });
  const text = await response.text();
  if (!response.ok) {
    let message = `Erro HTTP ${response.status}`;
    try { message = JSON.parse(text).detail || message; } catch { /* Non-JSON server response. */ }
    throw new Error(message);
  }
  return text;
}

function toBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

function setDownloads(encoded, name) {
  downloadUrls.forEach(url => URL.revokeObjectURL(url));
  const bytes = Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
  downloadUrls = [URL.createObjectURL(new Blob([bytes], { type: 'application/pkcs7-signature' })),
    URL.createObjectURL(new Blob([encoded], { type: 'text/plain' }))];
  const p7s = document.querySelector('#download-p7s');
  p7s.href = downloadUrls[0];
  p7s.download = `${name}.p7s`;
  const base64 = document.querySelector('#download-base64');
  base64.href = downloadUrls[1];
  base64.download = `${name}.base64`;
  document.querySelector('#downloads').hidden = false;
}

signForm.addEventListener('submit', async event => {
  event.preventDefault();
  const button = signForm.querySelector('button');
  button.disabled = true;
  generatedSignature = undefined;
  document.querySelector('#downloads').hidden = true;
  showMessage('#sign-message', 'Assinando…');
  try {
    const data = new FormData(signForm);
    generatedSignature = await request('/signature/', data);
    setDownloads(generatedSignature, data.get('document').name);
    showMessage('#sign-message', 'Assinatura gerada. Baixe o arquivo ou valide abaixo.');
  } catch (error) {
    showMessage('#sign-message', error.message, true);
  } finally {
    signForm.elements.password.value = '';
    button.disabled = false;
  }
});

function renderResult(result) {
  const heading = document.querySelector('#result-status');
  heading.textContent = result.status;
  heading.dataset.state = result.status === 'VALIDO' ? 'valid' : 'invalid';
  document.querySelector('#result-json').textContent = JSON.stringify(result, null, 2);
  document.querySelector('#result').hidden = false;
}

async function verify(encoded) {
  const button = verifyForm.querySelector('button');
  button.disabled = true;
  verifyGenerated.disabled = true;
  document.querySelector('#result').hidden = true;
  showMessage('#verify-message', 'Validando…');
  try {
    if (encoded.length > 10 * 1024 * 1024) throw new Error('A assinatura em Base64 deve ter até 10 MiB.');
    const data = new FormData();
    data.append('signature', new Blob([encoded], { type: 'text/plain' }), 'signature.base64');
    renderResult(JSON.parse(await request('/verify/', data)));
    showMessage('#verify-message', 'Verificação concluída.');
  } catch (error) {
    showMessage('#verify-message', error.message, true);
  } finally {
    button.disabled = false;
    verifyGenerated.disabled = false;
  }
}

verifyForm.addEventListener('submit', async event => {
  event.preventDefault();
  document.querySelector('#result').hidden = true;
  try {
    const file = verifyForm.elements.signature.files[0];
    if (file.size > 10 * 1024 * 1024) throw new Error('A assinatura deve ter até 10 MiB.');
    const bytes = new Uint8Array(await file.arrayBuffer());
    // DER/BER CMS starts with an ASN.1 SEQUENCE; the API itself accepts Base64.
    const encoded = bytes[0] === 0x30 ? toBase64(bytes) : new TextDecoder('utf-8').decode(bytes);
    await verify(encoded);
  } catch (error) {
    showMessage('#verify-message', error.message, true);
  }
});

verifyGenerated.addEventListener('click', () => {
  if (generatedSignature) verify(generatedSignature);
});
