'use strict';
const form = document.querySelector('#login');
const err = document.querySelector('#err');
const btn = document.querySelector('#submit');
const pw = document.querySelector('#password');
const peek = document.querySelector('#peek');

// show / hide password
peek.addEventListener('click', () => {
  const show = pw.type === 'password';
  pw.type = show ? 'text' : 'password';
  peek.setAttribute('aria-pressed', String(show));
  peek.setAttribute('aria-label', show ? 'hide password' : 'show password');
});

function fail(msg) {
  err.textContent = msg;
  err.classList.remove('shake');
  void err.offsetWidth;              // restart the shake animation
  err.classList.add('shake');
  pw.value = '';
  pw.focus();
}

form.addEventListener('submit', async e => {
  e.preventDefault();
  err.textContent = '';
  const data = new FormData(form);
  const username = String(data.get('username') || '').trim();
  const password = String(data.get('password') || '');
  if (!username || !password) return fail('enter your username and password');

  btn.disabled = true;
  btn.classList.add('busy');
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({username, password}),
    });
    if (r.ok) { location.replace('/'); return; }
    const j = await r.json().catch(() => ({}));
    fail(j.error || ('sign in failed (HTTP ' + r.status + ')'));
  } catch (_) {
    fail('could not reach CTFWarden');
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
  }
});
