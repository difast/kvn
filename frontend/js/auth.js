import { api, $, flash, bindPasswordToggle } from '/js/api.js';
if (api.isLoggedIn()) location.replace('/dashboard.html');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
let mode = location.hash === '#login' ? 'login' : 'register'; // registering is the default: the page's job is to onboard
bindPasswordToggle();

function setMode(m) {
  mode = m;
  $('#t-register').classList.toggle('on', m === 'register');
  $('#t-login').classList.toggle('on', m === 'login');
  $('#submit').textContent = m === 'register' ? 'Создать аккаунт' : 'Войти';
  $('#password').autocomplete = m === 'register' ? 'new-password' : 'current-password';
  $('#forgot').parentElement.hidden = m !== 'login';
  $('#meter').hidden = m !== 'register';
  $('#pw-hint').textContent = m === 'register' ? 'Не короче 8 символов. Лучше с цифрами и буквами разного регистра.' : '';
  $('#pw-hint').className = 'hint';
  $('#msg').className = 'msg';
  history.replaceState(null, '', `#${m}`);
}
$('#t-register').onclick = () => setMode('register');
$('#t-login').onclick = () => setMode('login');

function strength(pw) {
  let n = 0;
  if (pw.length >= 8) n++;
  if (pw.length >= 12) n++;
  if (/[a-zа-я]/.test(pw) && /[A-ZА-Я]/.test(pw)) n++;
  if (/\d/.test(pw)) n++;
  if (/[^\w\s]/.test(pw)) n++;
  return Math.min(n, 4);
}
$('#password').addEventListener('input', () => {
  const pw = $('#password').value, n = pw.length ? strength(pw) : 0;
  const bar = $('#meter i');
  bar.style.width = `${n * 25}%`;
  bar.style.background = ['var(--bad)', 'var(--bad)', 'var(--warn)', 'var(--ok)', 'var(--ok)'][n];
  $('#password').classList.remove('invalid');
  if (mode === 'register') { $('#pw-hint').textContent = 'Не короче 8 символов. Лучше с цифрами и буквами разного регистра.'; $('#pw-hint').className = 'hint'; }
});

function fieldError(input, hint, text) {
  input.classList.toggle('invalid', !!text);
  hint.textContent = text || '';
  hint.className = text ? 'hint err' : 'hint';
  return !text;
}
$('#email').addEventListener('blur', () => {
  const v = $('#email').value.trim();
  if (v) fieldError($('#email'), $('#email-hint'), EMAIL_RE.test(v) ? '' : 'Проверьте адрес: он должен выглядеть как name@example.com');
});
$('#email').addEventListener('input', () => fieldError($('#email'), $('#email-hint'), ''));

$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#email').value.trim(), password = $('#password').value;
  const okEmail = fieldError($('#email'), $('#email-hint'), EMAIL_RE.test(email) ? '' : 'Введите корректный email');
  const okPw = mode === 'login' ? !!password : fieldError($('#password'), $('#pw-hint'), password.length >= 8 ? '' : 'Пароль — минимум 8 символов');
  if (mode === 'login' && !password) fieldError($('#password'), $('#pw-hint'), 'Введите пароль');
  if (!okEmail || !okPw) return;

  const btn = $('#submit'), label = btn.textContent;
  btn.disabled = true; btn.textContent = 'Подождите…';
  try {
    await (mode === 'register' ? api.register(email, password) : api.login(email, password));
    location.href = '/dashboard.html';
  } catch (err) {
    if (err.code === 'email_taken') {
      flash($('#msg'), 'Этот email уже зарегистрирован. Нажмите «Вход», чтобы войти.', 'info');
    } else flash($('#msg'), err.message);
    btn.disabled = false; btn.textContent = label;
  }
});

$('#forgot').onclick = async (e) => {
  e.preventDefault();
  const email = $('#email').value.trim();
  if (!EMAIL_RE.test(email)) return fieldError($('#email'), $('#email-hint'), 'Введите email, на который отправить ссылку');
  try { await api.forgot(email); flash($('#msg'), 'Если такой аккаунт есть, мы отправили письмо со ссылкой для смены пароля.', 'ok'); }
  catch (err) { flash($('#msg'), err.message); }
};

setMode(mode);
$('#email').focus();
