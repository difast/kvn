import { api, $, flash } from '/js/api.js';
if (api.isLoggedIn()) location.replace('/dashboard.html');

let mode = location.hash === '#register' ? 'register' : 'login';
function render() {
  $('#t-register').classList.toggle('on', mode === 'register');
  $('#t-login').classList.toggle('on', mode === 'login');
  $('#submit').textContent = mode === 'register' ? 'Создать аккаунт' : 'Войти';
  $('#password').autocomplete = mode === 'register' ? 'new-password' : 'current-password';
  $('#forgot').style.display = mode === 'login' ? '' : 'none';
  $('#msg').className = 'msg';
}
$('#t-register').onclick = () => { mode = 'register'; render(); };
$('#t-login').onclick = () => { mode = 'login'; render(); };
render();

$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#email').value.trim(), password = $('#password').value;
  if (!email || !email.includes('@')) return flash($('#msg'), 'Введите корректный email');
  if (mode === 'register' && password.length < 8) return flash($('#msg'), 'Пароль — минимум 8 символов');
  $('#submit').disabled = true;
  try {
    await (mode === 'register' ? api.register(email, password) : api.login(email, password));
    location.href = '/dashboard.html';
  } catch (err) { flash($('#msg'), err.message); }
  finally { $('#submit').disabled = false; }
});

$('#forgot').onclick = async (e) => {
  e.preventDefault();
  const email = $('#email').value.trim();
  if (!email) return flash($('#msg'), 'Введите email выше');
  try { await api.forgot(email); flash($('#msg'), 'Если такой аккаунт есть, мы отправили письмо со ссылкой', 'ok'); }
  catch (err) { flash($('#msg'), err.message); }
};
