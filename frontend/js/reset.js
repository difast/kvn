import { api, $, flash, bindPasswordToggle } from '/js/api.js';
bindPasswordToggle();
const token = new URLSearchParams(location.hash.slice(1)).get('token');
$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('#password').value;
  if (!token) return flash($('#msg'), 'Ссылка недействительна или устарела');
  if (password.length < 8) return flash($('#msg'), 'Пароль — минимум 8 символов');
  try { await api.reset(token, password); flash($('#msg'), 'Пароль обновлён. Перенаправляем…', 'ok'); setTimeout(() => (location.href = '/auth.html'), 1200); }
  catch (err) { flash($('#msg'), err.message); }
});
