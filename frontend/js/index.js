import { api } from '/js/api.js';
if (api.isLoggedIn()) { const n = document.getElementById('nav'); n.textContent = 'Личный кабинет'; n.href = '/dashboard.html'; }
