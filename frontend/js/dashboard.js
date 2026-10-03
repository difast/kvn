import { api, $, flash, fmtDate } from '/js/api.js';
if (!api.isLoggedIn()) location.replace('/auth.html');

const LABEL = { active: 'Активна', expired: 'Истекла', none: 'Нет', revoked: 'Отозвана' };
let profile = null, confText = null;
const badge = (el, st, label) => { el.textContent = label || LABEL[st]; el.className = `badge ${st}`; };
const err = (e) => flash($('#msg'), e.message);

async function load() {
  try {
    const [me, { profiles }] = await Promise.all([api.me(), api.profiles()]);
    $('#who').textContent = me.user.email;
    const sub = me.subscription;
    badge($('#sub-status'), sub.status);
    $('#sub-end').textContent = sub.expiresAt ? fmtDate(sub.expiresAt) : '—';
    $('#pay').textContent = sub.active ? 'Продлить на 30 дней — 500 ₽' : 'Оплатить 500 ₽';

    profile = profiles.find((p) => p.status !== 'revoked') || null;
    if (profile) badge($('#vpn-status'), profile.status);
    else badge($('#vpn-status'), 'none', 'Не создан');
    $('#vpn-server').textContent = profile ? `${profile.server.name} (${profile.server.region})` : (me.vpnServers[0] ? `${me.vpnServers[0].name} (${me.vpnServers[0].region})` : 'Нет серверов');
    $('#vpn-addr').textContent = profile ? profile.address : '—';
    $('#get').textContent = profile ? 'Показать конфигурацию' : 'Получить VPN';
    $('#get').disabled = !sub.active;
    $('#get').title = sub.active ? '' : 'Сначала оплатите подписку';
  } catch (e) { if (e.status === 401) location.replace('/auth.html'); else err(e); }
}

$('#pay').onclick = async () => {
  $('#pay').disabled = true;
  try {
    const r = await api.pay('monthly');
    if (r.redirectUrl) return (location.href = r.redirectUrl); // real providers: hosted payment page
    flash($('#msg'), 'Оплата прошла успешно, подписка активна', 'ok');
    await load();
  } catch (e) { err(e); } finally { $('#pay').disabled = false; }
};

$('#get').onclick = async () => {
  try {
    if (!profile) profile = (await api.createProfile('Мое устройство')).profile;
    confText = await api.config(profile.id);
    await load();
    $('#conf').textContent = confText;
    $('#conf-card').hidden = false;
    $('#conf-card').scrollIntoView({ behavior: 'smooth' });
  } catch (e) { err(e); }
};

$('#download').onclick = () => {
  const url = URL.createObjectURL(new Blob([confText], { type: 'text/plain' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: `kvn-${profile.id}.conf` });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
};

$('#copy').onclick = async () => {
  try { await navigator.clipboard.writeText(confText); flash($('#msg'), 'Конфигурация скопирована', 'ok'); }
  catch { const r = document.createRange(); r.selectNodeContents($('#conf')); getSelection().removeAllRanges(); getSelection().addRange(r); flash($('#msg'), 'Выделено — нажмите «Копировать» в системном меню', 'ok'); }
};

$('#revoke').onclick = async () => {
  if (!confirm('Отозвать конфигурацию? Устройство потеряет доступ.')) return;
  try { await api.revokeProfile(profile.id); profile = null; confText = null; $('#conf').textContent = ''; $('#conf-card').hidden = true; flash($('#msg'), 'Конфигурация отозвана', 'ok'); await load(); } catch (e) { err(e); }
};

$('#logout').onclick = async () => { await api.logout(); location.href = '/'; };
if (api.isLoggedIn()) load();
