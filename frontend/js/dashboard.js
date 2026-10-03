import { api, $, flash, fmtDate } from '/js/api.js';
if (!api.isLoggedIn()) location.replace('/auth.html');

const LABEL = { active: 'Активна', expired: 'Истекла', none: 'Нет', revoked: 'Отозвана' };

// ---- connection instructions (per protocol and platform) ----
const HOW = {
  wireguard: {
    ios: ['Установите бесплатное приложение <b>WireGuard</b> из App Store.',
      'Если кабинет открыт на другом устройстве, откройте QR-код ниже. Если на самом iPhone, нажмите «Скачать конфигурацию» и откройте файл через «Поделиться → WireGuard».',
      'В приложении нажмите «+» и выберите «Создать из QR-кода» (наведите камеру на QR) либо «Создать из файла или архива».',
      'Разрешите добавление VPN-конфигурации и включите переключатель.',
      'Готово: откройте любой сервис проверки IP, должен показаться адрес сервера, а не ваш.'],
    android: ['Установите бесплатное приложение <b>WireGuard</b> из Google Play.',
      'Нажмите «+» и выберите «Сканировать QR-код» (наведите камеру на QR ниже) или «Импорт из файла или архива» (если скачали .conf).',
      'Задайте любое имя туннеля и подтвердите добавление VPN.',
      'Включите переключатель рядом с туннелем.',
      'Проверьте IP на любом сервисе проверки: должен быть адрес сервера.'],
    windows: ['Скачайте и установите <b>WireGuard</b> с официального сайта wireguard.com/install.',
      'Нажмите «Скачать конфигурацию» в кабинете и сохраните файл .conf.',
      'В WireGuard нажмите «Добавить туннель» → «Импортировать туннель(и) из файла» и выберите файл.',
      'Нажмите «Подключить».',
      'Проверьте IP на любом сервисе проверки.'],
    macos: ['Установите <b>WireGuard</b> из Mac App Store.',
      'Нажмите «Скачать конфигурацию» и сохраните файл .conf.',
      'Откройте WireGuard (значок в строке меню) → «Импортировать туннель(и) из файла» и выберите файл.',
      'Нажмите «Включить».',
      'Проверьте IP на любом сервисе проверки.'],
  },
  vless: {
    ios: ['Установите клиент <b>Happ</b> (или INCY) из App Store.',
      'Нажмите «Скопировать конфигурацию» в кабинете: в буфере окажется ссылка, начинающаяся с <b>vless://</b>.',
      'Откройте приложение, нажмите кнопку добавления («+») и выберите вставку из буфера обмена.',
      'Выберите появившуюся конфигурацию и нажмите кнопку подключения.',
      'Проверьте IP на любом сервисе проверки: должен показаться адрес сервера.'],
    android: ['Установите клиент <b>Happ</b> (или INCY) из Google Play.',
      'Нажмите «Скопировать конфигурацию» в кабинете: в буфере окажется ссылка <b>vless://</b>.',
      'В приложении нажмите «+» и выберите вставку из буфера обмена (либо отсканируйте QR ниже с другого устройства).',
      'Выберите конфигурацию и нажмите кнопку подключения. Разрешите создание VPN-соединения.',
      'Проверьте IP на любом сервисе проверки.'],
    windows: ['Установите клиент, поддерживающий VLESS: <b>Happ</b>, <b>v2rayN</b> или <b>Hiddify</b> (скачивайте с сайта разработчика).',
      'Нажмите «Скопировать конфигурацию»: в буфере окажется ссылка <b>vless://</b>.',
      'В клиенте выберите добавление конфигурации из буфера обмена (в v2rayN: «Серверы» → «Импорт из буфера обмена»).',
      'Выберите сервер и включите подключение (режим «Системный прокси» или «TUN» для всего трафика).',
      'Проверьте IP на любом сервисе проверки.'],
    macos: ['Установите клиент, поддерживающий VLESS: <b>Happ</b>, <b>Hiddify</b> или <b>Streisand</b>.',
      'Нажмите «Скопировать конфигурацию»: в буфере окажется ссылка <b>vless://</b>.',
      'В клиенте выберите добавление конфигурации из буфера обмена.',
      'Выберите сервер и включите подключение.',
      'Проверьте IP на любом сервисе проверки.'],
  },
};
const NOTES = {
  wireguard: 'Если приложение пишет об ошибке импорта, скачайте файл заново и убедитесь, что он не изменён: он должен начинаться со строки [Interface].',
  vless: 'Если приложение не распознало ссылку, убедитесь, что она скопирована целиком (начинается с vless:// и не обрывается). Ссылка содержит ваш личный ключ, не публикуйте её.',
};

let me = null, items = { wireguard: [], vless: [] }, proto = 'wireguard', platform = guessPlatform(), text = null;
try { proto = localStorage.getItem('kvn_proto') || proto; } catch { /* storage may be blocked */ }

function guessPlatform() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
  if (/Android/.test(ua)) return 'android';
  if (/Mac/.test(ua)) return 'macos';
  return 'windows';
}
const badge = (el, st, label) => { el.textContent = label || LABEL[st]; el.className = `badge ${st}`; };
const err = (e) => flash($('#msg'), e.message);
const current = () => items[proto].find((p) => p.status !== 'revoked') || null;

async function load() {
  try {
    const [m, wg] = await Promise.all([api.me(), api.profiles()]);
    me = m; items.wireguard = wg.profiles;
    items.vless = me.protocols?.vless ? (await api.vlessAccounts()).accounts : [];
    $('#p-vless').hidden = !me.protocols?.vless;
    if (proto === 'vless' && !me.protocols?.vless) proto = 'wireguard';
    render();
  } catch (e) { if (e.status === 401) location.replace('/auth.html'); else err(e); }
}

function render() {
  const sub = me.subscription, cur = current();
  $('#who').textContent = me.user.email;
  badge($('#sub-status'), sub.status);
  $('#sub-end').textContent = sub.expiresAt ? fmtDate(sub.expiresAt) : '—';
  $('#pay').textContent = sub.active ? 'Продлить на 30 дней — 500 ₽' : 'Оплатить 500 ₽';

  // stepper
  const has = Object.values(items).some((l) => l.some((p) => p.status === 'active'));
  const step = (id, cls) => { $(id).className = cls; };
  step('#s1', sub.active ? 'done' : 'now');
  step('#s2', has ? 'done' : sub.active ? 'now' : '');
  step('#s3', has ? 'now' : '');

  // protocol tabs
  for (const p of ['wireguard', 'vless']) $(`#p-${p}`).classList.toggle('on', p === proto);
  if (cur) badge($('#vpn-status'), cur.status); else badge($('#vpn-status'), 'none', 'Не создана');
  const srv = cur?.server || me.vpnServers[0];
  $('#vpn-server').textContent = srv ? `${srv.name} (${srv.region})` : 'Нет серверов';
  $('#get').textContent = cur ? 'Показать конфигурацию' : 'Получить VPN';
  $('#get').disabled = !sub.active;
  $('#get').title = sub.active ? '' : 'Сначала оплатите подписку';
  $('#cfg').hidden = !text;
  renderHow();
}

function renderHow() {
  document.querySelectorAll('#plat-tabs button').forEach((b) => b.classList.toggle('on', b.dataset.p === platform));
  // Instruction text is a fixed constant of this file (never server data), so innerHTML is safe here.
  $('#steps').innerHTML = HOW[proto][platform].map((s) => `<li>${s}</li>`).join('');
  $('#how-note').textContent = NOTES[proto];
}

function showText(t) {
  text = t;
  $('#conf').textContent = t;
  $('#download').hidden = proto !== 'wireguard';
  $('#copy').textContent = proto === 'wireguard' ? 'Скопировать конфигурацию' : 'Скопировать ссылку';
  try {
    const qr = window.qrcode(0, 'L'); qr.addData(t); qr.make();
    $('#qr').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true }); // generated by the bundled library from our own text
    $('#qr-box').hidden = false; $('#cfg-grid').classList.add('has-qr');
  } catch { $('#qr-box').hidden = true; $('#cfg-grid').classList.remove('has-qr'); }
  $('#cfg').hidden = false;
}

for (const p of ['wireguard', 'vless']) {
  $(`#p-${p}`).onclick = () => {
    proto = p; text = null; try { localStorage.setItem('kvn_proto', p); } catch { /* ignore */ }
    render();
  };
}
document.querySelectorAll('#plat-tabs button').forEach((b) => { b.onclick = () => { platform = b.dataset.p; renderHow(); }; });

$('#pay').onclick = async () => {
  $('#pay').disabled = true;
  try {
    const r = await api.pay('monthly');
    if (r.redirectUrl) return (location.href = r.redirectUrl); // real providers: hosted payment page
    flash($('#msg'), 'Оплата прошла успешно, подписка активна. Теперь получите конфигурацию.', 'ok');
    await load();
  } catch (e) { err(e); } finally { $('#pay').disabled = false; }
};

$('#get').onclick = async () => {
  try {
    let cur = current();
    if (!cur) cur = proto === 'wireguard' ? (await api.createProfile('Мое устройство')).profile : (await api.createVless('Мое устройство')).account;
    const t = proto === 'wireguard' ? await api.config(cur.id) : await api.vlessLink(cur.id);
    await load();
    showText(t);
    $('#cfg').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) { err(e); }
};

$('#download').onclick = () => {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: `kvn-${current()?.id || 'config'}.conf` });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
};

$('#copy').onclick = async () => {
  try { await navigator.clipboard.writeText(text); flash($('#msg'), 'Скопировано. Теперь вставьте в приложение.', 'ok'); }
  catch { const r = document.createRange(); r.selectNodeContents($('#conf')); getSelection().removeAllRanges(); getSelection().addRange(r); flash($('#msg'), 'Текст выделен: скопируйте его через меню («Копировать»).', 'info'); }
};

$('#revoke').onclick = async () => {
  if (!confirm('Отозвать конфигурацию? Устройство потеряет доступ.')) return;
  try {
    const cur = current();
    await (proto === 'wireguard' ? api.revokeProfile(cur.id) : api.revokeVless(cur.id));
    text = null; flash($('#msg'), 'Конфигурация отозвана. Можно создать новую.', 'ok'); await load();
  } catch (e) { err(e); }
};

$('#logout').onclick = async () => { await api.logout(); location.href = '/'; };
if (api.isLoggedIn()) load();
