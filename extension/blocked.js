'use strict';

const COPY = {
  tr: {
    pageTitle: 'Site Engellendi — SplitWire Browser',
    headline: 'Bu site SplitWire-Browser tarafından engellenmiştir',
    customBadge: 'Kişisel Engel · Odak Listesi',
    customDesc:
      'Bu alan adı kişisel engel listenizde yer aldığı için erişime kapatıldı. İsterseniz aşağıdan engeli kaldırabilirsiniz.',
    customUnblock: 'Engeli Kaldır & Devam Et',
    phishingBadge: 'Oltalama & Zararlı Site Kalkanı',
    phishingDesc:
      'Bu site bilinen bir oltalama (phishing), dolandırıcılık veya zararlı yazılım adresi olarak tespit edildi. Hesap güvenliğiniz için erişim durduruldu.',
    phishingUnblock: 'Riski Biliyorum, İzin Ver',
    goBack: 'Geri Dön',
  },
  en: {
    pageTitle: 'Site Blocked — SplitWire Browser',
    headline: 'This site has been blocked by SplitWire-Browser',
    customBadge: 'Custom Block · Focus List',
    customDesc:
      'Access was blocked because this domain is in your personal blocklist. You can unblock it below at any time.',
    customUnblock: 'Unblock & Continue',
    phishingBadge: 'Phishing & Malware Shield',
    phishingDesc:
      'This site was flagged as a known phishing, scam, or malicious domain. Access was stopped to protect your accounts.',
    phishingUnblock: 'I Understand the Risk, Allow',
    goBack: 'Go Back',
  },
};

const params = new URLSearchParams(window.location.search);
const reason = params.get('reason') === 'phishing' ? 'phishing' : 'custom';
const site = (params.get('site') || '').trim().toLowerCase();

document.documentElement.setAttribute('data-reason', reason);
document.getElementById('blockedDomain').textContent = site || '—';

function applyLanguage(lang) {
  const dict = COPY[lang] || COPY.tr;
  document.documentElement.lang = lang || 'tr';
  document.title = dict.pageTitle;
  document.getElementById('headlineText').textContent = dict.headline;
  document.getElementById('reasonBadge').textContent =
    reason === 'phishing' ? dict.phishingBadge : dict.customBadge;
  document.getElementById('descText').textContent =
    reason === 'phishing' ? dict.phishingDesc : dict.customDesc;
  document.getElementById('goBackLabel').textContent = dict.goBack;
  document.getElementById('unblockLabel').textContent =
    reason === 'phishing' ? dict.phishingUnblock : dict.customUnblock;
}

// Sync user's saved theme & language
if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
  chrome.storage.local.get('splitwireState', (res) => {
    const st = (res && res.splitwireState) || {};
    document.documentElement.setAttribute('data-theme', st.theme || 'dark');
    applyLanguage(st.lang || 'tr');
  });
} else {
  applyLanguage('tr');
}

document.getElementById('goBackBtn').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
});

const unblockBtn = document.getElementById('unblockBtn');
if (!site) {
  unblockBtn.style.display = 'none';
} else {
  unblockBtn.addEventListener('click', () => {
    unblockBtn.disabled = true;
    const msgType = reason === 'phishing' ? 'ALLOW_PHISHING_SITE' : 'REMOVE_CUSTOM_BLOCK';
    chrome.runtime.sendMessage({ type: msgType, domain: site }, () => {
      setTimeout(() => {
        window.location.replace(`https://${site}/`);
      }, 150);
    });
  });
}
