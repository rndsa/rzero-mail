/**
 * RZero Mail — High-Voltage Neo-Brutalism Controller
 * TempGun Layout Spec + Cookie Persistence + Realtime OTP + PIN Lock
 * Copyright (c) 2026 ren
 */

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
  return match ? decodeURIComponent(match[3]) : null;
}

function setCookie(name, val, days = 365) {
  const exp = new Date(Date.now() + days * 86400000).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(val)}; expires=${exp}; path=/; SameSite=Lax`;
}

let activeInbox = null;
let cachedPin = null;
let pendingClaimTarget = null;

function openClaimModal(targetAddress, customName, domain) {
  pendingClaimTarget = { address: targetAddress, name: customName, domain: domain };
  const modal = document.getElementById('claimModal');
  const targetEl = document.getElementById('claimTargetAddress');
  const pinInput = document.getElementById('claimPinInput');
  const errEl = document.getElementById('claimPinError');
  if (targetEl) targetEl.textContent = targetAddress;
  if (pinInput) pinInput.value = '';
  if (errEl) {
    errEl.style.display = 'none';
    errEl.textContent = '';
  }
  if (modal) modal.style.display = 'flex';
  setTimeout(() => pinInput && pinInput.focus(), 100);
}

async function submitClaimPin() {
  if (!pendingClaimTarget) return;
  const pinInput = document.getElementById('claimPinInput');
  const errEl = document.getElementById('claimPinError');
  const pin = (pinInput ? pinInput.value : '').trim();
  if (!pin) {
    if (errEl) {
      errEl.textContent = 'Harap masukkan PIN!';
      errEl.style.display = 'block';
    }
    return;
  }

  try {
    const res = await fetch('/api/inboxes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: pendingClaimTarget.name,
        domain: pendingClaimTarget.domain,
        pin: pin
      })
    });
    const data = await res.json();
    if (!res.ok) {
      if (errEl) {
        errEl.textContent = data.message || 'PIN yang dimasukkan salah!';
        errEl.style.display = 'block';
      }
      return;
    }

    // Success!
    cachedPin = pin;
    activeInbox = data.inbox || { address: data.address, is_locked: true };
    setCookie('rzero_active_email', activeInbox.address);
    document.getElementById('claimModal').style.display = 'none';
    if (createCard) createCard.style.display = 'none';
    if (customNameInput) customNameInput.value = '';

    await loadSessionInboxes();
    renderActiveInbox();
    await fetchMessages();
    showToast('PIN Benar! Email berhasil dibuka & terhubung.', 'mint');
    remainingSec = 10;
  } catch (e) {
    if (errEl) {
      errEl.textContent = 'Gagal menghubungi server';
      errEl.style.display = 'block';
    }
  }
}
let allInboxes = [];
let availableDomains = [];
let countdownInterval = null;
let remainingSec = 10;
let isAutoRefresh = true;

// UI Elements
const activeEmailEl = document.getElementById('activeEmail');
const msgCountEl = document.getElementById('msgCount');
const inboxCountPillEl = document.getElementById('inboxCountPill');
const lockStatusPillEl = document.getElementById('lockStatusPill');
const lockBadgeTextEl = document.getElementById('lockBadgeText');
const lockBtnTextEl = document.getElementById('lockBtnText');
const messageListEl = document.getElementById('messageList');
const copyBtn = document.getElementById('copyBtn');
const toggleNewBtn = document.getElementById('toggleNewBtn');
const refreshBtn = document.getElementById('refreshBtn');
const qrBtn = document.getElementById('qrBtn');
const lockBtn = document.getElementById('lockBtn');
const deleteBtn = document.getElementById('deleteBtn');
const inboxSelect = document.getElementById('inboxSelect');
const inboxSwitcherRow = document.getElementById('inboxSwitcherRow');

const createCard = document.getElementById('createCard');
const customNameInput = document.getElementById('customNameInput');
const domainSelect = document.getElementById('domainSelect');
const createCustomBtn = document.getElementById('createCustomBtn');
const createRandomBtn = document.getElementById('createRandomBtn');
const closeCreateBtn = document.getElementById('closeCreateBtn');

const autoToggleSwitch = document.getElementById('autoToggleSwitch');
const autoSwitchKnob = document.getElementById('autoSwitchKnob');
const countdownSecEl = document.getElementById('countdownSec');

const toastContainer = document.getElementById('toastContainer');

function showToast(msg, type = 'info') {
  if (!toastContainer) return;
  const t = document.createElement('div');
  t.className = `toast ${type === 'error' ? 'toast-error' : type === 'mint' ? 'toast-mint' : ''}`;
  t.innerText = msg;
  toastContainer.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transition = 'opacity 0.2s';
    setTimeout(() => t.remove(), 200);
  }, 2500);
}

// Extract OTP Code helper (Strict - never false trigger on dimensions/years/addresses)
function extractOtp(text, subject = '') {
  const combined = (subject + ' ' + (text || ''))
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, ' ');

  // Priority 1: Labeled OTP / Verification / Security code
  const labeledPatterns = [
    /(?:verification\s*code|kode\s*(?:verifikasi|otp)|one-time\s*(?:password|passcode)|security\s*code|confirm(?:ation)?\s*code|login\s*code|auth(?:entication)?\s*code|otp(?:\s*code)?|pin(?:\s*code)?)\s*[:=—–-]?\s*(?:is\s*|adalah\s*)?(\d{4,8})\b/i,
    /\b(\d{4,8})\b\s*(?:is\s*your\s*(?:verification|login|otp|security)\s*code|adalah\s*kode\s*(?:verifikasi|otp))/i,
    /(?:code|kode|otp)\s+is\s+(\d{4,8})\b/i,
    /(?:enter|masukkan|input)\s+(?:the\s+)?(?:code|kode|pin|otp)?\s*[:=—–-]?\s*(\d{4,8})\b/i,
  ];

  for (const p of labeledPatterns) {
    const m = combined.match(p);
    if (m && m[1]) return m[1];
  }

  // Priority 2: Standalone ONLY if verification context exists
  const hasAuthContext = /(?:verification|verifikasi|one-time|otp\b|security code|confirm\b|authenticate|otentikasi|login code)/i.test(combined);
  if (hasAuthContext) {
    const candidates = combined.match(/\b(?<![#$€£¥\/\-@.])(\d{4,8})\b(?![#$€£¥\/\-@.])/g);
    if (candidates) {
      for (const c of candidates) {
        const n = parseInt(c, 10);
        if (n >= 1990 && n <= 2035) continue;
        if ([1000, 1200, 1400, 1600, 1920, 2000, 5000].includes(n)) continue;
        return c;
      }
    }
  }

  return null;
}

// Fetch Domains (Sorted A-Z)
async function loadDomains() {
  try {
    const res = await fetch('/api/domains');
    const data = await res.json();
    availableDomains = (data.domains || []).sort((a, b) => a.localeCompare(b));
    if (domainSelect) {
      domainSelect.innerHTML = availableDomains.map(d => `<option value="${d}" ${d === 'rzmail.my.id' ? 'selected' : ''}>@${d}</option>`).join('');
    }
  } catch (e) {
    availableDomains = ['rzero.me'];
  }
}

// Fetch user session inboxes
async function loadSessionInboxes() {
  try {
    const res = await fetch('/api/inboxes');
    const data = await res.json();
    allInboxes = data.inboxes || [];
    updateSwitcherUI();
  } catch (e) {
    allInboxes = [];
  }
}

function updateSwitcherUI() {
  if (!inboxSelect || !inboxSwitcherRow) return;
  if (allInboxes.length > 1) {
    inboxSwitcherRow.style.display = 'flex';
    inboxSelect.innerHTML = allInboxes.map(ib => 
      `<option value="${ib.address}" ${activeInbox && activeInbox.address === ib.address ? 'selected' : ''}>${ib.address}</option>`
    ).join('');
  } else {
    inboxSwitcherRow.style.display = 'none';
  }
}

// Initialize active inbox
async function initInbox() {
  await loadDomains();
  await loadSessionInboxes();

  const savedAddr = getCookie('rzero_active_email');
  if (savedAddr) {
    activeInbox = { address: savedAddr };
  } else if (allInboxes.length > 0) {
    activeInbox = allInboxes[0];
  } else {
    // Generate new random inbox
    await createNewInbox();
    return;
  }

  setCookie('rzero_active_email', activeInbox.address);
  renderActiveInbox();
  await fetchMessages();
  startCountdown();
}

async function createNewInbox(customName = null, domain = null) {
  try {
    const payload = {};
    if (customName && domain) {
      payload.name = customName;
      payload.domain = domain;
    }
    const res = await fetch('/api/inboxes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      if (data.requiresPin || data.error === 'PIN_REQUIRED') {
        const fullAddr = data.address || (customName ? `${customName}@${domain}` : '');
        openClaimModal(fullAddr, customName, domain);
        return;
      }
      showToast(data.message || 'Gagal membuat inbox', 'error');
      return;
    }

    activeInbox = data.inbox || { address: data.address, is_locked: Boolean(data.isLocked) };
    setCookie('rzero_active_email', activeInbox.address);
    showToast(`Alamat dibuat: ${activeInbox.address}`, 'mint');
    if (createCard) createCard.style.display = 'none';
    if (customNameInput) customNameInput.value = '';

    await loadSessionInboxes();
    renderActiveInbox();
    await fetchMessages();
    remainingSec = 10;
  } catch (e) {
    showToast('Koneksi terputus', 'error');
  }
}

function renderActiveInbox() {
  if (!activeInbox) return;
  if (activeEmailEl) activeEmailEl.textContent = activeInbox.address;
  updateSwitcherUI();

  // Update PIN status
  const isLocked = activeInbox.is_locked || activeInbox.has_pin;
  if (isLocked) {
    if (lockBadgeTextEl) lockBadgeTextEl.textContent = 'TERKUNCI PIN';
    if (lockStatusPillEl) {
      lockStatusPillEl.className = 'pill-badge pill-white';
      lockStatusPillEl.style.backgroundColor = 'var(--yellow-light)';
    }
    if (lockBtnTextEl) lockBtnTextEl.textContent = 'BUKA / PIN';
  } else {
    if (lockBadgeTextEl) lockBadgeTextEl.textContent = 'LIVE';
    if (lockStatusPillEl) {
      lockStatusPillEl.className = 'pill-badge pill-mint';
      lockStatusPillEl.style.backgroundColor = 'var(--mint)';
    }
    if (lockBtnTextEl) lockBtnTextEl.textContent = 'KUNCI PIN';
  }
}

// Fetch Messages
async function fetchMessages() {
  if (!activeInbox) return;
  try {
    let url = `/api/inboxes/${encodeURIComponent(activeInbox.address)}/messages`;
    const headers = {};
    if (cachedPin) headers['X-Inbox-PIN'] = cachedPin;

    const res = await fetch(url, { headers });
    const data = await res.json();

    if (res.status === 403 && data.error === 'INBOX_LOCKED') {
      activeInbox.is_locked = true;
      renderActiveInbox();
      renderLockedState();
      return;
    }

    const messages = data.messages || [];
    renderMessages(messages);
  } catch (e) {
    console.error('Fetch err', e);
  }
}

function renderLockedState() {
  if (msgCountEl) msgCountEl.textContent = 'LOCKED';
  if (inboxCountPillEl) inboxCountPillEl.textContent = 'LOCKED';
  if (messageListEl) {
    messageListEl.innerHTML = `
      <div class="empty-inbox-state">
        <div class="empty-badge-circle" style="background-color: var(--pink-light);">
          <svg viewBox="0 0 24 24" width="32" height="32" stroke="#121316" stroke-width="2.2" fill="none"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>
        <div class="empty-title">Inbox Ini Terkunci PIN</div>
        <div class="empty-desc">
          Masukkan PIN keamanan untuk melihat pesan masuk dan kode OTP yang diterima.
        </div>
        <button class="btn-brutal btn-brutal-mint" onclick="openLockModal(true)" style="margin-top: 10px;">
          <svg class="icon-svg" viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2.5" fill="none"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
          <span>Buka Kunci Sekarang</span>
        </button>
      </div>
    `;
  }
}

let currentMessages = [];

function renderMessages(messages) {
  currentMessages = messages || [];
  const count = currentMessages.length;
  if (msgCountEl) msgCountEl.textContent = count;
  if (inboxCountPillEl) inboxCountPillEl.textContent = count;

  if (!messageListEl) return;

  if (count === 0) {
    messageListEl.innerHTML = `
      <div class="empty-inbox-state">
        <div class="empty-badge-circle">
          <svg viewBox="0 0 24 24" width="32" height="32" stroke="#121316" stroke-width="2" fill="none"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
        </div>
        <div class="empty-title">Belum ada pesan masuk</div>
        <div class="empty-desc">
          Semua email dan kode OTP yang dikirim ke alamat di atas akan muncul otomatis di sini secara realtime.
        </div>
      </div>
    `;
    return;
  }

  messageListEl.innerHTML = messages.map(m => {
    const otp = extractOtp(m.snippet || '', m.subject || '');
    const timeStr = new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <div class="msg-item" onclick="openMessageDetail('${m.id}')">
        <div class="msg-item-top">
          <span class="msg-from">${escapeHtml(m.from_address)}</span>
          <span class="msg-time">${timeStr}</span>
        </div>
        <div class="msg-subject">${escapeHtml(m.subject || '(Tanpa Subjek)')}</div>
        ${otp ? `<div class="msg-otp-tag"><svg class="icon-svg" viewBox="0 0 24 24" width="13" height="13" fill="#121316" stroke="#121316" stroke-width="1.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> <span>OTP: <strong>${otp}</strong></span></div>` : ''}
      </div>
    `;
  }).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Auto Refresh Timer
function startCountdown() {
  if (countdownInterval) clearInterval(countdownInterval);
  remainingSec = 10;
  if (countdownSecEl) countdownSecEl.textContent = remainingSec;

  countdownInterval = setInterval(() => {
    if (!isAutoRefresh) return;
    remainingSec--;
    if (remainingSec <= 0) {
      remainingSec = 10;
      fetchMessages();
    }
    if (countdownSecEl) countdownSecEl.textContent = remainingSec;
  }, 1000);
}

// Message Detail View
let currentMsgId = null;
async function openMessageDetail(id) {
  currentMsgId = id;
  const localMsg = currentMessages.find(m => m.id === id);

  function populateModal(m) {
    if (!m) return;
    document.getElementById('modalSubject').textContent = m.subject || '(Tanpa Subjek)';
    document.getElementById('modalFrom').textContent = m.from_address || m.from || '-';
    const dateVal = m.created_at || m.receivedAt || m.received_at;
    document.getElementById('modalTime').textContent = dateVal ? new Date(dateVal).toLocaleString() : '';

    const bodyText = m.body_text || m.body || '';
    const bodyHtml = m.body_html || m.bodyHtml || '';

    // Check OTP strictly (ignore raw HTML and false dimensions)
    const otp = extractOtp(bodyText, m.subject || '') || (m.otp_code && extractOtp(m.otp_code, m.subject || ''));
    const otpBanner = document.getElementById('modalOtpBanner');
    const otpCode = document.getElementById('modalOtpCode');
    if (otp) {
      otpBanner.style.display = 'block';
      otpCode.textContent = otp;
      document.getElementById('copyModalOtpBtn').onclick = () => {
        navigator.clipboard.writeText(otp);
        showToast(`OTP disalin: ${otp}`, 'mint');
      };
    } else {
      otpBanner.style.display = 'none';
    }

    const iframe = document.getElementById('modalIframe');
    iframe.srcdoc = bodyHtml || `<div style="font-family:sans-serif;padding:16px;">${escapeHtml(bodyText || '')}</div>`;
    document.getElementById('modalBodyTextContainer').textContent = bodyText || '(Tidak ada teks polos)';

    // Reset view to HTML
    document.getElementById('modalBodyHtmlContainer').style.display = 'block';
    document.getElementById('modalBodyTextContainer').style.display = 'none';

    document.getElementById('msgModal').style.display = 'flex';
  }

  if (localMsg) {
    populateModal(localMsg);
  }

  try {
    const headers = {};
    if (cachedPin) headers['X-Inbox-PIN'] = cachedPin;
    const res = await fetch(`/api/inboxes/${encodeURIComponent(activeInbox.address)}/messages/${id}`, { headers });
    if (res.ok) {
      const data = await res.json();
      if (data && data.message) {
        populateModal(data.message);
      }
    } else if (!localMsg) {
      showToast('Gagal memuat pesan', 'error');
    }
  } catch (e) {
    if (!localMsg) {
      showToast('Gagal membuka pesan', 'error');
    }
  }
}

// Fetch & Render Ads (Manual & Script Support)
async function loadAds() {
  try {
    const res = await fetch('/api/ads');
    if (!res.ok) return;
    const data = await res.json();
    const ads = data.ads || [];

    ads.forEach(ad => {
      const isMain = ad.slot_name === 'slot_main';
      const wrapper = document.getElementById(isMain ? 'adSlotMain' : 'adSlotBottom');
      const content = document.getElementById(isMain ? 'adSlotMainContent' : 'adSlotBottomContent');
      if (!wrapper || !content) return;

      if (ad.is_active === 0) {
        wrapper.style.display = 'none';
        return;
      }

      if (ad.ad_type === 'script' && ad.script_code) {
        content.innerHTML = ad.script_code;
        const scripts = content.querySelectorAll('script');
        scripts.forEach(oldScript => {
          const newScript = document.createElement('script');
          Array.from(oldScript.attributes).forEach(attr => newScript.setAttribute(attr.name, attr.value));
          newScript.appendChild(document.createTextNode(oldScript.innerHTML));
          oldScript.parentNode.replaceChild(newScript, oldScript);
        });
        wrapper.style.display = 'block';
      } else {
        const thumbHtml = ad.banner_url
          ? `<img src="${escapeHtml(ad.banner_url)}" class="ad-manual-thumb" alt="Promo" onerror="this.style.display='none'">`
          : `<div class="ad-manual-thumb" style="background:var(--yellow);"><svg viewBox="0 0 24 24" width="24" height="24" stroke="#121316" stroke-width="2.5" fill="none"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>`;

        const clickUrl = `/api/ads/click/${encodeURIComponent(ad.slot_name)}`;
        content.innerHTML = `
          <a href="${clickUrl}" target="_blank" rel="noopener noreferrer" class="ad-manual-card">
            ${thumbHtml}
            <div class="ad-manual-info">
              <div class="ad-manual-title">${escapeHtml(ad.title || 'Sponsor')}</div>
              <div class="ad-manual-desc">${escapeHtml(ad.description || '')}</div>
            </div>
            <div class="ad-manual-btn">
              <span>${escapeHtml(ad.cta_text || 'Lihat Promo')}</span>
              <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="3" fill="none"><line x1="7" y1="17" x2="17" y2="7"/><polyline points="7 7 17 7 17 17"/></svg>
            </div>
          </a>
        `;
        wrapper.style.display = 'block';
      }
    });
  } catch (e) {
    console.error('Failed to load ads', e);
  }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  initInbox();
  loadAds();

  // Copy
  if (copyBtn) {
    copyBtn.onclick = () => {
      if (!activeInbox) return;
      navigator.clipboard.writeText(activeInbox.address);
      showToast('Alamat disalin ke clipboard!', 'mint');
    };
  }

  // Refresh
  if (refreshBtn) {
    refreshBtn.onclick = () => {
      remainingSec = 10;
      fetchMessages();
      showToast('Memperbarui inbox...', 'mint');
    };
  }

  // Toggle New
  if (toggleNewBtn && createCard) {
    toggleNewBtn.onclick = () => {
      createCard.style.display = createCard.style.display === 'none' ? 'flex' : 'none';
    };
  }
  if (closeCreateBtn && createCard) {
    closeCreateBtn.onclick = () => {
      createCard.style.display = 'none';
    };
  }

  // Create Custom & Random
  if (createCustomBtn) {
    createCustomBtn.onclick = () => {
      const name = customNameInput.value.trim().toLowerCase();
      const dom = domainSelect.value;
      if (!name) return showToast('Masukkan nama kustom', 'error');
      createNewInbox(name, dom);
    };
  }
  if (createRandomBtn) {
    createRandomBtn.onclick = () => {
      createNewInbox();
    };
  }

  // Switch Inbox Select
  if (inboxSelect) {
    inboxSelect.onchange = () => {
      activeInbox = { address: inboxSelect.value };
      setCookie('rzero_active_email', activeInbox.address);
      renderActiveInbox();
      fetchMessages();
      remainingSec = 10;
    };
  }

  // QR Modal
  if (qrBtn) {
    qrBtn.onclick = () => {
      if (!activeInbox) return;
      const qrImg = document.getElementById('qrImage');
      const qrText = document.getElementById('qrAddressText');
      qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=mailto:${encodeURIComponent(activeInbox.address)}`;
      qrText.textContent = activeInbox.address;
      document.getElementById('qrModal').style.display = 'flex';
    };
  }
  const closeQrBtn = document.getElementById('closeQrBtn');
  if (closeQrBtn) closeQrBtn.onclick = () => {
    document.getElementById('qrModal').style.display = 'none';
  };

  // Lock Modal
  if (lockBtn) {
    lockBtn.onclick = () => {
      openLockModal(activeInbox.is_locked);
    };
  }

  const closeLockModalBtn = document.getElementById('closeLockModalBtn');
  const cancelPinBtn = document.getElementById('cancelPinBtn');
  if (closeLockModalBtn) closeLockModalBtn.onclick = () => document.getElementById('lockModal').style.display = 'none';
  if (cancelPinBtn) cancelPinBtn.onclick = () => document.getElementById('lockModal').style.display = 'none';

  // Claim / Unlock Locked Email Modal
  const closeClaimModalBtn = document.getElementById('closeClaimModalBtn');
  const cancelClaimBtn = document.getElementById('cancelClaimBtn');
  const submitClaimPinBtn = document.getElementById('submitClaimPinBtn');
  const claimPinInput = document.getElementById('claimPinInput');
  const claimModal = document.getElementById('claimModal');

  if (closeClaimModalBtn) closeClaimModalBtn.onclick = () => { if (claimModal) claimModal.style.display = 'none'; };
  if (cancelClaimBtn) cancelClaimBtn.onclick = () => { if (claimModal) claimModal.style.display = 'none'; };
  if (submitClaimPinBtn) submitClaimPinBtn.onclick = submitClaimPin;
  if (claimPinInput) {
    claimPinInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submitClaimPin();
    });
  }

  // Submit PIN
  const submitPinBtn = document.getElementById('submitPinBtn');
  const pinInput = document.getElementById('pinInput');
  if (submitPinBtn) {
    submitPinBtn.onclick = async () => {
      const pin = pinInput.value.trim();
      if (!pin) return showToast('Masukkan PIN', 'error');

      if (activeInbox.is_locked) {
        // Unlock attempt
        cachedPin = pin;
        await fetchMessages();
        document.getElementById('lockModal').style.display = 'none';
        pinInput.value = '';
        showToast('Kunci PIN diverifikasi', 'mint');
      } else {
        // Set PIN
        try {
          const res = await fetch(`/api/inboxes/${encodeURIComponent(activeInbox.address)}/lock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pin })
          });
          const d = await res.json();
          if (res.ok) {
            cachedPin = pin;
            activeInbox.is_locked = true;
            renderActiveInbox();
            document.getElementById('lockModal').style.display = 'none';
            pinInput.value = '';
            showToast('PIN berhasil dipasang!', 'mint');
          } else {
            showToast(d.message || 'Gagal pasang PIN', 'error');
          }
        } catch (e) {
          showToast('Koneksi terputus', 'error');
        }
      }
    };
  }

  // Delete Inbox
  if (deleteBtn) {
    deleteBtn.onclick = async () => {
      if (!activeInbox) return;
      if (!confirm(`Hapus inbox ${activeInbox.address}?`)) return;
      try {
        const headers = {};
        if (cachedPin) headers['X-Inbox-PIN'] = cachedPin;
        await fetch(`/api/inboxes/${encodeURIComponent(activeInbox.address)}`, {
          method: 'DELETE',
          headers
        });
        showToast('Inbox dihapus', 'mint');
        allInboxes = allInboxes.filter(i => i.address !== activeInbox.address);
        if (allInboxes.length > 0) {
          activeInbox = allInboxes[0];
          setCookie('rzero_active_email', activeInbox.address);
          renderActiveInbox();
          fetchMessages();
        } else {
          createNewInbox();
        }
      } catch (e) {
        showToast('Gagal menghapus', 'error');
      }
    };
  }

  // Auto Toggle Switch
  if (autoToggleSwitch) {
    autoToggleSwitch.onclick = () => {
      isAutoRefresh = !isAutoRefresh;
      if (isAutoRefresh) {
        autoToggleSwitch.style.backgroundColor = 'var(--mint)';
        autoSwitchKnob.style.right = '2px';
        autoSwitchKnob.style.left = 'auto';
        showToast('Auto-refresh AKTIF', 'mint');
      } else {
        autoToggleSwitch.style.backgroundColor = '#E5E7EB';
        autoSwitchKnob.style.right = 'auto';
        autoSwitchKnob.style.left = '2px';
        showToast('Auto-refresh NONAKTIF', 'info');
      }
    };
  }

  // Message Detail Controls
  const closeModalBtn = document.getElementById('closeModalBtn');
  if (closeModalBtn) closeModalBtn.onclick = () => document.getElementById('msgModal').style.display = 'none';

  const viewHtmlBtn = document.getElementById('viewHtmlBtn');
  const viewTextBtn = document.getElementById('viewTextBtn');
  if (viewHtmlBtn) {
    viewHtmlBtn.onclick = () => {
      document.getElementById('modalBodyHtmlContainer').style.display = 'block';
      document.getElementById('modalBodyTextContainer').style.display = 'none';
    };
  }
  if (viewTextBtn) {
    viewTextBtn.onclick = () => {
      document.getElementById('modalBodyHtmlContainer').style.display = 'none';
      document.getElementById('modalBodyTextContainer').style.display = 'block';
    };
  }

  const deleteMsgBtn = document.getElementById('deleteMsgBtn');
  if (deleteMsgBtn) {
    deleteMsgBtn.onclick = async () => {
      if (!currentMsgId || !activeInbox) return;
      try {
        const headers = {};
        if (cachedPin) headers['X-Inbox-PIN'] = cachedPin;
        await fetch(`/api/inboxes/${encodeURIComponent(activeInbox.address)}/messages/${currentMsgId}`, {
          method: 'DELETE',
          headers
        });
        document.getElementById('msgModal').style.display = 'none';
        showToast('Pesan dihapus', 'mint');
        fetchMessages();
      } catch (e) {
        showToast('Gagal hapus pesan', 'error');
      }
    };
  }
});

function openLockModal(isLocked) {
  const modal = document.getElementById('lockModal');
  const title = document.getElementById('lockModalTitle');
  const desc = document.getElementById('lockModalDesc');
  const btn = document.getElementById('submitPinBtn');

  if (isLocked) {
    title.textContent = 'BUKA KUNCI INBOX';
    desc.textContent = 'Inbox ini dilindungi PIN. Masukkan PIN untuk membuka isi inbox.';
    btn.textContent = 'Buka Kunci';
  } else {
    title.textContent = 'KUNCI DENGAN PIN';
    desc.textContent = 'Pasang 4-8 digit PIN rahasia untuk mengunci inbox ini dari akses publik.';
    btn.textContent = 'Pasang Kunci';
  }
  modal.style.display = 'flex';
}
window.openLockModal = openLockModal;
window.openMessageDetail = openMessageDetail;
