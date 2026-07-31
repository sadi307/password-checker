/* ================================================================
   STATE & CONSTANTS
   ================================================================ */
var PAGES = ['home','generator','checker','assistant','dashboard','vault','analytics','tips','auth','admin'];
var currentPage = 'home';
var activityLog = [];
var vaultData = [];
var vaultKey = null;
var currentUser = null;
var dashChart = null;
var analyticsCharts = {};
var lastGeneratedPassword = '';

var CHARSETS = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?~'
};
var AMBIGUOUS_CHARS = '0OolI1|';

var genOpts = { upper: true, lower: true, numbers: true, symbols: true, noAmbig: false };

var COMMON_PW = [
  'password','123456','12345678','qwerty','abc123','monkey','master','dragon',
  '111111','baseball','iloveyou','trustno1','sunshine','ashley','football',
  'shadow','123123','654321','superman','qazwsx','michael','password1',
  'password123','letmein','admin','welcome','login','princess','starwars',
  'passw0rd','hello','charlie','donald','1234','aa123456','password2',
  'qwerty123','1q2w3e4r','p@ssw0rd'
];

/* ================================================================
   UTILITIES
   ================================================================ */
function escapeHtml(t) {
  var d = document.createElement('div');
  d.textContent = t;
  return d.innerHTML.replace(/\n/g, '<br>');
}

function showToast(msg, type) {
  type = type || 'success';
  var t = document.createElement('div');
  t.className = 'toast toast-' + type;
  var icons = { success: 'check-circle', error: 'circle-exclamation', info: 'info-circle' };
  t.innerHTML = '<i class="fa-solid fa-' + (icons[type] || 'info-circle') + ' mr-2"></i>' + msg;
  document.getElementById('toast-container').appendChild(t);
  requestAnimationFrame(function() { t.classList.add('show'); });
  setTimeout(function() {
    t.classList.remove('show');
    setTimeout(function() { t.remove(); }, 350);
  }, 3000);
}

function addActivity(type, desc) {
  activityLog.unshift({ type: type, desc: desc, time: new Date() });
  if (activityLog.length > 50) activityLog.pop();
}

function timeAgo(d) {
  var s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

/* ================================================================
   NAVIGATION
   ================================================================ */
function navigateTo(page) {
  currentPage = page;
  PAGES.forEach(function(p) {
    var el = document.getElementById('page-' + p);
    if (el) el.classList.toggle('active', p === page);
  });
  document.querySelectorAll('.nav-item').forEach(function(n) {
    n.classList.toggle('active', n.dataset.page === page);
  });
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
  if (page === 'dashboard') updateDashboard();
  if (page === 'analytics') updateAnalytics();
  if (page === 'admin') initAdmin();
  if (page === 'tips') initTips();
  if (page === 'vault') renderVault();
  window.scrollTo(0, 0);
}

document.querySelectorAll('.nav-item').forEach(function(n) {
  n.addEventListener('click', function() { navigateTo(n.dataset.page); });
});

document.getElementById('menu-btn').addEventListener('click', function() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('show');
});

document.getElementById('sidebar-overlay').addEventListener('click', function() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
});

document.getElementById('home-gen-btn').addEventListener('click', function() { navigateTo('generator'); });
document.getElementById('home-check-btn').addEventListener('click', function() { navigateTo('checker'); });

/* ================================================================
   CRYPTO HELPERS
   ================================================================ */
function sha(algo, text) {
  var enc = new TextEncoder().encode(text);
  return crypto.subtle.digest(algo, enc).then(function(buf) {
    return Array.from(new Uint8Array(buf)).map(function(b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  });
}

function calcEntropy(pw) {
  if (!pw) return 0;
  var cs = 0;
  if (/[a-z]/.test(pw)) cs += 26;
  if (/[A-Z]/.test(pw)) cs += 26;
  if (/[0-9]/.test(pw)) cs += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) cs += 33;
  return cs > 0 ? pw.length * Math.log2(cs) : 0;
}

function estimateCrackTime(entropy) {
  var s = Math.pow(2, entropy) / 1e10 / 2;
  if (s < 0.001) return 'Instant';
  if (s < 1) return '<1 sec';
  if (s < 60) return Math.round(s) + ' sec';
  if (s < 3600) return Math.round(s / 60) + ' min';
  if (s < 86400) return Math.round(s / 3600) + ' hrs';
  if (s < 31536000) return Math.round(s / 86400) + ' days';
  if (s < 31536000 * 1000) return Math.round(s / 31536000) + ' yrs';
  if (s < 31536000 * 1e6) return Math.round(s / 31536000 / 1000) + 'K yrs';
  if (s < 31536000 * 1e9) return Math.round(s / 31536000 / 1e6) + 'M yrs';
  return 'Centuries+';
}

function detectPatterns(pw) {
  var p = [];
  if (COMMON_PW.indexOf(pw.toLowerCase()) !== -1) p.push('Common password');
  if (/^(123|234|345|456|567|678|789|abc|bcd|cde|def|qwe|wer|ert|rty|asd|sdf|dfg|zxc|xcv|cvb|vbn)/i.test(pw)) p.push('Sequential chars');
  if (/(.)\1{2,}/.test(pw)) p.push('Repeated chars');
  if (/^(.)\1+$/.test(pw)) p.push('All same char');
  if (/^[a-z]+$/i.test(pw)) p.push('Letters only');
  if (/^[0-9]+$/.test(pw)) p.push('Numbers only');
  if (pw.length < 8) p.push('Too short (<8)');
  if (/^[A-Z][a-z]+\d+!?$/.test(pw)) p.push('Predictable pattern');
  if (pw.length >= 1 && new Set(pw).size <= 3) p.push('Low uniqueness');
  return p;
}

function scorePassword(pw) {
  if (!pw) return { score: 0, label: 'Enter a password', color: 'var(--muted)', tier: 'none' };
  var s = 0;
  s += Math.min(pw.length * 4, 40);
  if (/[a-z]/.test(pw)) s += 10;
  if (/[A-Z]/.test(pw)) s += 10;
  if (/[0-9]/.test(pw)) s += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) s += 15;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s += 5;
  if (pw.length > 2 && /[^a-zA-Z]/.test(pw.slice(1, -1))) s += 5;
  if (COMMON_PW.indexOf(pw.toLowerCase()) !== -1) s = Math.min(s, 5);
  var pats = detectPatterns(pw);
  s -= pats.length * 8;
  if (new Set(pw).size <= 3 && pw.length > 3) s -= 20;
  s = Math.max(0, Math.min(100, s));
  var label, color, tier;
  if (s < 20) { label = 'Very Weak'; color = 'var(--danger)'; tier = 'very-weak'; }
  else if (s < 40) { label = 'Weak'; color = '#ff6b4a'; tier = 'weak'; }
  else if (s < 60) { label = 'Fair'; color = 'var(--warn)'; tier = 'fair'; }
  else if (s < 80) { label = 'Strong'; color = 'var(--accent)'; tier = 'strong'; }
  else { label = 'Very Strong'; color = '#00ff88'; tier = 'very-strong'; }
  return { score: s, label: label, color: color, tier: tier };
}

/* ================================================================
   PASSWORD GENERATOR
   ================================================================ */
function syncToggleVisuals() {
  document.querySelectorAll('#gen-toggles .toggle-btn').forEach(function(btn) {
    var opt = btn.dataset.opt;
    btn.setAttribute('aria-checked', genOpts[opt] ? 'true' : 'false');
  });
}

/* Attach toggle click handlers */
document.querySelectorAll('#gen-toggles .toggle-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var opt = btn.dataset.opt;
    if (!opt) return;
    var enabledCount = 0;
    ['upper', 'lower', 'numbers', 'symbols'].forEach(function(k) {
      if (genOpts[k]) enabledCount++;
    });
    if (genOpts[opt] && enabledCount <= 1 && opt !== 'noAmbig') {
      btn.classList.add('shake');
      setTimeout(function() { btn.classList.remove('shake'); }, 400);
      showToast('At least one character type must be selected', 'error');
      return;
    }
    genOpts[opt] = !genOpts[opt];
    syncToggleVisuals();
  });
});

/* Length controls */
var genLenSlider = document.getElementById('gen-length');
var genLenDisplay = document.getElementById('gen-len-val');

function updateLenDisplay() {
  genLenDisplay.textContent = genLenSlider.value;
  document.querySelectorAll('#gen-quick-lens .quick-len').forEach(function(b) {
    b.classList.toggle('active', b.dataset.len === genLenSlider.value);
  });
}

genLenSlider.addEventListener('input', updateLenDisplay);

document.getElementById('gen-len-minus').addEventListener('click', function() {
  var v = Math.max(4, parseInt(genLenSlider.value) - 1);
  genLenSlider.value = v;
  updateLenDisplay();
});

document.getElementById('gen-len-plus').addEventListener('click', function() {
  var v = Math.min(128, parseInt(genLenSlider.value) + 1);
  genLenSlider.value = v;
  updateLenDisplay();
});

document.querySelectorAll('#gen-quick-lens .quick-len').forEach(function(btn) {
  btn.addEventListener('click', function() {
    genLenSlider.value = btn.dataset.len;
    updateLenDisplay();
  });
});

document.getElementById('gen-copy-btn').addEventListener('click', function() {
  if (!lastGeneratedPassword) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(lastGeneratedPassword).then(function() {
      showToast('Password copied to clipboard');
    });
  } else {
    var ta = document.createElement('textarea');
    ta.value = lastGeneratedPassword;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Password copied to clipboard');
  }
});

document.getElementById('gen-refresh-btn').addEventListener('click', function() {
  generatePassword();
});

document.getElementById('gen-btn').addEventListener('click', function() {
  this.classList.add('clicked');
  var self = this;
  setTimeout(function() { self.classList.remove('clicked'); }, 300);
  generatePassword();
});

function generatePassword() {
  try {
    var len = parseInt(genLenSlider.value);
    if (isNaN(len) || len < 4) len = 4;
    if (len > 128) len = 128;

    var pool = '';
    var required = [];
    var typeKeys = ['upper', 'lower', 'numbers', 'symbols'];

    for (var t = 0; t < typeKeys.length; t++) {
      var key = typeKeys[t];
      if (!genOpts[key]) continue;
      var cs = CHARSETS[key];
      if (genOpts.noAmbig) {
        cs = cs.split('').filter(function(c) { return AMBIGUOUS_CHARS.indexOf(c) === -1; }).join('');
      }
      if (cs.length === 0) continue;
      pool += cs;
      var randArr = new Uint32Array(1);
      crypto.getRandomValues(randArr);
      required.push(cs[randArr[0] % cs.length]);
    }

    if (pool.length === 0) {
      showToast('Select at least one character type', 'error');
      return;
    }

    /* Deduplicate pool */
    var poolArr = [];
    var seen = {};
    for (var i = 0; i < pool.length; i++) {
      if (!seen[pool[i]]) { seen[pool[i]] = true; poolArr.push(pool[i]); }
    }
    var poolStr = poolArr.join('');
    var poolLen = poolStr.length;

    if (poolLen === 0) {
      showToast('No characters available after filtering', 'error');
      return;
    }

    var result = required.slice();
    var remaining = len - result.length;
    if (remaining > 0) {
      var fillRand = new Uint32Array(remaining);
      crypto.getRandomValues(fillRand);
      for (var j = 0; j < remaining; j++) {
        result.push(poolStr[fillRand[j] % poolLen]);
      }
    }

    /* Fisher-Yates shuffle */
    for (var k = result.length - 1; k > 0; k--) {
      var swapArr = new Uint32Array(1);
      crypto.getRandomValues(swapArr);
      var swapIdx = swapArr[0] % (k + 1);
      var tmp = result[k];
      result[k] = result[swapIdx];
      result[swapIdx] = tmp;
    }

    var password = result.join('');
    lastGeneratedPassword = password;
    renderGeneratedPassword(password);

    var info = scorePassword(password);
    var entropy = calcEntropy(password);

    var bar = document.getElementById('gen-strength-bar');
    bar.style.width = info.score + '%';
    bar.style.background = info.color;

    var badge = document.getElementById('gen-strength-badge');
    badge.textContent = info.label;
    badge.style.background = info.color + '20';
    badge.style.color = info.color;

    document.getElementById('gen-strength-text').textContent = info.label + ' \u2014 ' + entropy.toFixed(1) + ' bits entropy';
    document.getElementById('gen-strength-text').style.color = info.color;
    document.getElementById('gen-score-text').textContent = info.score + '/100';
    document.getElementById('gen-score-text').style.color = info.color;

    document.getElementById('gen-copy-btn').disabled = false;
    addActivity('generated', 'Generated ' + len + '-char password (score: ' + info.score + ')');
    showToast('Password generated successfully');

  } catch (err) {
    console.error('Generator error:', err);
    showToast('Error generating password: ' + err.message, 'error');
  }
}

function renderGeneratedPassword(pw) {
  var output = document.getElementById('gen-output');
  var placeholder = document.getElementById('gen-placeholder');
  var pwText = document.getElementById('gen-password-text');

  placeholder.style.display = 'none';
  pwText.style.display = 'inline';

  output.className = 'pw-output has-value';
  var info = scorePassword(pw);
  if (info.tier !== 'none') output.classList.add('tier-' + info.tier);

  var html = '';
  for (var i = 0; i < pw.length; i++) {
    var ch = pw[i];
    var cls = 'lower';
    if (/[A-Z]/.test(ch)) cls = 'upper';
    else if (/[0-9]/.test(ch)) cls = 'num';
    else if (/[^a-zA-Z0-9]/.test(ch)) cls = 'sym';
    html += '<span class="char-hl ' + cls + '">' + escapeHtml(ch) + '</span>';
  }
  pwText.innerHTML = html;
}

/* ================================================================
   PASSWORD CHECKER
   ================================================================ */
var checkDebounce = null;

document.getElementById('check-input').addEventListener('input', function() {
  clearTimeout(checkDebounce);
  checkDebounce = setTimeout(analyzePassword, 150);
});

document.getElementById('check-eye-btn').addEventListener('click', function() {
  var inp = document.getElementById('check-input');
  var eye = document.getElementById('check-eye');
  if (inp.type === 'password') { inp.type = 'text'; eye.className = 'fa-solid fa-eye-slash'; }
  else { inp.type = 'password'; eye.className = 'fa-solid fa-eye'; }
});

document.getElementById('check-clear-btn').addEventListener('click', function() {
  document.getElementById('check-input').value = '';
  analyzePassword();
});

document.querySelectorAll('[data-copy-hash]').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var text = document.getElementById(btn.dataset.copyHash).textContent;
    if (text && text !== '\u2014') {
      navigator.clipboard.writeText(text).then(function() { showToast('Hash copied'); });
    }
  });
});

function analyzePassword() {
  var pw = document.getElementById('check-input').value;
  var info = scorePassword(pw);
  document.getElementById('check-bar').style.width = info.score + '%';
  document.getElementById('check-bar').style.background = info.color;
  document.getElementById('check-label').textContent = pw ? info.label : 'Enter a password';
  document.getElementById('check-label').style.color = pw ? info.color : 'var(--muted)';
  document.getElementById('check-score').textContent = info.score + '/100';

  var entropy = calcEntropy(pw);
  document.getElementById('m-entropy').textContent = pw ? entropy.toFixed(1) + ' bits' : '0 bits';
  document.getElementById('m-crack').textContent = pw ? estimateCrackTime(entropy) : '\u2014';

  var div = 0;
  if (/[a-z]/.test(pw)) div++;
  if (/[A-Z]/.test(pw)) div++;
  if (/[0-9]/.test(pw)) div++;
  if (/[^a-zA-Z0-9]/.test(pw)) div++;
  document.getElementById('m-diversity').textContent = pw ? div + '/4' : '0/4';

  var pats = detectPatterns(pw);
  var patEl = document.getElementById('m-pattern');
  if (!pw) { patEl.textContent = 'None'; patEl.style.color = 'var(--muted)'; }
  else if (pats.length === 0) { patEl.textContent = 'Clean'; patEl.style.color = 'var(--success)'; }
  else { patEl.textContent = pats[0]; patEl.style.color = 'var(--danger)'; }

  var findingsEl = document.getElementById('check-findings');
  var listEl = document.getElementById('findings-list');
  if (pw) {
    findingsEl.style.display = 'block';
    var f = [];
    if (pw.length < 8) f.push({ icon: 'fa-ruler', color: 'var(--danger)', text: 'Too short. Use at least 12 characters.' });
    else if (pw.length < 12) f.push({ icon: 'fa-ruler', color: 'var(--warn)', text: 'Consider 12+ characters for better security.' });
    if (div < 4) f.push({ icon: 'fa-font', color: 'var(--warn)', text: 'Add more character types for higher entropy.' });
    if (pats.length > 0) f.push({ icon: 'fa-magnifying-glass', color: 'var(--danger)', text: 'Pattern: ' + pats.join(', ') });
    if (entropy < 40) f.push({ icon: 'fa-bolt', color: 'var(--danger)', text: 'Very low entropy (' + entropy.toFixed(1) + ' bits).' });
    else if (entropy < 60) f.push({ icon: 'fa-bolt', color: 'var(--warn)', text: 'Moderate entropy (' + entropy.toFixed(1) + ' bits).' });
    if (COMMON_PW.indexOf(pw.toLowerCase()) !== -1) f.push({ icon: 'fa-skull-crossbones', color: 'var(--danger)', text: 'COMMONLY USED password. Do NOT use it.' });
    if (info.score >= 80) f.push({ icon: 'fa-shield-halved', color: 'var(--success)', text: 'Excellent! Meets high security standards.' });
    if (f.length === 0) f.push({ icon: 'fa-circle-info', color: 'var(--cyan)', text: 'Decent but could be improved.' });
    listEl.innerHTML = f.map(function(x) {
      return '<li class="flex items-start gap-3 text-sm"><i class="fa-solid ' + x.icon + ' mt-0.5" style="color:' + x.color + '"></i><span>' + x.text + '</span></li>';
    }).join('');
  } else {
    findingsEl.style.display = 'none';
  }

  if (pw) {
    Promise.all([
      sha('SHA-1', pw), sha('SHA-256', pw), sha('SHA-384', pw), sha('SHA-512', pw)
    ]).then(function(hashes) {
      document.getElementById('hash-sha1').textContent = hashes[0];
      document.getElementById('hash-sha256').textContent = hashes[1];
      document.getElementById('hash-sha384').textContent = hashes[2];
      document.getElementById('hash-sha512').textContent = hashes[3];
    });
    addActivity('checked', 'Analyzed password (score: ' + info.score + ')');
  } else {
    ['sha1', 'sha256', 'sha384', 'sha512'].forEach(function(a) {
      document.getElementById('hash-' + a).textContent = '\u2014';
    });
  }
}

/* ================================================================
   AI ASSISTANT
   ================================================================ */
document.getElementById('chat-send-btn').addEventListener('click', sendChat);
document.getElementById('chat-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') sendChat();
});
document.querySelectorAll('[data-quick]').forEach(function(btn) {
  btn.addEventListener('click', function() {
    document.getElementById('chat-input').value = btn.dataset.quick;
    sendChat();
  });
});

function sendChat() {
  var input = document.getElementById('chat-input');
  var msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  appendChat('user', msg);
  setTimeout(function() { typeChatResponse(generateAIResponse(msg)); }, 300 + Math.random() * 500);
}

function appendChat(role, text) {
  var c = document.getElementById('chat-messages');
  var d = document.createElement('div');
  d.className = 'flex gap-3' + (role === 'user' ? ' justify-end' : '');
  if (role === 'user') {
    d.innerHTML = '<div class="chat-bubble chat-user">' + escapeHtml(text) + '</div><div class="w-8 h-8 rounded-full bg-[var(--border)] flex items-center justify-center flex-shrink-0"><i class="fa-solid fa-user text-[var(--muted)] text-xs"></i></div>';
  } else {
    d.innerHTML = '<div class="w-8 h-8 rounded-full bg-[var(--accent-g)] border border-[var(--accent-d)] flex items-center justify-center flex-shrink-0"><i class="fa-solid fa-robot text-[var(--accent)] text-xs"></i></div><div class="chat-bubble chat-ai" id="typing-bubble"></div>';
  }
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
}

function typeChatResponse(text) {
  var c = document.getElementById('chat-messages');
  var d = document.createElement('div');
  d.className = 'flex gap-3';
  d.innerHTML = '<div class="w-8 h-8 rounded-full bg-[var(--accent-g)] border border-[var(--accent-d)] flex items-center justify-center flex-shrink-0"><i class="fa-solid fa-robot text-[var(--accent)] text-xs"></i></div><div class="chat-bubble chat-ai" id="typing-bubble"></div>';
  c.appendChild(d);
  var bubble = document.getElementById('typing-bubble');
  var i = 0;
  var iv = setInterval(function() {
    bubble.innerHTML = escapeHtml(text.slice(0, i + 1)) + (i < text.length - 1 ? '<span class="inline-block w-1.5 h-4 bg-[var(--accent)] ml-0.5 animate-pulse align-middle"></span>' : '');
    i++;
    c.scrollTop = c.scrollHeight;
    if (i >= text.length) { clearInterval(iv); bubble.removeAttribute('id'); }
  }, 12);
}

function generateAIResponse(msg) {
  var l = msg.toLowerCase();
  var am = l.match(/analyze(?:\s+the\s+password)?:?\s*(.+)/);
  if (am) {
    var pw = am[1].trim();
    var info = scorePassword(pw);
    var en = calcEntropy(pw);
    var pats = detectPatterns(pw);
    var r = 'Analysis of "' + pw + '":\n\nStrength: ' + info.label + ' (' + info.score + '/100)\nEntropy: ' + en.toFixed(1) + ' bits\nCrack time: ' + estimateCrackTime(en);
    if (pats.length > 0) r += '\n\nPatterns: ' + pats.join(', ');
    if (COMMON_PW.indexOf(pw.toLowerCase()) !== -1) r += '\n\nThis is a COMMONLY USED password. Change it immediately.';
    if (info.score < 40) r += '\n\nTips:\n- Use 14+ characters\n- Mix all character types\n- Avoid common patterns';
    else if (info.score < 70) r += '\n\nTo improve: add length and more character variety.';
    else r += '\n\nStrong password. Store securely and never reuse.';
    return r;
  }
  if (l.includes('sha-256') || l.includes('sha256') || l.includes('sha'))
    return 'SHA-256 produces a fixed 256-bit digest from any input.\n\nHow it works:\n1. Pad input to 512-bit blocks\n2. Expand each block into 64 words\n3. 64 rounds of bitwise operations per block\n4. Output: 256-bit hash\n\nKey properties:\n- One-way: cannot reverse\n- Deterministic: same input = same output\n- Avalanche: 1 bit change = ~50% output change\n\nUsed in TLS, blockchain, digital signatures, and password hashing.';
  if (l.includes('passphrase'))
    return 'A passphrase uses 4-7 random words separated by hyphens.\n\nExample: "velvet-mountain-orbit-falcon-crystal"\n\nWhy it works:\n- 30+ characters = massive search space\n- Easier to remember\n- Each Diceware word adds ~12.9 bits entropy\n- 5 words = ~65 bits';
  if (l.includes('how long') || l.includes('length'))
    return 'Password length by security level:\n\n8 chars: Crackable in hours\n12 chars: Decent for low-stakes\n16 chars: Strong for most accounts\n20+ chars: High-value accounts\n32+ chars: Critical infrastructure\n\nRecommendation: 16+ for everything, 24+ for important accounts.';
  if (l.includes('2fa') || l.includes('two-factor') || l.includes('mfa'))
    return '2FA adds a second verification layer:\n\n1. Hardware Keys (FIDO2) - Best, phishing-resistant\n2. Authenticator Apps (TOTP) - Very good\n3. SMS - Weakest, vulnerable to SIM swapping\n\n2FA blocks 99.9% of automated attacks.';
  if (l.includes('breach') || l.includes('leak'))
    return 'Over 15 billion credentials have been leaked.\n\nProtection:\n1. Check haveibeenpwned.com\n2. Never reuse passwords\n3. Use a password manager\n4. Change credentials immediately if breached';
  return 'I can help with:\n\n- Analyze passwords (e.g., "Analyze: MyP@ss123")\n- Explain SHA algorithms\n- Passphrase advice\n- Password length recommendations\n- 2FA/MFA guidance\n\nWhat would you like to know?';
}

/* ================================================================
   DASHBOARD
   ================================================================ */
function updateDashboard() {
  var strong = 0, weak = 0;
  vaultData.forEach(function(e) { if (scorePassword(e.password).score >= 60) strong++; else weak++; });
  activityLog.forEach(function(a) {
    var m = a.desc.match(/score:\s*(\d+)/);
    if (m) { if (parseInt(m[1]) >= 60) strong++; else weak++; }
  });
  var total = vaultData.length || strong + weak || 0;
  document.getElementById('dash-total').textContent = total;
  document.getElementById('dash-strong').textContent = strong;
  document.getElementById('dash-weak').textContent = weak;
  document.getElementById('dash-score').textContent = total ? Math.round((strong / Math.max(total, 1)) * 100) + '%' : '\u2014';

  var actEl = document.getElementById('dash-activity');
  if (!activityLog.length) {
    actEl.innerHTML = '<div class="text-sm text-[var(--muted)]">No activity yet.</div>';
  } else {
    actEl.innerHTML = activityLog.slice(0, 8).map(function(a) {
      var ic = a.type === 'generated' ? 'fa-wand-magic-sparkles' : a.type === 'checked' ? 'fa-magnifying-glass' : 'fa-vault';
      var cl = a.type === 'generated' ? 'var(--accent)' : a.type === 'checked' ? 'var(--cyan)' : 'var(--warn)';
      return '<div class="flex items-center gap-3 text-sm"><i class="fa-solid ' + ic + '" style="color:' + cl + '"></i><span class="flex-1">' + a.desc + '</span><span class="text-xs text-[var(--muted)]">' + timeAgo(a.time) + '</span></div>';
    }).join('');
  }

  var ctx = document.getElementById('dash-chart');
  if (dashChart) dashChart.destroy();
  dashChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: ['Strong', 'Weak'], datasets: [{ data: [strong, weak], backgroundColor: ['#00ff88', '#ff4757'], borderWidth: 0, borderRadius: 4 }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#4a7058', font: { family: 'Space Grotesk' } } } } }
  });
}

/* ================================================================
   VAULT
   ================================================================ */
function deriveKey(pw, salt) {
  var enc = new TextEncoder().encode(pw);
  return crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']).then(function(km) {
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  });
}

function encryptData(key, data) {
  var s = crypto.getRandomValues(new Uint8Array(16));
  var iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(JSON.stringify(data))).then(function(ct) {
    return { salt: Array.from(s), iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
  });
}

function decryptData(key, e) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(e.iv) }, key, new Uint8Array(e.ct)).then(function(ct) {
    return JSON.parse(new TextDecoder().decode(ct));
  });
}

document.getElementById('vault-unlock-btn').addEventListener('click', unlockVault);
document.getElementById('vault-master').addEventListener('keydown', function(e) { if (e.key === 'Enter') unlockVault(); });
document.getElementById('vault-lock-btn').addEventListener('click', lockVault);
document.getElementById('vault-add-btn').addEventListener('click', function() { openVaultModal(); });
document.getElementById('vault-modal-close').addEventListener('click', closeVaultModal);
document.getElementById('vault-save-btn').addEventListener('click', saveVaultEntry);
document.getElementById('vault-gen-fill').addEventListener('click', fillVaultGen);
document.getElementById('vault-search').addEventListener('input', renderVault);

function unlockVault() {
  var mp = document.getElementById('vault-master').value;
  if (!mp) { showToast('Enter a master password', 'error'); return; }
  var stored = localStorage.getItem('sp_vault');
  var salt, promise;
  if (stored) {
    var p = JSON.parse(stored);
    salt = new Uint8Array(p.salt);
    promise = deriveKey(mp, salt).then(function(key) {
      vaultKey = key;
      return decryptData(key, p).then(function(data) { vaultData = data; });
    });
  } else {
    salt = crypto.getRandomValues(new Uint8Array(16));
    promise = deriveKey(mp, salt).then(function(key) {
      vaultKey = key;
      vaultData = [];
      return encryptData(key, vaultData).then(function(enc) {
        enc.salt = Array.from(salt);
        localStorage.setItem('sp_vault', JSON.stringify(enc));
      });
    });
  }
  promise.then(function() {
    document.getElementById('vault-locked').style.display = 'none';
    document.getElementById('vault-unlocked').style.display = 'block';
    document.getElementById('vault-add-btn').style.display = '';
    renderVault();
    showToast('Vault unlocked');
    addActivity('vault', 'Unlocked vault');
  }).catch(function() {
    showToast('Wrong master password', 'error');
  });
}

function lockVault() {
  vaultKey = null;
  vaultData = [];
  document.getElementById('vault-locked').style.display = 'block';
  document.getElementById('vault-unlocked').style.display = 'none';
  document.getElementById('vault-add-btn').style.display = 'none';
  document.getElementById('vault-master').value = '';
  showToast('Vault locked', 'info');
}

function renderVault() {
  var search = (document.getElementById('vault-search') ? document.getElementById('vault-search').value : '').toLowerCase();
  var filtered = vaultData.filter(function(e) {
    return !search || e.service.toLowerCase().indexOf(search) !== -1 || e.username.toLowerCase().indexOf(search) !== -1;
  });
  var list = document.getElementById('vault-list');
  if (!filtered.length) {
    list.innerHTML = '<div class="glow-card p-8 text-center text-[var(--muted)]"><i class="fa-solid fa-vault text-3xl mb-3 block opacity-30"></i>No entries yet.</div>';
    return;
  }
  list.innerHTML = filtered.map(function(e) {
    var info = scorePassword(e.password);
    var ri = vaultData.indexOf(e);
    return '<div class="glow-card p-4 flex items-center gap-4 flex-wrap">' +
      '<div class="w-10 h-10 rounded-lg bg-[var(--bg2)] border border-[var(--border)] flex items-center justify-center font-bold text-sm text-[var(--accent)]">' + escapeHtml(e.service.charAt(0).toUpperCase()) + '</div>' +
      '<div class="flex-1 min-w-[150px]"><div class="font-semibold text-sm">' + escapeHtml(e.service) + '</div><div class="text-xs text-[var(--muted)]">' + escapeHtml(e.username) + '</div></div>' +
      '<div class="text-right"><div class="text-xs mb-1" style="color:' + info.color + '">' + info.label + ' (' + info.score + ')</div><div class="w-20 strength-bar h-1.5"><div class="strength-fill" style="width:' + info.score + '%;background:' + info.color + '"></div></div></div>' +
      '<div class="flex gap-2">' +
        '<button class="btn-icon" style="width:32px;height:32px;font-size:12px" data-vault-copy="' + ri + '"><i class="fa-solid fa-copy"></i></button>' +
        '<button class="btn-icon" style="width:32px;height:32px;font-size:12px" data-vault-edit="' + ri + '"><i class="fa-solid fa-pen"></i></button>' +
        '<button class="btn-icon" style="width:32px;height:32px;font-size:12px;color:var(--danger)" data-vault-del="' + ri + '"><i class="fa-solid fa-trash"></i></button>' +
      '</div></div>';
  }).join('');

  list.querySelectorAll('[data-vault-copy]').forEach(function(b) {
    b.addEventListener('click', function() { copyVaultPw(parseInt(b.dataset.vaultCopy)); });
  });
  list.querySelectorAll('[data-vault-edit]').forEach(function(b) {
    b.addEventListener('click', function() { editVaultEntry(parseInt(b.dataset.vaultEdit)); });
  });
  list.querySelectorAll('[data-vault-del]').forEach(function(b) {
    b.addEventListener('click', function() { deleteVaultEntry(parseInt(b.dataset.vaultDel)); });
  });
}

function openVaultModal(editIdx) {
  document.getElementById('vault-modal').classList.add('show');
  if (editIdx !== undefined) {
    var e = vaultData[editIdx];
    document.getElementById('vault-modal-title').textContent = 'Edit Entry';
    document.getElementById('vault-service').value = e.service;
    document.getElementById('vault-username').value = e.username;
    document.getElementById('vault-password').value = e.password;
    document.getElementById('vault-notes').value = e.notes || '';
    document.getElementById('vault-edit-id').value = editIdx;
  } else {
    document.getElementById('vault-modal-title').textContent = 'Add Entry';
    document.getElementById('vault-service').value = '';
    document.getElementById('vault-username').value = '';
    document.getElementById('vault-password').value = '';
    document.getElementById('vault-notes').value = '';
    document.getElementById('vault-edit-id').value = '';
  }
}

function closeVaultModal() { document.getElementById('vault-modal').classList.remove('show'); }

function fillVaultGen() {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  var arr = new Uint32Array(24);
  crypto.getRandomValues(arr);
  var pw = '';
  for (var i = 0; i < 24; i++) pw += chars[arr[i] % chars.length];
  document.getElementById('vault-password').value = pw;
}

function saveVaultEntry() {
  if (!vaultKey) return;
  var service = document.getElementById('vault-service').value.trim();
  var username = document.getElementById('vault-username').value.trim();
  var password = document.getElementById('vault-password').value;
  var notes = document.getElementById('vault-notes').value.trim();
  if (!service || !password) { showToast('Service and password required', 'error'); return; }
  var eid = document.getElementById('vault-edit-id').value;
  if (eid !== '') {
    vaultData[parseInt(eid)] = { service: service, username: username, password: password, notes: notes, updated: Date.now() };
  } else {
    vaultData.push({ service: service, username: username, password: password, notes: notes, created: Date.now(), updated: Date.now() });
  }
  encryptData(vaultKey, vaultData).then(function(enc) {
    var stored = JSON.parse(localStorage.getItem('sp_vault'));
    enc.salt = stored.salt;
    localStorage.setItem('sp_vault', JSON.stringify(enc));
    closeVaultModal();
    renderVault();
    showToast(eid !== '' ? 'Entry updated' : 'Entry saved');
    addActivity('vault', (eid !== '' ? 'Updated' : 'Added') + ' ' + service);
  });
}

function deleteVaultEntry(idx) {
  vaultData.splice(idx, 1);
  encryptData(vaultKey, vaultData).then(function(enc) {
    var stored = JSON.parse(localStorage.getItem('sp_vault'));
    enc.salt = stored.salt;
    localStorage.setItem('sp_vault', JSON.stringify(enc));
    renderVault();
    showToast('Entry deleted', 'info');
  });
}

function editVaultEntry(idx) { openVaultModal(idx); }
function copyVaultPw(idx) {
  navigator.clipboard.writeText(vaultData[idx].password);
  showToast('Password copied');
  addActivity('vault', 'Copied ' + vaultData[idx].service);
}

/* ================================================================
   ANALYTICS
   ================================================================ */
function updateAnalytics() {
  var all = vaultData;
  var cd = { color: '#4a7058', font: { family: 'Space Grotesk' } };
  Object.keys(analyticsCharts).forEach(function(k) { if (analyticsCharts[k]) analyticsCharts[k].destroy(); });
  analyticsCharts = {};

  analyticsCharts.strengthTime = new Chart(document.getElementById('chart-strength-time'), {
    type: 'line',
    data: { labels: all.length ? all.map(function(_, i) { return '#' + (i + 1); }) : ['No data'], datasets: [{ label: 'Score', data: all.length ? all.map(function(e) { return scorePassword(e.password).score; }) : [0], borderColor: '#00ff88', backgroundColor: 'rgba(0,255,136,0.1)', fill: true, tension: 0.4, pointBackgroundColor: '#00ff88', pointRadius: 4 }] },
    options: { responsive: true, scales: { x: { ticks: cd, grid: { color: 'rgba(24,48,36,0.5)' } }, y: { min: 0, max: 100, ticks: cd, grid: { color: 'rgba(24,48,36,0.5)' } } }, plugins: { legend: { labels: cd } } }
  });

  var lb = { '<8': 0, '8-12': 0, '13-16': 0, '17-24': 0, '25+': 0 };
  all.forEach(function(e) { var l = e.password.length; if (l < 8) lb['<8']++; else if (l <= 12) lb['8-12']++; else if (l <= 16) lb['13-16']++; else if (l <= 24) lb['17-24']++; else lb['25+']++; });
  analyticsCharts.lengthDist = new Chart(document.getElementById('chart-length-dist'), {
    type: 'bar', data: { labels: Object.keys(lb), datasets: [{ data: Object.values(lb), backgroundColor: ['#ff4757', '#ffa502', '#00d4ff', '#00ff88', '#00cc6a'], borderRadius: 6, borderSkipped: false }] },
    options: { responsive: true, scales: { x: { ticks: cd, grid: { display: false } }, y: { ticks: cd, grid: { color: 'rgba(24,48,36,0.5)' } } }, plugins: { legend: { display: false } } }
  });

  var cL = 0, cU = 0, cN = 0, cS = 0;
  all.forEach(function(e) { if (/[a-z]/.test(e.password)) cL++; if (/[A-Z]/.test(e.password)) cU++; if (/[0-9]/.test(e.password)) cN++; if (/[^a-zA-Z0-9]/.test(e.password)) cS++; });
  var n = all.length || 1;
  analyticsCharts.charType = new Chart(document.getElementById('chart-chartype'), {
    type: 'radar', data: { labels: ['Lowercase', 'Uppercase', 'Numbers', 'Symbols'], datasets: [{ data: [cL / n * 100, cU / n * 100, cN / n * 100, cS / n * 100], borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.15)', pointBackgroundColor: '#00d4ff' }] },
    options: { responsive: true, scales: { r: { min: 0, max: 100, ticks: Object.assign({}, cd, { backdropColor: 'transparent' }), grid: { color: 'rgba(24,48,36,0.5)' }, angleLines: { color: 'rgba(24,48,36,0.5)' }, pointLabels: cd } }, plugins: { legend: { display: false } } }
  });

  var eb = { '<40': 0, '40-60': 0, '60-80': 0, '80-100': 0, '100+': 0 };
  all.forEach(function(e) { var en = calcEntropy(e.password); if (en < 40) eb['<40']++; else if (en < 60) eb['40-60']++; else if (en < 80) eb['60-80']++; else if (en < 100) eb['80-100']++; else eb['100+']++; });
  analyticsCharts.entropy = new Chart(document.getElementById('chart-entropy'), {
    type: 'doughnut', data: { labels: Object.keys(eb), datasets: [{ data: Object.values(eb), backgroundColor: ['#ff4757', '#ffa502', '#00d4ff', '#00ff88', '#00cc6a'], borderWidth: 0, borderRadius: 4 }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: cd } } }
  });
}

/* ================================================================
   SECURITY TIPS
   ================================================================ */
function initTips() {
  var tips = [
    { icon: 'fa-ruler-combined', color: 'var(--accent)', title: 'Length is King', desc: 'A 20-character passphrase is far stronger than "P@ssw0rd!" despite being easier to remember.' },
    { icon: 'fa-clone', color: 'var(--danger)', title: 'Never Reuse Passwords', desc: 'When one service is breached, attackers try those credentials everywhere.' },
    { icon: 'fa-shuffle', color: 'var(--cyan)', title: 'True Randomness Matters', desc: 'Humans are terrible at generating random passwords. Always use a cryptographic RNG.' },
    { icon: 'fa-fingerprint', color: 'var(--warn)', title: 'Enable Two-Factor Authentication', desc: '2FA blocks 99.9% of automated attacks. Prioritize hardware keys for critical accounts.' },
    { icon: 'fa-database', color: 'var(--accent)', title: 'Understand Hash Algorithms', desc: 'SHA-256/384/512 are one-way functions. Password hashes should always be salted.' },
    { icon: 'fa-key', color: 'var(--cyan)', title: 'Use a Password Manager', desc: 'This vault uses AES-256-GCM \u2014 the same standard used by governments worldwide.' },
    { icon: 'fa-magnifying-glass', color: 'var(--warn)', title: 'Check for Breaches', desc: 'Over 15 billion credentials have been exposed. Check haveibeenpwned.com regularly.' },
    { icon: 'fa-layer-group', color: 'var(--danger)', title: 'Defense in Depth', desc: 'Combine strong passwords with 2FA, updates, firewalls, and phishing awareness.' },
    { icon: 'fa-network-wired', color: 'var(--accent)', title: 'Beware of Phishing', desc: 'The strongest password is useless if you give it to an attacker. Verify URLs first.' },
    { icon: 'fa-microchip', color: 'var(--cyan)', title: 'Hardware Security Keys', desc: 'FIDO2 keys use public-key crypto and are immune to phishing via domain verification.' }
  ];
  document.getElementById('tips-container').innerHTML = tips.map(function(t) {
    return '<div class="glow-card p-6 cursor-pointer" data-tip-toggle><div class="flex items-start gap-4"><div class="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0" style="background:' + t.color + '15;border:1px solid ' + t.color + '30"><i class="fa-solid ' + t.icon + '" style="color:' + t.color + '"></i></div><div class="flex-1"><div class="flex items-center justify-between"><h3 class="font-semibold">' + t.title + '</h3><i class="fa-solid fa-chevron-down text-xs text-[var(--muted)]"></i></div><p class="tip-detail hidden text-sm text-[var(--muted)] mt-3 leading-relaxed">' + t.desc + '</p></div></div></div>';
  }).join('');
  document.querySelectorAll('[data-tip-toggle]').forEach(function(el) {
    el.addEventListener('click', function() { el.querySelector('.tip-detail').classList.toggle('hidden'); });
  });
}

/* ================================================================
   AUTH
   ================================================================ */
document.getElementById('show-register-link').addEventListener('click', function() {
  document.getElementById('auth-login').style.display = 'none';
  document.getElementById('auth-register').style.display = 'block';
  document.getElementById('auth-title').textContent = 'Register';
  document.getElementById('auth-subtitle').textContent = 'Create a new account';
});
document.getElementById('show-login-link').addEventListener('click', function() {
  document.getElementById('auth-login').style.display = 'block';
  document.getElementById('auth-register').style.display = 'none';
  document.getElementById('auth-title').textContent = 'Login';
  document.getElementById('auth-subtitle').textContent = 'Access your account';
});
document.getElementById('login-btn').addEventListener('click', doLogin);
document.getElementById('login-pass').addEventListener('keydown', function(e) { if (e.key === 'Enter') doLogin(); });
document.getElementById('register-btn').addEventListener('click', doRegister);
document.getElementById('reg-pass2').addEventListener('keydown', function(e) { if (e.key === 'Enter') doRegister(); });

function doRegister() {
  var u = document.getElementById('reg-user').value.trim();
  var e = document.getElementById('reg-email').value.trim();
  var p = document.getElementById('reg-pass').value;
  var p2 = document.getElementById('reg-pass2').value;
  if (!u || !e || !p) { showToast('All fields required', 'error'); return; }
  if (p !== p2) { showToast('Passwords do not match', 'error'); return; }
  if (p.length < 6) { showToast('Password must be at least 6 characters', 'error'); return; }
  if (scorePassword(p).score < 20) { showToast('Password too weak', 'error'); return; }
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var saltStr = Array.from(salt).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
  sha('SHA-256', p + saltStr).then(function(hash) {
    var users = JSON.parse(localStorage.getItem('sp_users') || '[]');
    if (users.find(function(x) { return x.username === u; })) { showToast('Username taken', 'error'); return; }
    users.push({ username: u, email: e, hash: hash, salt: Array.from(salt), role: 'user', created: Date.now() });
    localStorage.setItem('sp_users', JSON.stringify(users));
    showToast('Account created!');
    document.getElementById('show-login-link').click();
  });
}

function doLogin() {
  var u = document.getElementById('login-user').value.trim();
  var p = document.getElementById('login-pass').value;
  if (!u || !p) { showToast('Enter username and password', 'error'); return; }
  var users = JSON.parse(localStorage.getItem('sp_users') || '[]');
  var found = users.find(function(x) { return x.username === u; });
  if (!found) { showToast('User not found', 'error'); return; }
  var saltStr = found.salt.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
  sha('SHA-256', p + saltStr).then(function(hash) {
    if (hash !== found.hash) { showToast('Incorrect password', 'error'); return; }
    currentUser = found;
    document.getElementById('sidebar-username').textContent = found.username;
    document.getElementById('sidebar-user').querySelector('.text-xs').textContent = found.role === 'admin' ? 'Administrator' : 'Logged in';
    showToast('Welcome back, ' + found.username + '!');
    addActivity('auth', 'Logged in as ' + found.username);
    navigateTo('dashboard');
  });
}

/* ================================================================
   ADMIN PANEL
   ================================================================ */
function initAdmin() {
  var defs = [
    { username: 'admin', email: 'admin@securepass.ai', role: 'admin', status: 'active' },
    { username: 'alice_dev', email: 'alice@example.com', role: 'user', status: 'active' },
    { username: 'bob_secure', email: 'bob@example.com', role: 'user', status: 'active' },
    { username: 'charlie_ops', email: 'charlie@example.com', role: 'moderator', status: 'active' },
    { username: 'diana_ana', email: 'diana@example.com', role: 'user', status: 'inactive' }
  ];
  var users = JSON.parse(localStorage.getItem('sp_users') || '[]');
  var all = defs.concat(users.map(function(u) {
    return { username: u.username, email: u.email, role: u.role, status: 'active' };
  }));

  document.getElementById('admin-users').innerHTML = all.map(function(u) {
    var rc = u.role === 'admin' ? 'var(--danger)' : u.role === 'moderator' ? 'var(--cyan)' : 'var(--muted)';
    var sc = u.status === 'active' ? 'var(--success)' : 'var(--muted)';
    return '<tr><td class="font-medium">' + escapeHtml(u.username) + '</td><td class="text-[var(--muted)]">' + escapeHtml(u.email) + '</td><td><span class="text-xs px-2 py-0.5 rounded" style="color:' + rc + ';background:' + rc + '15">' + u.role + '</span></td><td><span class="flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full" style="background:' + sc + '"></span><span class="text-xs" style="color:' + sc + '">' + u.status + '</span></span></td></tr>';
  }).join('');

  var logs = [
    { t: '2 min ago', m: 'Password checked \u2014 score: 82', c: 'var(--cyan)' },
    { t: '5 min ago', m: 'Password generated (24 chars)', c: 'var(--success)' },
    { t: '12 min ago', m: 'Vault unlocked by admin', c: 'var(--cyan)' },
    { t: '1 hr ago', m: 'Failed login for "test"', c: 'var(--warn)' },
    { t: '2 hrs ago', m: 'New user registered', c: 'var(--success)' },
    { t: '3 hrs ago', m: 'System health check passed', c: 'var(--cyan)' }
  ];
  document.getElementById('admin-logs').innerHTML = logs.map(function(l) {
    return '<div class="flex items-start gap-2 text-xs"><span class="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style="background:' + l.c + '"></span><div><div class="text-[var(--text)]">' + l.m + '</div><div class="text-[var(--muted)] mt-0.5">' + l.t + '</div></div></div>';
  }).join('');

  document.getElementById('admin-alerts').innerHTML = [
    { lv: 'critical', ic: 'fa-skull-crossbones', cl: 'var(--danger)', ti: 'Brute Force Attack Detected', d: 'Multiple failed logins from 192.168.1.45.', t: '12 min ago' },
    { lv: 'high', ic: 'fa-triangle-exclamation', cl: 'var(--warn)', ti: 'Weak Master Password', d: 'User "diana_ana" has vault password scoring below 30.', t: '2 hrs ago' },
    { lv: 'medium', ic: 'fa-circle-info', cl: 'var(--cyan)', ti: 'Outdated Encryption', d: '3 vault entries use legacy encryption.', t: '1 day ago' }
  ].map(function(a) {
    return '<div class="bg-[var(--bg2)] rounded-lg p-4 border-l-4" style="border-left-color:' + a.cl + '"><div class="flex items-start gap-3"><i class="fa-solid ' + a.ic + ' mt-0.5" style="color:' + a.cl + '"></i><div class="flex-1"><div class="flex items-center gap-2"><span class="font-semibold text-sm">' + a.ti + '</span><span class="text-[10px] px-1.5 py-0.5 rounded uppercase font-bold" style="background:' + a.cl + '20;color:' + a.cl + '">' + a.lv + '</span></div><p class="text-xs text-[var(--muted)] mt-1">' + a.d + '</p><span class="text-[10px] text-[var(--muted)] mt-2 block">' + a.t + '</span></div></div></div>';
  }).join('');
}

/* ================================================================
   HOME HASH RAIN
   ================================================================ */
(function() {
  var c = document.getElementById('hash-rain');
  if (!c) return;
  var h = [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'a3d2f8c1e5b6a7d9c0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f',
    '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
  ];
  for (var i = 0; i < 6; i++) {
    var s = document.createElement('span');
    s.textContent = h[i % h.length];
    s.style.left = (Math.random() * 90) + '%';
    s.style.animationDuration = (15 + Math.random() * 20) + 's';
    s.style.animationDelay = (-Math.random() * 20) + 's';
    s.style.top = (Math.random() * 100) + '%';
    c.appendChild(s);
  }
})();

/* ================================================================
   INIT: Default admin user
   ================================================================ */
(function() {
  if (!localStorage.getItem('sp_users')) {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var saltStr = Array.from(salt).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    sha('SHA-256', 'admin123' + saltStr).then(function(hash) {
      localStorage.setItem('sp_users', JSON.stringify([{
        username: 'admin',
        email: 'admin@securepass.ai',
        hash: hash,
        salt: Array.from(salt),
        role: 'admin',
        created: Date.now()
      }]));
    });
  }
})();