
// ================================================================
//  FIREBASE REST HELPERS
//  All reads/writes go to Firebase Realtime Database via REST.
//  No Firebase SDK is imported — this works in any sandboxed iframe.
// ================================================================

var firebaseReady = FIREBASE_URL && FIREBASE_URL.indexOf('YOUR-PROJECT') === -1;

function fbPath(path) {
  return FIREBASE_URL.replace(/\/$/, '') + path + '.json';
}

async function fbGet(path) {
  try {
    var r = await fetch(fbPath(path));
    if (!r.ok) return null;
    var d = await r.json();
    return d;                     // null if key doesn't exist — that's correct
  } catch(e) { return null; }
}

async function fbSet(path, data) {
  await fetch(fbPath(path), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
}

// PATCH merges only the given fields server-side, leaving other fields intact.
// This avoids the read-modify-write race where a full PUT clobbers concurrent edits.
async function fbUpdate(path, fields) {
  await fetch(fbPath(path), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(fields)
  });
}
// Update only specific fields on a user record (race-safe). Falls back to a
// merge-into-localStorage when Firebase isn't active.
async function userPatch(userId, fields) {
  var k = 'users/' + safeKey(userId);
  if (firebaseReady) {
    await fbUpdate('/' + k, fields);
  } else {
    var existing = lsGet(k) || {};
    for (var f in fields) { if (fields.hasOwnProperty(f)) existing[f] = fields[f]; }
    lsSet(k, existing);
  }
  // Keep the in-memory copy consistent if present
  if (allUsers && allUsers[safeKey(userId)]) {
    var rec = allUsers[safeKey(userId)];
    for (var g in fields) { if (fields.hasOwnProperty(g)) rec[g] = fields[g]; }
  }
}

async function fbDelete(path) {
  await fetch(fbPath(path), { method: 'DELETE' });
}

async function fbGetAll(path) {
  try {
    var r = await fetch(fbPath(path));
    if (!r.ok) return {};
    var d = await r.json();
    return d || {};
  } catch(e) { return {}; }
}

// Firebase keys cannot contain . $ # [ ] /
function safeKey(s) {
  return String(s).trim().replace(/[.$#\[\]\/]/g, '_').toUpperCase();
}

// ================================================================
//  LOCALSTORAGE FALLBACK
//  Used only when Firebase is not configured.
//  Namespaced under 'cairo_' to avoid collisions.
// ================================================================
var LS = 'cairo_';
function lsGet(k)    { try { return JSON.parse(localStorage.getItem(LS+k)); } catch(e) { return null; } }
function lsSet(k,v)  { try { localStorage.setItem(LS+k, JSON.stringify(v)); } catch(e) {} }
function lsDel(k)    { try { localStorage.removeItem(LS+k); } catch(e) {} }
function lsAll(pfx)  {
  var out = {};
  try {
    for (var i = 0; i < localStorage.length; i++) {
      var key = localStorage.key(i);
      if (key && key.startsWith(LS+pfx)) {
        var bare = key.slice(LS.length);
        var v = lsGet(bare);
        if (v) out[bare] = v;
      }
    }
  } catch(e) {}
  return out;
}

// ================================================================
//  UNIFIED STORAGE API
//  userStore  — credentials, private per user
//  orderStore — shared queue across all users
// ================================================================
async function userGet(userId) {
  var k = 'users/' + safeKey(userId);
  return firebaseReady ? fbGet('/' + k) : lsGet(k);
}
async function userSet(userId, data) {
  var k = 'users/' + safeKey(userId);
  if (firebaseReady) await fbSet('/' + k, data);
  else lsSet(k, data);
}
async function userGetAll() {
  if (firebaseReady) return await fbGetAll('/users');
  return lsAll('users/');
}
async function userDel(userId) {
  var k = 'users/' + safeKey(userId);
  if (firebaseReady) await fbDelete('/' + k); else lsDel(k);
}

async function ordersGetAll() {
  if (firebaseReady) {
    var all = await fbGetAll('/orders');
    return all ? Object.values(all) : [];
  }
  return Object.values(lsAll('orders/'));
}
async function orderSet(id, data) {
  var k = 'orders/' + id;
  if (firebaseReady) await fbSet('/' + k, data);
  else lsSet(k, data);
}
async function orderDel(id) {
  var k = 'orders/' + id;
  if (firebaseReady) await fbDelete('/' + k);
  else lsDel(k);
}

// ── Comment storage ──
// Stored at /comments/{safeOrderId}/{commentId}
// Flat per-order bucket — concurrent writes are safe, no order rewrite needed.
function commentKey(orderId) {
  return orderId.replace(/[.$#\[\]\/]/g, '_');
}
async function commentsGet(orderId) {
  var path = '/comments/' + commentKey(orderId);
  if (firebaseReady) {
    var all = await fbGetAll(path);
    return all ? Object.values(all) : [];
  }
  return Object.values(lsAll('comments/' + commentKey(orderId) + '/'));
}
async function commentAdd(orderId, comment) {
  var path = '/comments/' + commentKey(orderId) + '/' + comment.id;
  if (firebaseReady) await fbSet(path, comment);
  else lsSet('comments/' + commentKey(orderId) + '/' + comment.id, comment);
}

// ================================================================
//  AUTH
// ================================================================
var currentUser = null;

// ── Passphrase hashing ──
// Legacy hash (weak, 32-bit) retained ONLY to verify pre-migration accounts.
// New accounts and any successful legacy login are upgraded to salted SHA-256.
function hashPassLegacy(s) {
  var h = 0;
  for (var i = 0; i < s.length; i++) { h = Math.imul(31, h) + s.charCodeAt(i) | 0; }
  return h.toString(36);
}

// Generate a random salt (hex string)
function makeSalt() {
  var a = new Uint8Array(16);
  var c = window.crypto || window.msCrypto;
  if (c && c.getRandomValues) {
    c.getRandomValues(a);
  } else {
    // Last-resort fallback (non-crypto) — only hit in insecure/legacy contexts
    for (var i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(a).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
}

// Salted SHA-256 → hex. Async (uses Web Crypto). Falls back to a stronger
// iterated legacy hash if crypto.subtle is unavailable (e.g. insecure context).
async function hashPassSecure(passphrase, salt) {
  var data = salt + '::' + passphrase;
  if (window.crypto && window.crypto.subtle) {
    var buf = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
    return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
  }
  // Fallback: repeated legacy mixing (better than single pass, used only without subtle crypto)
  var h = data;
  for (var i = 0; i < 1000; i++) h = hashPassLegacy(h + i);
  return 'fb_' + h;
}

// PBKDF2 key-stretched hash (hashVer 3). ~150k SHA-256 iterations makes offline
// brute-force of a leaked database vastly more expensive than a single hash.
var PBKDF2_ITERS = 150000;
async function hashPassPBKDF2(passphrase, salt, iters) {
  iters = iters || PBKDF2_ITERS;
  if (window.crypto && window.crypto.subtle && window.crypto.subtle.importKey) {
    try {
      var enc = new TextEncoder();
      var keyMaterial = await window.crypto.subtle.importKey(
        'raw', enc.encode(passphrase), { name:'PBKDF2' }, false, ['deriveBits']);
      var bits = await window.crypto.subtle.deriveBits(
        { name:'PBKDF2', salt: enc.encode(salt), iterations: iters, hash:'SHA-256' },
        keyMaterial, 256);
      return Array.from(new Uint8Array(bits)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
    } catch(_) {
      // Fall through to SHA-256 path if PBKDF2 unsupported
    }
  }
  return await hashPassSecure(passphrase, salt);
}

// Build a fresh credential object for storing on a user record.
async function makeCredential(passphrase) {
  var salt = makeSalt();
  // hashVer 3 = PBKDF2 key-stretched. Records the iteration count so future
  // changes to PBKDF2_ITERS don't break verification of existing accounts.
  var hash = await hashPassPBKDF2(passphrase, salt, PBKDF2_ITERS);
  return { hash: hash, salt: salt, hashVer: 3, iters: PBKDF2_ITERS };
}
// Copy all credential fields onto a record (keeps hash scheme fields in sync).
function applyCredential(rec, cred) {
  rec.hash = cred.hash;
  rec.salt = cred.salt;
  rec.hashVer = cred.hashVer;
  rec.iters = cred.iters || null;
  return rec;
}

// ── Recovery codes ──
// Generate N human-friendly one-time codes (e.g. "A7F2-9C4E"). Returns the plain
// codes (to show the user once) plus their hashed forms (to store).
function makeRecoveryCodeString() {
  var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous 0/O/1/I
  var a = new Uint8Array(8);
  var c = window.crypto || window.msCrypto;
  if (c && c.getRandomValues) c.getRandomValues(a);
  else for (var i=0;i<a.length;i++) a[i]=Math.floor(Math.random()*256);
  var s = '';
  for (var j=0;j<8;j++) { s += chars[a[j] % chars.length]; if (j===3) s += '-'; }
  return s;
}
async function generateRecoveryCodes(count) {
  count = count || 8;
  var plain = [], stored = [];
  for (var i=0;i<count;i++) {
    var code = makeRecoveryCodeString();
    plain.push(code);
    var salt = makeSalt();
    // Normalise (uppercase, strip dashes/spaces) before hashing so input is forgiving
    var hash = await hashPassSecure(code.replace(/[-\s]/g,'').toUpperCase(), salt);
    stored.push({ hash: hash, salt: salt, used: false });
  }
  return { plain: plain, stored: stored };
}
// Verify a recovery code against a user record's stored codes.
// Returns the index of the matching unused code, or -1.
async function verifyRecoveryCode(rec, code) {
  if (!rec || !Array.isArray(rec.recoveryCodes)) return -1;
  var norm = String(code||'').replace(/[-\s]/g,'').toUpperCase();
  if (!norm) return -1;
  for (var i=0;i<rec.recoveryCodes.length;i++) {
    var rc = rec.recoveryCodes[i];
    if (rc.used) continue;
    var h = await hashPassSecure(norm, rc.salt);
    if (h === rc.hash) return i;
  }
  return -1;
}

// Show the one-time recovery codes after they are generated.
var _pendingRecoveryProceed = null;
function showRecoveryCodes(codes, msg, onAck) {
  var list = document.getElementById('recoveryCodesList');
  list.innerHTML = codes.map(function(c){ return '<div style="padding:2px 0;">' + e(c) + '</div>'; }).join('');
  document.getElementById('recoveryShowMsg').textContent = msg || '';
  window._recoveryCodesPlain = codes.join('\n');
  _pendingRecoveryProceed = onAck || null;
  document.getElementById('recoveryShowModal').classList.add('open');
}
function ackRecoveryCodes() {
  document.getElementById('recoveryShowModal').classList.remove('open');
  window._recoveryCodesPlain = null;
  var cb = _pendingRecoveryProceed; _pendingRecoveryProceed = null;
  if (typeof cb === 'function') cb();
}
function copyRecoveryCodes() {
  var txt = window._recoveryCodesPlain || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(function(){
      var btn = document.querySelector('[data-action="copy-recovery"]');
      if (btn) { var t = btn.textContent; btn.textContent = '✓ COPIED'; setTimeout(function(){ btn.textContent = t; }, 1500); }
    }).catch(function(){ alert('Copy failed — please select and copy manually.'); });
  } else {
    alert('Recovery codes:\n\n' + txt);
  }
}

// ── Forgot-passphrase flow (self-service reset via recovery code) ──
function openForgot() {
  document.getElementById('forgotUser').value = '';
  document.getElementById('forgotCode').value = '';
  document.getElementById('forgotNewPass').value = '';
  document.getElementById('forgotConfirm').value = '';
  document.getElementById('forgotErr').textContent = '';
  document.getElementById('forgotModal').classList.add('open');
}
function closeForgot() { document.getElementById('forgotModal').classList.remove('open'); }
async function saveForgot() {
  var uid  = safeKey(document.getElementById('forgotUser').value.trim());
  var code = document.getElementById('forgotCode').value.trim();
  var nw   = document.getElementById('forgotNewPass').value.trim();
  var conf = document.getElementById('forgotConfirm').value.trim();
  var errEl = document.getElementById('forgotErr');
  if (!uid || !code || !nw || !conf) { errEl.textContent = '> ALL FIELDS REQUIRED'; return; }
  if (nw.length < 3) { errEl.textContent = '> NEW PASSPHRASE TOO SHORT (MIN 3)'; return; }
  if (nw !== conf)   { errEl.textContent = '> PASSPHRASES DO NOT MATCH'; return; }
  var rec = null;
  try { rec = await userGet(uid); } catch(_) {}
  if (!rec) { errEl.textContent = '> ID NOT FOUND'; return; }
  if (!Array.isArray(rec.recoveryCodes) || !rec.recoveryCodes.length) {
    errEl.textContent = '> NO RECOVERY CODES ON FILE · Contact a CL5 member.'; return;
  }
  var idx = await verifyRecoveryCode(rec, code);
  if (idx < 0) { errEl.textContent = '> INVALID OR ALREADY-USED CODE'; return; }
  // Consume the code, set the new passphrase
  rec.recoveryCodes[idx].used = true;
  rec.recoveryCodes[idx].usedAt = Date.now();
  var cred = await makeCredential(nw);
  applyCredential(rec, cred);
  rec.passChangedAt = Date.now();
  // A successful recovery also clears any lockout
  rec.lockedUntil = null; rec.failedAttempts = 0;
  try {
    await userSet(uid, rec);
    auditRecord('PASSPHRASE RECOVERED', 'EC·'+uid+' via recovery code', 'SYSTEM');
    closeForgot();
    var remaining = rec.recoveryCodes.filter(function(c){ return !c.used; }).length;
    alert('Passphrase reset successfully.\n\nYou have ' + remaining + ' recovery code' + (remaining===1?'':'s') + ' remaining. You can now sign in with your new passphrase.');
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

// ── Regenerate recovery codes from My Account (invalidates old ones) ──
async function regenerateRecoveryCodes() {
  if (!currentUser) return;
  if (!await pfConfirm('Generate a new set of recovery codes?\n\nThis will INVALIDATE all your existing codes. You will be shown the new codes once.')) return;
  var rec = null;
  try { rec = await userGet(currentUser.id); } catch(_) {}
  if (!rec) { alert('Could not load account.'); return; }
  var recovery = await generateRecoveryCodes(8);
  rec.recoveryCodes = recovery.stored;
  try {
    await userSet(currentUser.id, rec);
    auditRecord('REGENERATED RECOVERY CODES', 'EC·'+currentUser.id);
    closeMyAccount();
    showRecoveryCodes(recovery.plain, 'NEW RECOVERY CODES · Your old codes no longer work.');
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Duress code (covert coercion signal) ──
function openDuressModal() {
  if (!currentUser) return;
  document.getElementById('duressNew').value = '';
  document.getElementById('duressConfirm').value = '';
  document.getElementById('duressErr').textContent = '';
  // Reflect whether one is currently set
  (async function(){
    var rec = null; try { rec = await userGet(currentUser.id); } catch(_) {}
    var status = document.getElementById('duressStatus');
    if (status) status.textContent = (rec && rec.duressCred) ? 'A duress code is currently set.' : 'No duress code set.';
    var clearBtn = document.getElementById('duressClearBtn');
    if (clearBtn) clearBtn.style.display = (rec && rec.duressCred) ? 'inline-block' : 'none';
  })();
  document.getElementById('duressModal').classList.add('open');
}
function closeDuressModal() { document.getElementById('duressModal').classList.remove('open'); }
async function saveDuressCode() {
  if (!currentUser) return;
  var nw   = document.getElementById('duressNew').value;
  var conf = document.getElementById('duressConfirm').value;
  var errEl = document.getElementById('duressErr');
  if (!nw || nw.length < 3) { errEl.textContent = '> DURESS CODE TOO SHORT (MIN 3)'; return; }
  if (nw !== conf) { errEl.textContent = '> CODES DO NOT MATCH'; return; }
  var rec = null;
  try { rec = await userGet(currentUser.id); } catch(_) {}
  if (!rec) { errEl.textContent = '> COULD NOT LOAD ACCOUNT'; return; }
  // The duress code must NOT equal the real passphrase (or it could never be distinguished).
  var sameAsReal = await verifyPass(rec, nw);
  if (sameAsReal.ok) { errEl.textContent = '> DURESS CODE MUST DIFFER FROM YOUR PASSPHRASE'; return; }
  rec.duressCred = await makeCredential(nw); // hashed like a real credential
  rec.duressActive = false; rec.duressTriggeredAt = null;
  try {
    await userSet(currentUser.id, rec);
    auditRecord('SET DURESS CODE', 'EC·'+currentUser.id);
    closeDuressModal();
    alert('Duress code saved.\n\nIf you are ever forced to log in under coercion, use this code instead of your passphrase. You will appear to log in normally, but Security will be silently alerted.');
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}
async function clearDuressCode() {
  if (!currentUser) return;
  if (!await pfConfirm('Remove your duress code?')) return;
  var rec = null;
  try { rec = await userGet(currentUser.id); } catch(_) {}
  if (!rec) return;
  rec.duressCred = null;
  try {
    await userSet(currentUser.id, rec);
    auditRecord('CLEARED DURESS CODE', 'EC·'+currentUser.id);
    closeDuressModal();
    alert('Duress code removed.');
  } catch(err) { alert('ERROR: ' + err.message); }
}

// Verify a passphrase against a user record. Returns:
//   { ok: bool, needsUpgrade: bool }
// needsUpgrade=true means the account is on an older hash scheme and matched —
// the caller should re-store a fresh (PBKDF2) credential transparently.
async function verifyPass(rec, passphrase) {
  if (!rec) return { ok:false, needsUpgrade:false };
  // hashVer 3 — PBKDF2 (current). Use the stored iteration count.
  if (rec.hashVer === 3 && rec.salt) {
    var p = await hashPassPBKDF2(passphrase, rec.salt, rec.iters || PBKDF2_ITERS);
    // If iteration policy has since increased, flag for transparent re-hash.
    var stale = (rec.iters || PBKDF2_ITERS) < PBKDF2_ITERS;
    return { ok: p === rec.hash, needsUpgrade: (p === rec.hash) && stale };
  }
  // hashVer 2 — salted SHA-256. Matches → upgrade to PBKDF2.
  if (rec.hashVer === 2 && rec.salt) {
    var computed = await hashPassSecure(passphrase, rec.salt);
    return { ok: computed === rec.hash, needsUpgrade: computed === rec.hash };
  }
  // Legacy hash (no salt / no version). Matches → upgrade to PBKDF2.
  var legacy = hashPassLegacy(passphrase);
  return { ok: legacy === rec.hash, needsUpgrade: legacy === rec.hash };
}

var loginMode = 'login';
function setLoginMode(m) {
  loginMode = m;
  document.getElementById('tabLogin').classList.toggle('active', m === 'login');
  document.getElementById('tabReg').classList.toggle('active', m === 'register');
  document.getElementById('loginExtras').style.display = m === 'register' ? 'block' : 'none';
  document.getElementById('loginBtn').textContent = m === 'login' ? '[ AUTHENTICATE ]' : '[ REGISTER & AUTHENTICATE ]';
  document.getElementById('loginErr').textContent = '';
}

function setErr(msg) { document.getElementById('loginErr').textContent = '> ' + msg; }
function setBusy(busy) {
  var btn = document.getElementById('loginBtn');
  btn.disabled = busy;
  if (busy) btn.innerHTML = '<span class="login-spinner"></span>PROCESSING...';
  else btn.textContent = loginMode === 'login' ? '[ AUTHENTICATE ]' : '[ REGISTER & AUTHENTICATE ]';
}

async function doAuth() {
  var u = document.getElementById('loginUser').value.trim();
  var p = document.getElementById('loginPass').value;
  if (!u || !p) { setErr('MISSING CREDENTIALS'); return; }
  if (u.length < 2) { setErr('ID TOO SHORT'); return; }

  setBusy(true);
  var uid = safeKey(u);

  try {
    if (loginMode === 'register') {
      var existing = await userGet(uid);
      if (existing) { setErr('ID ALREADY REGISTERED'); setBusy(false); return; }
      var reqCl = document.getElementById('loginClearance').value;
      var reqSite = (document.getElementById('loginSite') || {}).value || '';
      var cred = await makeCredential(p); // salted SHA-256
      var recovery = await generateRecoveryCodes(8); // one-time recovery codes
      // Check if any active account exists yet (bootstrap case)
      var allU = await userGetAll();
      var hasActive = allU && Object.values(allU).some(function(x){ return x.status==='active' || (!x.status && x.hash); });
      if (hasActive) {
        // Normal path: save as pending CL3, do NOT log in
        await userSet(uid, { hash: cred.hash, salt: cred.salt, hashVer: cred.hashVer, iters: cred.iters || null,
          recoveryCodes: recovery.stored,
          clearance: '3', requestedClearance: reqCl, site: reqSite || null,
          status: 'pending', created: Date.now(), displayId: uid });
        setBusy(false);
        showRecoveryCodes(recovery.plain, 'REGISTRATION SUBMITTED · Awaiting CL5 approval.');
        return;
      } else {
        // Bootstrap: first-ever account, auto-approve at requested clearance
        await userSet(uid, { hash: cred.hash, salt: cred.salt, hashVer: cred.hashVer, iters: cred.iters || null,
          recoveryCodes: recovery.stored,
          clearance: reqCl, requestedClearance: reqCl, site: reqSite || null,
          status: 'active', created: Date.now(), displayId: uid });
        currentUser = { id: uid, clearance: reqCl };
        // Show codes; proceed into the app only after the user acknowledges them
        setBusy(false);
        showRecoveryCodes(recovery.plain, 'ACCOUNT CREATED · Save these, then continue.', function(){ onLogin(); });
        return;
      }

    } else {
      var rec = await userGet(uid);
      if (!rec)           { setErr('ID NOT FOUND · REGISTER FIRST'); setBusy(false); return; }

      // ── Account lockout: block guessing before we even check the passphrase ──
      if (rec.lockedUntil && Date.now() < rec.lockedUntil) {
        var waitMs = rec.lockedUntil - Date.now();
        var waitMin = Math.ceil(waitMs / 60000);
        setErr('ACCOUNT LOCKED · Too many failed attempts. Try again in ' + waitMin + ' minute' + (waitMin>1?'s':'') + '.');
        setBusy(false); return;
      }

      var v = await verifyPass(rec, p);
      if (!v.ok) {
        // ── Duress check: a secondary passphrase that logs in normally but silently
        // signals coercion. Checked only when the real passphrase fails, so it never
        // interferes with normal login. ──
        if (rec.duressCred) {
          var dv = await verifyPass({ hashVer: rec.duressCred.hashVer, salt: rec.duressCred.salt,
                                      hash: rec.duressCred.hash, iters: rec.duressCred.iters }, p);
          if (dv.ok) {
            // Fire the silent alarm: flag the account + audit it as a SYSTEM event.
            var dnow = Date.now();
            try { await userPatch(uid, { duressTriggeredAt: dnow, duressActive: true, lastLogin: dnow, loginCount: (rec.loginCount||0)+1, failedAttempts: 0 }); } catch(_) {}
            if (typeof auditRecord === 'function') auditRecord('⚠ DURESS SIGNAL', 'EC·'+uid+' authenticated under duress — covert coercion alert', 'SYSTEM');
            // Proceed with a normal-looking login so a coercer notices nothing.
            rec.duressTriggeredAt = dnow; rec.duressActive = true;
            rec.lastLogin = dnow; rec.loginCount = (rec.loginCount||0)+1; rec.failedAttempts = 0;
            var dStatus = rec.status || 'active';
            if (dStatus === 'pending' || dStatus === 'denied' || dStatus === 'retired') {
              // Even under duress, a non-active account can't enter — but show the SAME
              // generic message it normally would, to avoid tipping off the coercer.
              setErr('AUTHENTICATION FAILED'); setBusy(false); return;
            }
            currentUser = { id: uid, clearance: deriveClearance(rec), rawClearance: rec.clearance,
                            linkedPfId: rec.linkedPfId || null, linkedEfId: rec.linkedEfId || null, compartments: Array.isArray(rec.compartments) ? rec.compartments : [], duress: true };
            setBusy(false); onLogin(); return;
          }
        }
        // Record the failed attempt and lock after a threshold
        var fails = (rec.failedAttempts || 0) + 1;
        rec.failedAttempts = fails;
        rec.lastFailedAt = Date.now();
        var THRESHOLD = 5;
        var remaining = THRESHOLD - fails;
        if (fails >= THRESHOLD) {
          // Escalating lockout: 1st lock 1min, 2nd 5min, 3rd+ 15min
          var lockCount = (rec.lockoutCount || 0) + 1;
          rec.lockoutCount = lockCount;
          var mins = lockCount === 1 ? 1 : lockCount === 2 ? 5 : 15;
          rec.lockedUntil = Date.now() + mins*60000;
          rec.failedAttempts = 0; // reset counter; lockout now governs
          // PATCH only the lockout fields so we don't clobber a concurrent admin edit
          try { await userPatch(uid, { failedAttempts:0, lastFailedAt:rec.lastFailedAt, lockoutCount:lockCount, lockedUntil:rec.lockedUntil }); } catch(_) {}
          if (typeof auditRecord === 'function') auditRecord('ACCOUNT LOCKED', 'EC·'+uid+' ('+mins+'min) after repeated failures', 'SYSTEM');
          setErr('ACCOUNT LOCKED · Too many failed attempts. Locked for ' + mins + ' minute' + (mins>1?'s':'') + '.');
        } else {
          try { await userPatch(uid, { failedAttempts:fails, lastFailedAt:rec.lastFailedAt }); } catch(_) {}
          setErr('AUTHENTICATION FAILED · ' + remaining + ' attempt' + (remaining>1?'s':'') + ' remaining before lockout.');
        }
        setBusy(false); return;
      }

      // Successful auth — clear failure state, record login
      rec.failedAttempts = 0;
      rec.lockedUntil = null;
      rec.lockoutCount = 0;
      rec.lastLogin = Date.now();
      rec.loginCount = (rec.loginCount || 0) + 1;

      var loginPatch = {
        failedAttempts: 0, lockedUntil: null, lockoutCount: 0,
        lastLogin: rec.lastLogin, loginCount: rec.loginCount
      };
      // Transparently upgrade older-scheme accounts to PBKDF2 on successful login
      if (v.needsUpgrade) {
        try {
          var up = await makeCredential(p);
          applyCredential(rec, up);
          loginPatch.hash = up.hash; loginPatch.salt = up.salt;
          loginPatch.hashVer = up.hashVer; loginPatch.iters = up.iters || null;
        } catch(_) { /* non-fatal: login still proceeds */ }
      }
      // PATCH only the login/upgrade fields so a concurrent admin edit isn't clobbered
      try { await userPatch(uid, loginPatch); } catch(_) {}

      var acctStatus = rec.status || 'active'; // legacy accounts (no status) = active
      if (acctStatus === 'pending') {
        setErr('ACCOUNT PENDING · A CL5 member must authorise your registration before you can access the system.');
        setBusy(false); return;
      }
      if (acctStatus === 'denied') {
        var dreason = rec.statusReason ? ' · Reason: ' + rec.statusReason : '';
        setErr('ACCESS DENIED · Contact the Ethics Committee Chair for assistance.' + dreason);
        setBusy(false); return;
      }
      if (acctStatus === 'retired') {
        setErr('ACCOUNT RETIRED · This account is inactive. Contact a CL5 member to reactivate.');
        setBusy(false); return;
      }
      // Integrity hold: COMPROMISED / POSSIBLE IMPOSTER suspend access until Security clears it.
      if (integrityBlocksAccess(rec.integrityStatus)) {
        setErr('ACCESS SUSPENDED · This account is under a security hold (' + integrityLabel(rec.integrityStatus) + '). Contact Site Security.');
        setBusy(false); return;
      }
      var derivedCl = deriveClearance(rec);
currentUser = { id: uid, clearance: derivedCl, rawClearance: rec.clearance, linkedPfId: rec.linkedPfId || null, linkedEfId: rec.linkedEfId || null, compartments: Array.isArray(rec.compartments) ? rec.compartments : [] };
    }
  } catch(e) {
    setErr('CONNECTION ERROR: ' + e.message);
    setBusy(false);
    return;
  }

  setBusy(false);
  onLogin();
}

function doGuest() {
  currentUser = null;
  onLogin();
}

async function onLogin() { // Make function async
  document.getElementById('loginOverlay').style.display = 'none';

  // Show config warning if Firebase not set up
  document.getElementById('cfgWarn').style.display = firebaseReady ? 'none' : 'block';

  if (currentUser) {
    var userRec = await userGet(currentUser.id);
    if (userRec && !userRec.linkedPfId && !userRec.linkedEfId) {
      openLinkPersonnelModal();
      // Keep user in read-only mode until file is linked
      var roBanner = document.getElementById('cl3Banner');
      if (roBanner) roBanner.style.display = 'block';
      return; // Stop further execution until linked
    }
    var pill = document.getElementById('userPill');
    pill.style.display = 'inline-block';
    // Fetch current user record to get unit tag
    userGet(currentUser.id).then(function(rec) {
      var unitTag = rec && rec.unit ? ' · ' + (rec.unit === 'omega1' ? 'Ω-1' : 'EC') : '';
      pill.textContent = 'EC·' + currentUser.id + ' [L' + currentUser.clearance + ']' + unitTag + '  ▾';
    }).catch(function(){ pill.textContent = 'EC·' + currentUser.id + ' [L' + currentUser.clearance + ']  ▾'; });
    document.getElementById('ordersAuthNotice').style.display = 'none';
    document.getElementById('ordersForm').style.display = 'block';
    var eof = document.getElementById('ethicsOrdersForm');
    var eoaN = document.getElementById('ethicsOrdersAuthNotice');
    if (eof)  eof.style.display  = 'block';
    if (eoaN) eoaN.style.display = 'none';
    // Load ethics orders and recruit in background for badges
    loadEthicsOrders();
    loadEthicsRecruit();
    // Show ADMIN button for CL5 only
    var adminBtn = document.getElementById('adminBtn');
    if (adminBtn) adminBtn.style.display = parseInt(currentUser.clearance) >= 5 ? 'inline-block' : 'none';
    if (parseInt(currentUser.clearance) >= 5) loadAdminData();
    // Show CL3 read-only banner
    var roBanner = document.getElementById('cl3Banner');
    if (roBanner) roBanner.style.display = parseInt(currentUser.clearance) <= 3 ? 'block' : 'none';
  } else {
    document.getElementById('ordersAuthNotice').style.display = 'block';
    document.getElementById('ordersForm').style.display = 'none';
  }

  loadOrders();
  loadPersonnel();
  loadTrainings();
  loadOperations();
  loadEthicsPersonnel(); // needed so EC members get correct clearance from refreshClearance()
  loadEthicsCases();
  loadTribunals();
  refreshIntelNav();
  refreshReadinessNav();
  loadIntel('ec');
  loadCompartments();
  loadPromoReqs();
  loadActivityReqs();
  startPolling();
  setTimeout(showLoginNotifications, 1500); // after data loads
  setTimeout(function(){ if (document.getElementById('tab-overview') && document.getElementById('tab-overview').classList.contains('active')) renderOverview(); }, 1500);
  if (typeof startSessionTimer === 'function') startSessionTimer();
}

// ── Session idle timeout ──
var SESSION_IDLE_MS = 30 * 60000;   // 30 minutes of inactivity → logout
var SESSION_WARN_MS = 2 * 60000;    // show warning 2 minutes before
var _sessionTimer = null, _sessionWarnTimer = null, _sessionCountdownTimer = null;

function startSessionTimer() {
  clearSessionTimers();
  if (!currentUser) return;            // only for authenticated sessions
  if (currentUser.guest) return;       // not for read-only observers
  _sessionWarnTimer = setTimeout(showSessionWarning, Math.max(0, SESSION_IDLE_MS - SESSION_WARN_MS));
  _sessionTimer = setTimeout(sessionExpire, SESSION_IDLE_MS);
}
function clearSessionTimers() {
  if (_sessionTimer) clearTimeout(_sessionTimer);
  if (_sessionWarnTimer) clearTimeout(_sessionWarnTimer);
  if (_sessionCountdownTimer) clearInterval(_sessionCountdownTimer);
  _sessionTimer = _sessionWarnTimer = _sessionCountdownTimer = null;
}
function resetSessionTimer() {
  if (!currentUser || currentUser.guest) return;
  // If the warning is showing, don't silently reset — let the user choose.
  var warn = document.getElementById('sessionWarnModal');
  if (warn && warn.classList.contains('open')) return;
  startSessionTimer();
}
function showSessionWarning() {
  if (!currentUser || currentUser.guest) return;
  var modal = document.getElementById('sessionWarnModal');
  if (!modal) return;
  modal.classList.add('open');
  var remaining = Math.floor(SESSION_WARN_MS / 1000);
  var cd = document.getElementById('sessionCountdown');
  if (cd) cd.textContent = remaining;
  _sessionCountdownTimer = setInterval(function() {
    remaining--;
    if (cd) cd.textContent = remaining;
    if (remaining <= 0) { clearInterval(_sessionCountdownTimer); _sessionCountdownTimer = null; }
  }, 1000);
}
function sessionStay() {
  var modal = document.getElementById('sessionWarnModal');
  if (modal) modal.classList.remove('open');
  if (_sessionCountdownTimer) { clearInterval(_sessionCountdownTimer); _sessionCountdownTimer = null; }
  startSessionTimer(); // fresh full idle window
}
function sessionExpire() {
  var modal = document.getElementById('sessionWarnModal');
  if (modal) modal.classList.remove('open');
  clearSessionTimers();
  var wasUser = currentUser ? currentUser.id : null;
  logout();
  if (wasUser && typeof setErr === 'function') {
    setErr('SESSION EXPIRED · Signed out due to inactivity.');
  }
}
// Activity listeners (throttled) reset the idle timer.
var _lastActivityReset = 0;
function _onUserActivity() {
  var now = Date.now();
  if (now - _lastActivityReset < 5000) return; // throttle to once per 5s
  _lastActivityReset = now;
  resetSessionTimer();
}
['click','keydown','mousemove','scroll','touchstart'].forEach(function(ev){
  document.addEventListener(ev, _onUserActivity, { passive: true });
});

function logout() {
  stopPolling();
  if (typeof stopOverviewHeartbeat === 'function') stopOverviewHeartbeat();
  if (typeof clearSessionTimers === 'function') clearSessionTimers();
  currentUser = null;
  if (typeof adminDirSelected !== 'undefined' && adminDirSelected.clear) adminDirSelected.clear();
  // Fully clear in-memory state so nothing leaks to a subsequent session
  allOrders = []; allEthicsOrders = [];
  allPersonnel = []; allEthicsPersonnel = [];
  allRecruitment = []; allEthicsRecruit = [];
  allPOI = []; allTargets = [];
  allBlacklistConfigs = []; allBlacklistEntries = []; blSheetCache = {};
  allAuditLog = [];
  allUsers = {};
  renderOrders();
  document.getElementById('userPill').style.display = 'none';
  var nb = document.getElementById('notifBanner'); if (nb) nb.style.display = 'none';
  // Close any open modal so none is orphaned over the login screen after logout/expiry
  Array.prototype.forEach.call(document.querySelectorAll('.modal-overlay.open, .modal-overlay-2.open, .ef-modal-bg.open'), function(el){
    el.classList.remove('open');
  });
  var adminBtn = document.getElementById('adminBtn');
  if (adminBtn) adminBtn.style.display = 'none';
  var roBanner = document.getElementById('cl3Banner');
  if (roBanner) roBanner.style.display = 'none';
  document.getElementById('loginOverlay').style.display = 'flex';
  document.getElementById('loginErr').textContent = '';
  document.getElementById('loginUser').value = '';
  document.getElementById('loginPass').value = '';
  setLoginMode('login');
}

// ================================================================
//  ACTIVITY TRACKING (Omega-1 & Ethics — requirements, logs, status)
// ================================================================
// Configurable activity requirements, editable by CL5 in the admin panel.
// Personnel log activity entries (hours + note + tagged contributions); the system
// derives an activity status (Active / Semi-Active / Inactive) and flags breaches.
var allActivityReqs = null; // { omega:{weeklyHours,monthlyHours}, ethicsAssistant:{weeklyHours,requireInteraction} }

function defaultActivityReqs() {
  return {
    omega:           { weeklyHours: 5,  monthlyHours: 25 },
    ethicsAssistant: { weeklyHours: 1,  requireInteraction: true }
  };
}
async function activityReqsGetAll() {
  if (firebaseReady) { var all = await fbGetAll('/activityReqs'); return all || null; }
  return lsGet('activityReqs/config') || null;
}
async function activityReqsSave() {
  if (firebaseReady) await fbSet('/activityReqs', allActivityReqs);
  else lsSet('activityReqs/config', allActivityReqs);
}
async function loadActivityReqs() {
  try {
    var stored = await activityReqsGetAll();
    if (stored && typeof stored === 'object' && stored.omega) {
      allActivityReqs = stored;
      // Backfill any missing keys after an app update
      var d = defaultActivityReqs(), changed = false;
      if (!allActivityReqs.ethicsAssistant) { allActivityReqs.ethicsAssistant = d.ethicsAssistant; changed = true; }
      if (changed) { try { await activityReqsSave(); } catch(_){} }
    } else {
      allActivityReqs = defaultActivityReqs();
      try { await activityReqsSave(); } catch(_){}
    }
  } catch(e) { allActivityReqs = defaultActivityReqs(); }
}

// ── Time-period helpers (UTC week starting Monday; calendar month) ──
function _startOfWeek(ts) {
  var d = new Date(ts); d.setUTCHours(0,0,0,0);
  var day = d.getUTCDay();            // 0=Sun..6=Sat
  var diff = (day === 0 ? 6 : day - 1); // days since Monday
  d.setUTCDate(d.getUTCDate() - diff);
  return d.getTime();
}
function _startOfMonth(ts) {
  var d = new Date(ts);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
}
// Sum logged hours for a record within [since, now].
function activityHoursSince(rec, since) {
  if (!rec || !Array.isArray(rec.activityLog)) return 0;
  return rec.activityLog.reduce(function(sum, a){
    if (a && a.at >= since && typeof a.hours === 'number') return sum + a.hours;
    return sum;
  }, 0);
}
function activityHoursThisWeek(rec)  { return activityHoursSince(rec, _startOfWeek(Date.now())); }
function activityHoursThisMonth(rec) { return activityHoursSince(rec, _startOfMonth(Date.now())); }
// Count of activity entries this week (used for Ethics interaction requirement).
function activityEntriesThisWeek(rec) {
  if (!rec || !Array.isArray(rec.activityLog)) return 0;
  var since = _startOfWeek(Date.now());
  return rec.activityLog.filter(function(a){ return a && a.at >= since; }).length;
}
function activityHasContributionThisWeek(rec) {
  if (!rec || !Array.isArray(rec.activityLog)) return false;
  var since = _startOfWeek(Date.now());
  return rec.activityLog.some(function(a){
    return a && a.at >= since && (
      (Array.isArray(a.tags) && a.tags.length) || (a.note && a.note.trim())
    );
  });
}

// The weekly hours requirement that applies to a given Omega-1 file.
function omegaWeeklyReq() { return (allActivityReqs && allActivityReqs.omega && allActivityReqs.omega.weeklyHours) || 0; }
function omegaMonthlyReq(){ return (allActivityReqs && allActivityReqs.omega && allActivityReqs.omega.monthlyHours) || 0; }

// ── Derived activity status ──
// Returns { key:'active'|'semi'|'inactive'|'leave'|'manual', label, auto, manual }
// LoA/RoA always reports 'leave'. A manual override (set by senior command) wins
// over the auto-derivation but is surfaced as such.
function activityStatus(rec, unit) {
  unit = unit || 'pf';
  if (!rec) return { key:'inactive', label:'INACTIVE', auto:true };
  // Authorised absence overrides everything
  if (getActiveLeave(rec)) {
    var lv = getActiveLeave(rec);
    return { key:'leave', label:(lv && lv.type ? lv.type.toUpperCase() : 'ON LEAVE'), auto:true, onLeave:true };
  }
  // Manual override by command
  if (rec.activityOverride && rec.activityOverride.status) {
    return { key:rec.activityOverride.status,
             label:_activityLabel(rec.activityOverride.status),
             manual:true, by:rec.activityOverride.by, at:rec.activityOverride.at };
  }
  // Auto-derive from logged activity vs the requirement
  var req, weekHours, met, some;
  if (unit === 'ef') {
    // Only Assistants carry an activity requirement on the Ethics side
    if (rec.role !== 'Assistant') return { key:'active', label:'ACTIVE', auto:true, exempt:true };
    req = (allActivityReqs && allActivityReqs.ethicsAssistant) || {};
    weekHours = activityHoursThisWeek(rec);
    met = weekHours >= (req.weeklyHours || 0) && (!req.requireInteraction || activityHasContributionThisWeek(rec));
    some = weekHours > 0 || activityEntriesThisWeek(rec) > 0;
  } else {
    weekHours = activityHoursThisWeek(rec);
    met = weekHours >= omegaWeeklyReq();
    some = weekHours > 0 || activityEntriesThisWeek(rec) > 0;
  }
  if (met) return { key:'active', label:'ACTIVE', auto:true };
  if (some) return { key:'semi', label:'SEMI-ACTIVE', auto:true };
  return { key:'inactive', label:'INACTIVE', auto:true };
}
function _activityLabel(key) {
  return key === 'active' ? 'ACTIVE' : key === 'semi' ? 'SEMI-ACTIVE' : key === 'inactive' ? 'INACTIVE' : key.toUpperCase();
}
function activityStatusClass(key) {
  return key === 'active' ? 'b-green' : key === 'semi' ? 'b-amber' : key === 'leave' ? 'b-cyan' : 'b-red';
}
// True if the file is in breach (under requirement and not on leave). Exempt: on leave,
// or Ethics non-Assistants, or when requirements aren't configured.
function activityInBreach(rec, unit) {
  if (!rec || !allActivityReqs) return false;
  if (getActiveLeave(rec)) return false;
  var st = activityStatus(rec, unit);
  // A manual 'active' override clears breach; otherwise breach = not active
  if (st.exempt) return false;
  if (st.manual) return st.key !== 'active';
  return st.key !== 'active';
}

// ── Activity section UI (Omega-1 + Ethics-Assistant personnel files) ──
function _fmtHrs(h) {
  if (typeof h !== 'number' || isNaN(h)) h = 0;
  return (Math.round(h * 100) / 100) + ' h';
}
// Short status label used in the collapsible section header.
function activityHdrLabel(rec, unit) {
  if (unit === 'ef' && rec.role !== 'Assistant') return '';
  var st = activityStatus(rec, unit);
  return ' · ' + st.label;
}
// ── Activity permission gates ──
// Who may LOG activity hours on a file: CL5 (command), the user linked to the
// file (their own activity), Senior CL4 (Omega-1 files), or Senior EC
// Chairman/Member (Ethics files). NOT junior members, and not other people's files.
function canLogActivity(p, unit) {
  if (!currentUser || !p) return false;
  if (parseInt(currentUser.clearance || '0') >= 5) return true;             // CL5 / command
  if (unit === 'pf' && currentUser.linkedPfId === p.id) return true;        // own Omega-1 file
  if (unit === 'ef' && currentUser.linkedEfId === p.id) return true;        // own Ethics file
  if (unit === 'pf' && currentUser.linkedPfId) {                            // Senior CL4 (Omega-1)
    var me = allPersonnel.find(function(x){ return x.id === currentUser.linkedPfId; });
    if (me && CL4_SENIOR_RANKS.includes(me.rank)) return true;
  }
  if (unit === 'ef') {                                                      // Senior EC (Ethics)
    var role = currentEfRole();
    if (role === 'Chairman' || role === 'Member') return true;
  }
  return false;
}
// Who may manually SET / clear / remove activity STATUS: Senior CL4 or CL5 only
// (Senior EC Chairman/Member for Ethics files). A user may NOT set the status on
// their own file below CL5 — status is a command assessment, not self-declared.
function canSetActivityStatus(p, unit) {
  if (!currentUser || !p) return false;
  var cl = parseInt(currentUser.clearance || '0');
  if (cl >= 5) return true;                                                 // CL5 unrestricted
  if (unit === 'pf' && currentUser.linkedPfId === p.id) return false;       // no self-setting
  if (unit === 'ef' && currentUser.linkedEfId === p.id) return false;       // no self-setting
  if (unit === 'pf' && currentUser.linkedPfId) {                            // Senior CL4 (Omega-1)
    var me = allPersonnel.find(function(x){ return x.id === currentUser.linkedPfId; });
    if (me && CL4_SENIOR_RANKS.includes(me.rank)) return true;
  }
  if (unit === 'ef') {                                                      // Senior EC (Ethics)
    var role = currentEfRole();
    if (role === 'Chairman' || role === 'Member') return true;
  }
  return false;
}
function buildActivitySection(p, unit) {
  unit = unit || 'pf';
  if (unit === 'ef' && p.role !== 'Assistant') {
    return '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ ' + e((p.role || 'EC').toUpperCase()) + ' ROLES ARE EXEMPT FROM ACTIVITY REQUIREMENTS ]</div>';
  }
  var st       = activityStatus(p, unit);
  var inBreach = activityInBreach(p, unit);
  var wk       = activityHoursThisWeek(p);
  var mo       = activityHoursThisMonth(p);
  var canLog   = canLogActivity(p, unit);        // Sr CL4 / CL5 / linked user
  var canCmd   = canSetActivityStatus(p, unit);  // Sr CL4 / CL5 (not own file below CL5)
  var log      = objArr(p.activityLog).sort(function(a, b){ return (b.at || 0) - (a.at || 0); });

  var reqWk, reqMo, reqLine;
  if (unit === 'ef') {
    var ea = (allActivityReqs && allActivityReqs.ethicsAssistant) || {};
    reqWk = ea.weeklyHours || 0; reqMo = 0;
    reqLine = 'REQUIREMENT · ' + reqWk + ' h/week' + (ea.requireInteraction ? ' + at least one logged contribution' : '');
  } else {
    reqWk = omegaWeeklyReq(); reqMo = omegaMonthlyReq();
    reqLine = 'REQUIREMENT · ' + reqWk + ' h/week · ' + reqMo + ' h/month';
  }
  var wkColor = wk >= reqWk ? 'green' : 'amber';
  var moColor = mo >= reqMo ? 'green' : 'amber';

  var html = '';
  // Status + figures
  html += '<div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:.4rem;">'
        +   '<span class="badge ' + activityStatusClass(st.key) + '" style="font-size:.55rem;">' + e(st.label) + '</span>'
        +   (st.manual ? '<span style="font-size:.5rem;color:var(--amber);">MANUAL OVERRIDE · EC·' + e(st.by || '—') + (st.at ? ' · ' + safeDate(st.at) : '') + '</span>' : '')
        +   (st.onLeave ? '<span style="font-size:.5rem;color:var(--text-faint);">authorised absence — requirement suspended</span>' : '')
        +   '<span style="font-size:.55rem;color:var(--text-dim);margin-left:auto;">'
        +     '<span style="color:var(--' + wkColor + ');">' + _fmtHrs(wk) + '</span> wk'
        +     (unit === 'ef' ? '' : ' · <span style="color:var(--' + moColor + ');">' + _fmtHrs(mo) + '</span> mo')
        +   '</span>'
        + '</div>';
  html += '<div style="font-size:.5rem;color:var(--text-faint);margin-bottom:.5rem;letter-spacing:.04em;">' + reqLine + '</div>';
  if (inBreach) {
    html += '<div style="border:1px solid #5a2a14;background:rgba(120,50,20,.18);color:var(--amber);font-size:.55rem;padding:.4rem .5rem;border-radius:var(--radius);margin-bottom:.5rem;">⚠ BELOW REQUIREMENT — operative is in breach of the current activity threshold.</div>';
  }

  // Command override controls
  if (canCmd) {
    html += '<div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.55rem;font-size:.55rem;">'
          +   '<span style="color:var(--text-faint);">OVERRIDE ·</span>'
          +   '<select id="actOverride_' + e(p.id) + '" class="modal-input" style="width:auto;font-size:.55rem;padding:2px 6px;">'
          +     '<option value="">— set status —</option>'
          +     '<option value="active"'   + (st.manual && st.key === 'active'   ? ' selected' : '') + '>Active</option>'
          +     '<option value="semi"'     + (st.manual && st.key === 'semi'     ? ' selected' : '') + '>Semi-Active</option>'
          +     '<option value="inactive"' + (st.manual && st.key === 'inactive' ? ' selected' : '') + '>Inactive</option>'
          +   '</select>'
          +   '<button class="pf-section-btn" data-action="set-activity-override" data-id="' + e(p.id) + '" data-unit="' + unit + '">[ APPLY ]</button>'
          +   (st.manual ? '<button class="pf-section-btn" data-action="clear-activity-override" data-id="' + e(p.id) + '" data-unit="' + unit + '" style="opacity:.85;">[ CLEAR ]</button>' : '')
          + '</div>';
  }

  // Log-entry form
  if (canLog) {
    html += '<div style="display:flex;gap:.35rem;flex-wrap:wrap;align-items:center;margin-bottom:.55rem;">'
          +   '<input id="actHours_' + e(p.id) + '" type="number" min="0" step="0.5" class="modal-input" placeholder="hrs" style="width:62px;font-size:.58rem;padding:3px 6px;"/>'
          +   '<input id="actNote_' + e(p.id) + '" class="modal-input" placeholder="What was done (op, patrol, training, contribution)..." style="flex:1;min-width:140px;font-size:.58rem;padding:3px 6px;"/>'
          +   '<input id="actTags_' + e(p.id) + '" class="modal-input" placeholder="tags (comma-sep)" style="width:120px;font-size:.58rem;padding:3px 6px;"/>'
          +   '<button class="pf-btn" data-action="add-activity" data-id="' + e(p.id) + '" data-unit="' + unit + '">[ LOG ]</button>'
          + '</div>';
  }

  // Log entries (most recent first)
  if (!log.length) {
    html += '<div style="font-size:.58rem;color:var(--text-faint);padding:3px 0;">[ NO ACTIVITY LOGGED ]</div>';
  } else {
    html += log.slice(0, 40).map(function(a){
      var tagHtml = (Array.isArray(a.tags) && a.tags.length)
        ? ' ' + a.tags.map(function(t){ return '<span class="badge b-cyan" style="font-size:.45rem;">' + e(t) + '</span>'; }).join(' ')
        : '';
      var del = canCmd
        ? '<button class="pf-section-btn" data-action="del-activity" data-id="' + e(p.id) + '" data-unit="' + unit + '" data-actid="' + e(a.id || '') + '" style="border-color:#4a1414;color:#dd4444;font-size:.45rem;padding:1px 5px;" title="Remove entry">✕</button>'
        : '';
      return '<div style="display:flex;justify-content:space-between;gap:.5rem;align-items:flex-start;border-bottom:1px solid var(--border);padding:.3rem 0;font-size:.58rem;">'
           +   '<span style="flex:1;"><span style="color:var(--green);font-family:\'VT323\',monospace;">' + _fmtHrs(a.hours || 0) + '</span> · '
           +     (a.note ? e(a.note) : '<span style="color:var(--text-faint);">no description</span>') + tagHtml
           +     '<br><span style="font-size:.48rem;color:var(--text-faint);">' + safeDateTime(a.at) + ' · logged by EC·' + e(a.by || '—') + '</span></span>'
           +   del
           + '</div>';
    }).join('');
    if (log.length > 40) html += '<div style="font-size:.5rem;color:var(--text-faint);padding-top:.3rem;">… showing 40 most recent of ' + log.length + ' entries</div>';
  }
  return html;
}

// ── Activity logging actions (unit-generic: 'pf' = Omega-1, 'ef' = Ethics) ──
function _activityRec(id, unit) {
  var arr = unit === 'ef' ? allEthicsPersonnel : allPersonnel;
  return (arr || []).find(function(p){ return p.id === id; });
}
function _activityPersist(rec, unit) {
  return unit === 'ef' ? ethicsPersonnelSet(rec.id, rec) : personnelSet(rec.id, rec);
}
function _activityReRender(unit) {
  if (unit === 'ef') renderEthicsFiles(); else renderPersonnelFiles();
  try { renderOverview(); } catch (_) {}
}
async function addActivityEntry(id, unit) {
  unit = unit || 'pf';
  var rec = _activityRec(id, unit);
  if (!rec) return;
  if (!canLogActivity(rec, unit)) { alert('You do not have authority to log activity on this file.'); return; }
  var hEl = document.getElementById('actHours_' + id);
  var nEl = document.getElementById('actNote_'  + id);
  var tEl = document.getElementById('actTags_'  + id);
  if (!hEl) return;
  var hours = parseFloat(hEl.value);
  if (isNaN(hours) || hours <= 0) { alert('Enter a positive number of hours.'); return; }
  if (hours > 168)               { alert('Hours per entry cannot exceed 168 (one week).'); return; }
  hours = Math.round(hours * 100) / 100;
  var note = (nEl ? nEl.value : '').trim();
  var tags = (tEl ? tEl.value : '').split(',').map(function(s){ return s.trim(); }).filter(Boolean).slice(0, 8);
  var entry = {
    id:    'act_' + Date.now() + '_' + Math.random().toString(36).slice(2, 5),
    at:    Date.now(),
    hours: hours,
    note:  note,
    tags:  tags,
    by:    currentUser.id
  };
  if (!Array.isArray(rec.activityLog)) rec.activityLog = [];
  rec.activityLog.push(entry);
  hEl.disabled = true;
  try {
    await _activityPersist(rec, unit);
    auditRecord('LOGGED ACTIVITY', (unit === 'ef' ? 'EC·' : 'Ω·') + (rec.name || rec.id) + ' · ' + hours + 'h' + (note ? ' · ' + note : ''));
  } catch (err) { rec.activityLog.pop(); alert('ERROR: ' + err.message); }
  hEl.disabled = false;
  _activityReRender(unit);
}
async function removeActivityEntry(id, unit, actId) {
  unit = unit || 'pf';
  var rec = _activityRec(id, unit);
  if (!rec || !Array.isArray(rec.activityLog)) return;
  if (!canSetActivityStatus(rec, unit)) { alert('Senior command authority (Sr CL4 / CL5) required to remove activity entries.'); return; }
  if (!(await pfConfirm('Remove this activity entry? This cannot be undone.'))) return;
  var idx = rec.activityLog.findIndex(function(a){ return a && a.id === actId; });
  if (idx < 0) return;
  var removed = rec.activityLog.splice(idx, 1)[0];
  try {
    await _activityPersist(rec, unit);
    auditRecord('REMOVED ACTIVITY', (unit === 'ef' ? 'EC·' : 'Ω·') + (rec.name || rec.id) + ' · ' + (removed.hours || 0) + 'h');
  } catch (err) { rec.activityLog.splice(idx, 0, removed); alert('ERROR: ' + err.message); }
  _activityReRender(unit);
}
async function setActivityOverride(id, unit) {
  unit = unit || 'pf';
  var rec = _activityRec(id, unit);
  if (!rec) return;
  if (!canSetActivityStatus(rec, unit)) { alert('Only Sr CL4 / CL5 may set activity status. You cannot set your own.'); return; }
  var sel = document.getElementById('actOverride_' + id);
  if (!sel || !sel.value) return;
  var status = sel.value;
  var prev = rec.activityOverride;
  rec.activityOverride = { status: status, by: currentUser.id, at: Date.now() };
  try {
    await _activityPersist(rec, unit);
    auditRecord('SET ACTIVITY OVERRIDE', (unit === 'ef' ? 'EC·' : 'Ω·') + (rec.name || rec.id) + ' → ' + status.toUpperCase());
  } catch (err) { rec.activityOverride = prev; alert('ERROR: ' + err.message); }
  _activityReRender(unit);
}
async function clearActivityOverride(id, unit) {
  unit = unit || 'pf';
  var rec = _activityRec(id, unit);
  if (!rec || !rec.activityOverride) return;
  if (!canSetActivityStatus(rec, unit)) { alert('Only Sr CL4 / CL5 may change activity status.'); return; }
  var prev = rec.activityOverride;
  delete rec.activityOverride;
  try {
    await _activityPersist(rec, unit);
    auditRecord('CLEARED ACTIVITY OVERRIDE', (unit === 'ef' ? 'EC·' : 'Ω·') + (rec.name || rec.id));
  } catch (err) { rec.activityOverride = prev; alert('ERROR: ' + err.message); }
  _activityReRender(unit);
}

// ================================================================
//  PROMOTION REQUIREMENTS (Omega-1, CL5-editable)
// ================================================================
// Requirements are keyed by rank transition "From>To". Each value is an array of
// { id, text } items. A personnel file tracks which items it has met toward its
// NEXT rank in p.promoProgress (reset automatically on any rank change).
var allPromoReqs = null; // map: { "From>To": [ {id,text}, ... ] }

// Ordered low→high rank progression (the order operatives advance through).
var PROMO_ORDER = ['Private','Specialist','Lance Corporal','Corporal','Sergeant','Command Sergeant','Lieutenant'];
function promoNextRank(rank) {
  var i = PROMO_ORDER.indexOf(rank);
  if (i === -1 || i >= PROMO_ORDER.length - 1) return null;
  return PROMO_ORDER[i + 1];
}
function promoKey(fromRank, toRank) { return fromRank + '>' + toRank; }

// Default requirements (seeded on first load; CL5 can edit/extend afterwards).
function defaultPromoReqs() {
  function mk(arr){ return arr.map(function(t,i){ return { id: 'r'+(i+1), text: t }; }); }
  return {
    'Private>Specialist': mk([]),
    'Specialist>Lance Corporal': mk([]),
    'Lance Corporal>Corporal': mk([
      'Host a training while being observed by a Lieutenant or above, or a personnel tagged with "Development Manager" or "Development Assistant".',
      'Complete Personnel File.',
      'Pass the NCO Questionnaire.'
    ]),
    'Corporal>Sergeant': mk([
      'Lead an Escort while being observed by a Lieutenant or above, or a personnel tagged with "Development Manager" or "Development Assistant".',
      'Scout 1 Potential New Candidate.',
      'Join a Squadron.',
      'Pass the Leadership Questionnaire.'
    ]),
    'Sergeant>Command Sergeant': mk([
      'Mentor a new operative through the ranks of PVT and SPC.',
      'Host Regular Patrols / Trainings / Scouts.',
      'Lead or play a Major Role in a Roleplay Scenario while being observed by a Lieutenant or above.'
    ]),
    'Command Sergeant>Lieutenant': mk([
      'Promotions to Lieutenant and above are assessed on a case-by-case basis by command.'
    ]),
    __meta: {
      caseByCaseFrom: 'Lieutenant',
      caseByCaseNote: 'This operative is at the top of the standard progression. Further advancement is assessed on a case-by-case basis by command.'
    }
  };
}
// Configurable case-by-case threshold (CL5-editable in the admin menu).
// Ranks at or above caseByCaseFrom (by seniority) are command-discretion: they
// show caseByCaseNote instead of a requirements checklist.
function getPromoMeta() {
  var m = (allPromoReqs && allPromoReqs.__meta) || {};
  return {
    caseByCaseFrom: m.caseByCaseFrom || 'Lieutenant',
    caseByCaseNote: m.caseByCaseNote || 'This operative is at the top of the standard progression. Further advancement is assessed on a case-by-case basis by command.'
  };
}
async function promoReqsGetAll() {
  if (firebaseReady) { var all = await fbGetAll('/promoReqs'); return all || null; }
  var raw = lsGet('promoReqs/config');
  return raw || null;
}
async function promoReqsSave() {
  if (firebaseReady) await fbSet('/promoReqs', allPromoReqs);
  else lsSet('promoReqs/config', allPromoReqs);
}
async function loadPromoReqs() {
  try {
    var stored = await promoReqsGetAll();
    if (stored && typeof stored === 'object') {
      allPromoReqs = stored;
      // Backfill any transitions missing from stored config (e.g. after an app update)
      var defs = defaultPromoReqs(), changed = false;
      Object.keys(defs).forEach(function(k){ if (!allPromoReqs[k]) { allPromoReqs[k] = defs[k]; changed = true; } });
      if (changed) { try { await promoReqsSave(); } catch(_){} }
    } else {
      allPromoReqs = defaultPromoReqs();
      try { await promoReqsSave(); } catch(_){}
    }
  } catch(e) { allPromoReqs = defaultPromoReqs(); }
}
// Requirement items for a file's next promotion (null if top of ladder / none defined).
function promoReqsFor(rank) {
  if (!allPromoReqs) return null;
  var next = promoNextRank(rank);
  if (!next) return null;
  return { next: next, items: allPromoReqs[promoKey(rank, next)] || [] };
}

// ================================================================
//  COMPARTMENTS (need-to-know access programs)
// ================================================================
// A compartment is a named access program. Members are "read into" compartments
// via grants on their user record (rec.compartments = [id,...]). Content tagged
// with a compartment requires BOTH sufficient clearance AND the grant to view.
var allCompartments = [];

async function compartmentsGetAll() {
  if (firebaseReady) {
    var all = await fbGetAll('/compartments');
    return all ? Object.values(all) : [];
  }
  return Object.values(lsAll('compartments/'));
}
async function compartmentSet(id, data) {
  var k = 'compartments/' + safeKey(id);
  if (firebaseReady) await fbSet('/' + k, data);
  else lsSet(k, data);
}
async function compartmentDel(id) {
  var k = 'compartments/' + safeKey(id);
  if (firebaseReady) await fbDelete('/' + k);
  else lsDel(k);
}
async function loadCompartments() {
  try {
    var raw = await compartmentsGetAll();
    allCompartments = (raw || []).filter(function(c){ return c && c.id; });
    allCompartments.sort(function(a,b){ return (a.name||'').localeCompare(b.name||''); });
  } catch(e) { allCompartments = []; }
}
function compartmentName(id) {
  var c = allCompartments.find(function(x){ return x.id === id; });
  return c ? c.name : null;
}
// Does the current user hold a given compartment grant? CL5 holds all (Overseer access).
function userHasCompartment(compId) {
  if (!compId) return true; // untagged content is open at clearance level
  if (currentUser && parseInt(currentUser.clearance) >= 5) return true;
  if (!currentUser) return false;
  var grants = currentUser.compartments;
  return Array.isArray(grants) && grants.indexOf(compId) !== -1;
}

// Populate a <select> with the available compartments (used by the order form).
function populateCompartmentSelect(selectId, selectedVal) {
  var sel = document.getElementById(selectId);
  if (!sel) return;
  // Lazy-load the registry if it hasn't been fetched yet this session.
  if (!allCompartments.length) {
    loadCompartments().then(function(){ fillCompartmentSelect(sel, selectedVal); });
    return;
  }
  fillCompartmentSelect(sel, selectedVal);
}
function fillCompartmentSelect(sel, selectedVal) {
  var cur = selectedVal !== undefined ? selectedVal : sel.value;
  var opts = '<option value="">OPEN (no compartment)</option>';
  allCompartments.forEach(function(c){
    opts += '<option value="' + e(c.id) + '"' + (c.id === cur ? ' selected' : '') + '>' +
            e((c.code ? c.code + ' — ' : '') + (c.name || '')) + '</option>';
  });
  sel.innerHTML = opts;
}


// ================================================================
//  ORDERS
// ================================================================
var allOrders = [], activeFilter = 'ALL', pollTimer = null;
// ── Soft-delete (recycle bin) ──
// Deleted records are kept (with deleted/deletedBy/deletedAt) and partitioned out of the
// live arrays so every existing render automatically excludes them. CL5 can restore or purge.
var deletedPersonnel = [], deletedEthics = [], deletedOrders = [], deletedEthicsOrders = [];
// Partition a freshly-loaded record list into [live, deleted], routing deleted ones to a sink.
function partitionDeleted(records, assignSink) {
  var live = [], dead = [];
  (records || []).forEach(function(r){
    if (r && r.deleted) dead.push(r); else if (r) live.push(r);
  });
  if (typeof assignSink === 'function') assignSink(dead);
  return live;
}
var expandedOrders = new Set();   // tracks which order cards are showing comments
var commentCache   = {};          // orderId → array of comment objects (client cache)

async function loadOrders() {
  try {
    var raw = await ordersGetAll();
    allOrders = partitionDeleted(raw.filter(function(o) { return o && o.id; }), function(d){ deletedOrders = d; });
    allOrders.sort(function(a, b) { return b.created - a.created; });
    document.getElementById('refreshNote').textContent =
      'last sync ' + new Date().toISOString().slice(11,19) + ' UTC';
  } catch(e) {
    document.getElementById('refreshNote').textContent = 'sync error';
  }
  renderOrders();
  updateOrderBadge();
}

// ================================================================
//  MY ACCOUNT — self-service view for the logged-in user
// ================================================================
async function openMyAccount() {
  if (!currentUser) return;
  document.getElementById('myAccountModal').classList.add('open');
  var body = document.getElementById('myAccountBody');
  body.innerHTML = '<div style="font-size:.62rem;color:var(--text-faint);padding:.5rem;">[ LOADING... ]</div>';

  var rec = null;
  try { rec = await userGet(currentUser.id); } catch(_) {}
  if (!rec) rec = {};

  // Resolve linked file
  var fileInfo = '<span style="color:var(--text-faint);">[ NO FILE LINKED ]</span>';
  if (rec.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === rec.linkedPfId; });
    fileInfo = pf ? '<span class="badge b-cyan">Ω-1: ' + e(pf.name) + ' [' + e(pf.rank) + ']</span>'
                  : '<span style="color:var(--amber);">Ω-1 file (ID ' + e(rec.linkedPfId) + ')</span>';
  } else if (rec.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === rec.linkedEfId; });
    fileInfo = ef ? '<span class="badge b-amber">EC: ' + e(ef.name) + ' [' + e(ef.role) + ']</span>'
                  : '<span style="color:var(--amber);">EC file (ID ' + e(rec.linkedEfId) + ')</span>';
  }

  // Clearance label
  var clLabels = { '3':'Level 3 — Standard Access', '4':'Level 4 — Senior Access', '5':'Level 5 — Command Access' };
  var clLabel = clLabels[currentUser.clearance] || ('Level ' + currentUser.clearance);

  // Unit
  var unitLabel = rec.unit === 'omega1' ? 'OMEGA-1' : rec.unit === 'ethics' ? 'ETHICS COMMITTEE' : '—';

  // Strikes on linked file
  var myStrikes = [];
  var linkedRec = rec.linkedPfId ? allPersonnel.find(function(p){return p.id===rec.linkedPfId;})
                : rec.linkedEfId ? allEthicsPersonnel.find(function(p){return p.id===rec.linkedEfId;}) : null;
  if (linkedRec && Array.isArray(linkedRec.strikes)) {
    myStrikes = linkedRec.strikes.filter(function(s){ return isStrikeActive(s); });
  }
  var strikeInfo = myStrikes.length
    ? '<span class="badge b-red">' + myStrikes.length + ' ACTIVE STRIKE' + (myStrikes.length>1?'S':'') + '</span>'
    : '<span class="badge b-green">NO ACTIVE STRIKES</span>';

  var joinDate = rec.created ? safeDate(rec.created) : '—';
  var lastLoginStr = rec.lastLogin ? safeDateTime(rec.lastLogin) + ' UTC' : '—';
  var loginCountStr = rec.loginCount ? (rec.loginCount + ' total') : '—';
  var recoveryCount = Array.isArray(rec.recoveryCodes) ? rec.recoveryCodes.filter(function(c){ return !c.used; }).length : 0;
  var recoveryStr = Array.isArray(rec.recoveryCodes)
    ? (recoveryCount + ' unused of ' + rec.recoveryCodes.length)
    : '<span style="color:var(--amber);">none — generate below</span>';

  function row(label, val) {
    return '<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);font-size:.64rem;">'
      + '<span style="color:var(--text-dim);">' + label + '</span>'
      + '<span style="color:var(--text);text-align:right;">' + val + '</span></div>';
  }

  body.innerHTML =
      row('MEMBER ID', 'EC·' + e(currentUser.id))
    + row('CLEARANCE', e(clLabel))
    + row('UNIT', e(unitLabel))
    + row('HOME SITE', e(rec.site || '— Unassigned —'))
    + row('PROGRAMS', (Array.isArray(rec.compartments) && rec.compartments.length
        ? rec.compartments.map(function(id){ return e(compartmentName(id) || id); }).join(', ')
        : '— None —'))
    + row('LINKED FILE', fileInfo)
    + row('STANDING', strikeInfo)
    + row('REGISTERED', joinDate)
    + row('LAST SIGN-IN', lastLoginStr)
    + row('SIGN-INS', loginCountStr)
    + row('RECOVERY CODES', recoveryStr)
    + (myStrikes.length
        ? '<div style="margin-top:.6rem;font-size:.58rem;color:var(--amber);border-left:2px solid #4a3a14;padding-left:.6rem;line-height:1.6;">⚠ You have ' + myStrikes.length + ' active strike(s) on your file. You may submit an appeal from your personnel file.</div>'
        : '');
}
function closeMyAccount() { document.getElementById('myAccountModal').classList.remove('open'); }

// ── Self-service passphrase change ──
function openChangePass() {
  document.getElementById('changePassCurrent').value = '';
  document.getElementById('changePassNew').value     = '';
  document.getElementById('changePassConfirm').value = '';
  document.getElementById('changePassErr').textContent = '';
  document.getElementById('changePassModal').classList.add('open');
}
function closeChangePass() { document.getElementById('changePassModal').classList.remove('open'); }
async function saveChangePass() {
  if (!currentUser) return;
  var cur  = document.getElementById('changePassCurrent').value;
  var nw   = document.getElementById('changePassNew').value.trim();
  var conf = document.getElementById('changePassConfirm').value.trim();
  var errEl = document.getElementById('changePassErr');
  if (!cur || !nw || !conf) { errEl.textContent = '> ALL FIELDS REQUIRED'; return; }
  if (nw.length < 3)        { errEl.textContent = '> NEW PASSPHRASE TOO SHORT (MIN 3)'; return; }
  if (nw !== conf)          { errEl.textContent = '> NEW PASSPHRASES DO NOT MATCH'; return; }
  var rec = null;
  try { rec = await userGet(currentUser.id); } catch(_) {}
  if (!rec) { errEl.textContent = '> COULD NOT LOAD ACCOUNT'; return; }
  var v = await verifyPass(rec, cur);
  if (!v.ok) { errEl.textContent = '> CURRENT PASSPHRASE INCORRECT'; return; }
  var cred = await makeCredential(nw);
  applyCredential(rec, cred);
  rec.passChangedAt = Date.now();
  try {
    await userSet(currentUser.id, rec);
    closeChangePass();
    closeMyAccount();
    alert('Passphrase updated successfully.');
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

// ── Login notifications: surface pending actions relevant to the user ──
// ── Command Overview dashboard ──
// True when the Overview tab is the one currently displayed.
function overviewIsActive() {
  var t = document.getElementById('tab-overview');
  return !!(t && t.classList.contains('active'));
}
// Re-render the dashboard only if it's the active tab (used by live-sync hooks).
function refreshOverviewIfActive() {
  if (overviewIsActive()) renderOverview();
}
// Lightweight heartbeat so the clock and time-relative figures stay fresh between
// the 30 s background data polls. Re-renders every 15 s while the tab is open.
var _overviewHeartbeat = null;
function startOverviewHeartbeat() {
  stopOverviewHeartbeat();
  _overviewHeartbeat = setInterval(function(){
    if (overviewIsActive()) renderOverview(); else stopOverviewHeartbeat();
  }, 15000);
}
function stopOverviewHeartbeat() {
  if (_overviewHeartbeat) { clearInterval(_overviewHeartbeat); _overviewHeartbeat = null; }
}
// Programmatically activate a tab by id (used by dashboard click-throughs).
function goToTab(id) {
  var el = document.querySelector('.nav-tab[onclick*="\'' + id + '\'"], .nav-standalone-tab[onclick*="\'' + id + '\'"]');
  if (el) { switchTab(el, id); return; }
  // Fallback: activate the content panel directly if the nav item isn't found.
  document.querySelectorAll('.tab-content').forEach(function(t){ t.classList.remove('active'); });
  var tab = document.getElementById('tab-' + id);
  if (tab) tab.classList.add('active');
}
function ovCard(title, value, sub, accent, tab, urgent) {
  var click = tab ? ' onclick="goToTab(\'' + tab + '\')" style="cursor:pointer;"' : '';
  return '<div class="ov-card' + (urgent ? ' ov-urgent' : '') + '"' + click + '>'
    + '<div class="ov-val" style="color:' + (accent || 'var(--green)') + ';">' + value + '</div>'
    + '<div class="ov-title">' + e(title) + '</div>'
    + (sub ? '<div class="ov-sub">' + e(sub) + '</div>' : '')
    + '</div>';
}
function renderOverview() {
  var el = document.getElementById('overviewBody');
  if (!el) return;
  if (!currentUser) { el.innerHTML = '<div style="color:var(--text-faint);font-size:.6rem;">Authenticate to view command overview.</div>'; return; }
  var cl = parseInt(currentUser.clearance || '3');
  var cards = [];
  var alerts = [];

  // ── Safety-critical (CL5): active duress signals ──
  if (cl >= 5) {
    var duress = Object.values(allUsers || {}).filter(function(u){ return u && u.duressActive; });
    if (duress.length) {
      alerts.push(ovCard('ACTIVE DURESS SIGNAL' + (duress.length>1?'S':''), duress.length,
        duress.map(function(u){ return u.displayId || u.id; }).slice(0,3).join(', '), 'var(--red)', null, true));
    }
  }

  // ── Integrity holds (senior CL4 + CL5): compromised / impostor-review ──
  if (canViewFileIntegrity && canViewFileIntegrity()) {
    var holds = Object.values(allUsers || {}).filter(function(u){
      return u && (u.integrityStatus === 'compromised' || u.integrityStatus === 'impostor-review');
    });
    if (holds.length) {
      alerts.push(ovCard('SECURITY HOLDS', holds.length, 'compromised / impostor review', 'var(--red)', null, true));
    }
  }

  // ── Pending registrations (CL5) ──
  if (cl >= 5) {
    var pending = Object.values(allUsers || {}).filter(function(u){ return u && u.status === 'pending'; }).length;
    cards.push(ovCard('Registrations Pending', pending, pending ? 'awaiting approval' : 'all clear',
      pending ? 'var(--amber)' : 'var(--green)', 'log'));
  }

  // ── Recruitment votes awaiting this user (CL4+) ──
  if (cl >= 4) {
    var votesO = (allRecruitment || []).filter(function(r){ return r.stage === 'scouting' && !(r.votes && r.votes[currentUser.id]); }).length;
    var votesE = (allEthicsRecruit || []).filter(function(r){ return r.stage === 'application' && !(r.votes && r.votes[currentUser.id]); }).length;
    if (votesO) cards.push(ovCard('Omega-1 Votes', votesO, 'recruits awaiting your vote', 'var(--amber)', 'recruit'));
    if (votesE) cards.push(ovCard('Ethics Votes', votesE, 'applications awaiting your vote', 'var(--amber)', 'ethics-recruit'));
  }

  // ── Strike appeals to review (CL5) ──
  if (cl >= 5) {
    var appeals = 0;
    (allPersonnel || []).concat(allEthicsPersonnel || []).forEach(function(p){
      if (Array.isArray(p.strikes)) appeals += p.strikes.filter(function(s){ return s.status === 'Appealed' && s.appeal && !s.appeal.resolution; }).length;
    });
    if (appeals) cards.push(ovCard('Strike Appeals', appeals, 'awaiting review', 'var(--amber)', 'blacklist'));
  }

  // ── Promotion-ready Omega-1 operatives (CL4+) ──
  if (cl >= 4 && allPromoReqs) {
    var ready = (allPersonnel || []).filter(function(p){
      if (!p || p.status !== 'Active') return false;
      var info = promoReqsFor(p.rank);
      if (!info || !info.items || !info.items.length) return false;
      var prog = (p.promoProgress && typeof p.promoProgress === 'object') ? p.promoProgress : {};
      return info.items.every(function(it){ return prog[it.id] && prog[it.id].met; });
    });
    if (ready.length) {
      cards.push(ovCard('Promotion-Ready', ready.length, ready.map(function(p){ return p.name; }).slice(0,3).join(', '), 'var(--green)', 'personnel-files'));
    }
  }

  // ── Active orders by priority (everyone) ──
  var liveOrders = (allOrders || []).filter(function(o){ return o.status !== 'CANCELLED' && o.status !== 'ARCHIVED' && !orderIsRestricted(o); });
  var crit = liveOrders.filter(function(o){ return (o.priority||'').toUpperCase() === 'CRITICAL'; }).length;
  cards.push(ovCard('Active Directives', liveOrders.length, crit ? crit + ' critical' : 'omega-1 orders', crit ? 'var(--red)' : 'var(--green)', 'orders'));

  // ── Personnel on active leave (CL4+) ──
  if (cl >= 4) {
    var onLeave = (allPersonnel || []).filter(function(p){
      return Array.isArray(p.leave) && p.leave.some(function(l){ return isLeaveActive ? isLeaveActive(l) : (l && l.status === 'active'); });
    }).length;
    if (onLeave) cards.push(ovCard('On Leave', onLeave, 'LOA / ROA active', 'var(--text-dim)', 'roster'));
  }

  // ── Recycle bin (CL5) ──
  if (cl >= 5) {
    var binCount = recycleBinCount();
    if (binCount) cards.push(ovCard('Recycle Bin', binCount, 'deleted items recoverable', 'var(--text-dim)', null));
  }

  var greeting = '<div style="font-size:.62rem;color:var(--text-dim);margin-bottom:.7rem;line-height:1.5;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;">'
    + '<span>Welcome, <span style="color:var(--green);">EC·' + e(currentUser.id) + '</span> · Clearance Level ' + e(currentUser.clearance)
    + ' · ' + e(safeDateTime(Date.now())) + ' UTC</span>'
    + '<span style="font-size:.5rem;letter-spacing:.1em;color:var(--green-dim);border:1px solid var(--border2);border-radius:8px;padding:1px 7px;display:inline-flex;align-items:center;gap:4px;"><span class="ov-live-dot"></span>LIVE</span></div>';

  var alertBlock = alerts.length
    ? '<div style="font-size:.55rem;letter-spacing:.12em;color:var(--red);margin:.2rem 0 .4rem;">⚠ REQUIRES ATTENTION</div><div class="ov-grid">' + alerts.join('') + '</div>'
    : '';
  var cardBlock = '<div class="ov-grid" style="margin-top:.7rem;">' + cards.join('') + '</div>';

  el.innerHTML = greeting + alertBlock + cardBlock;
}

function showLoginNotifications() {
  if (!currentUser) return;
  var banner = document.getElementById('notifBanner');
  if (!banner) return;
  var cl = parseInt(currentUser.clearance || '3');
  var items = [];

  if (cl >= 4) {
    var needVoteO = allRecruitment.filter(function(r){
      return r.stage === 'scouting' && !(r.votes && r.votes[currentUser.id]);
    }).length;
    if (needVoteO) items.push('🗳 ' + needVoteO + ' Omega-1 recruit' + (needVoteO>1?'s':'') + ' awaiting your vote');

    var needVoteE = allEthicsRecruit.filter(function(r){
      return r.stage === 'application' && !(r.votes && r.votes[currentUser.id]);
    }).length;
    if (needVoteE) items.push('🗳 ' + needVoteE + ' Ethics application' + (needVoteE>1?'s':'') + ' awaiting your vote');
  }

  if (cl >= 5) {
    var pendingRegs = Object.values(allUsers).filter(function(u){ return u.status === 'pending'; }).length;
    if (pendingRegs) items.push('👤 ' + pendingRegs + ' registration' + (pendingRegs>1?'s':'') + ' awaiting approval');

    var appeals = 0;
    allPersonnel.concat(allEthicsPersonnel).forEach(function(p){
      if (Array.isArray(p.strikes)) appeals += p.strikes.filter(function(s){
        return s.status === 'Appealed' && s.appeal && !s.appeal.resolution;
      }).length;
    });
    if (appeals) items.push('⚖ ' + appeals + ' strike appeal' + (appeals>1?'s':'') + ' awaiting review');
  }

  var myRec = currentUser.linkedPfId ? allPersonnel.find(function(p){return p.id===currentUser.linkedPfId;})
            : currentUser.linkedEfId ? allEthicsPersonnel.find(function(p){return p.id===currentUser.linkedEfId;}) : null;
  if (myRec && Array.isArray(myRec.strikes)) {
    var myActive = myRec.strikes.filter(function(s){ return isStrikeActive(s); }).length;
    if (myActive) items.push('⚠ You have ' + myActive + ' active strike' + (myActive>1?'s':'') + ' on your file');
  }

  if (!items.length) { banner.style.display = 'none'; return; }
  banner.innerHTML = '▸ ' + items.join('  ·  ') + '  <span style="color:var(--text-faint);">(click to dismiss)</span>';
  banner.style.display = 'block';
}
function dismissNotif() {
  var b = document.getElementById('notifBanner');
  if (b) b.style.display = 'none';
}

// ================================================================
//  AUDIT LOG — records admin/sensitive actions (CL5 view only)
// ================================================================
var allAuditLog = [];

async function auditGetAll() {
  if (firebaseReady) { var r = await fbGetAll('/auditLog'); return r ? Object.values(r).filter(function(x){return x&&x.id;}) : []; }
  return Object.values(lsAll('auditLog/')).filter(function(x){return x&&x.id;});
}
// Record an action. Fire-and-forget — never blocks the calling action.
function auditRecord(action, detail, byOverride) {
  var actor = currentUser ? currentUser.id : byOverride;
  if (!actor) return;
  var entry = {
    id: 'aud_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    action: action, detail: detail || '',
    by: actor, at: Date.now()
  };
  try {
    if (firebaseReady) fbSet('/auditLog/' + entry.id, entry);
    else lsSet('auditLog/' + entry.id, entry);
    allAuditLog.push(entry);
  } catch(_) {}
}

async function loadAuditLog() {
  try { allAuditLog = await auditGetAll(); } catch(_) { allAuditLog = []; }
  renderAuditLog();
}

// ================================================================
//  DATA EXPORT — CSV download for directory, roster, audit log (CL5)
// ================================================================
// RFC-4180 CSV field escaping: wrap in quotes if it contains comma/quote/newline.
function csvCell(v) {
  var s = (v === undefined || v === null) ? '' : String(v);
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}
// Build a CSV string from an array of header keys and an array of row objects.
function buildCSV(headers, rows) {
  var head = headers.map(function(h){ return csvCell(h.label); }).join(',');
  var body = rows.map(function(r){
    return headers.map(function(h){ return csvCell(h.get(r)); }).join(',');
  }).join('\r\n');
  return head + '\r\n' + body;
}
// Trigger a browser download of text as a file.
function downloadFile(filename, text, mime) {
  try {
    var blob = new Blob([text], { type: (mime || 'text/csv') + ';charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
  } catch(err) { alert('Export failed: ' + err.message); }
}
function exportStamp() { return new Date().toISOString().slice(0,10); }

// Export the user directory (respects nothing — full account list, CL5 only).
function exportUsersCSV() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var rows = Object.values(allUsers);
  var headers = [
    { label:'Member ID',      get:function(u){ return u.displayId || ''; } },
    { label:'Clearance',      get:function(u){ return 'CL' + (u.clearance||'3'); } },
    { label:'Status',         get:function(u){ return u.status || 'active'; } },
    { label:'Unit',           get:function(u){ return u.unit==='omega1'?'Omega-1':u.unit==='ethics'?'Ethics':''; } },
    { label:'Home Site',      get:function(u){ return u.site || ''; } },
    { label:'Linked File',    get:function(u){ return u.linkedPfId || u.linkedEfId || ''; } },
    { label:'Registered',     get:function(u){ return u.created ? safeDate(u.created) : ''; } },
    { label:'Last Sign-In',   get:function(u){ return u.lastLogin ? safeDateTime(u.lastLogin) : ''; } },
    { label:'Sign-In Count',  get:function(u){ return u.loginCount || 0; } },
    { label:'Locked',         get:function(u){ return (u.lockedUntil && Date.now()<u.lockedUntil) ? 'YES' : ''; } },
    { label:'Status Reason',  get:function(u){ return u.statusReason || ''; } }
  ];
  downloadFile('cairo-users-' + exportStamp() + '.csv', buildCSV(headers, rows));
  auditRecord('EXPORTED', 'user directory (' + rows.length + ' accounts)');
}

// Export the audit log (CL5 only).
function exportAuditCSV() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var rows = allAuditLog.slice().sort(function(a,b){ return b.at - a.at; });
  var headers = [
    { label:'Timestamp (UTC)', get:function(a){ return safeDateTime(a.at); } },
    { label:'Actor',           get:function(a){ return a.by || ''; } },
    { label:'Action',          get:function(a){ return a.action || ''; } },
    { label:'Detail',          get:function(a){ return a.detail || ''; } }
  ];
  downloadFile('cairo-audit-' + exportStamp() + '.csv', buildCSV(headers, rows));
}

// Export a personnel roster. system: 'pf' (Omega-1) or 'ef' (Ethics). CL5 only for full export.
function exportRosterCSV(system) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var isEf = system === 'ef';
  var rows = (isEf ? allEthicsPersonnel : allPersonnel).slice();
  var headers = [
    { label:'Name',       get:function(p){ return p.name || ''; } },
    { label:'Codename',   get:function(p){ return p.nickname || ''; } },
    { label: isEf?'Role':'Rank', get:function(p){ return isEf ? (p.role||'') : (p.rank||''); } },
    { label:'Date of Birth', get:function(p){ return p.dob || ''; } },
    { label:'Status',     get:function(p){ return p.status || 'Active'; } },
    { label:'Active Strikes', get:function(p){ return Array.isArray(p.strikes) ? p.strikes.filter(isStrikeActive).length : 0; } }
  ];
  downloadFile('cairo-' + (isEf?'ethics':'omega1') + '-roster-' + exportStamp() + '.csv', buildCSV(headers, rows));
  auditRecord('EXPORTED', (isEf?'Ethics':'Omega-1') + ' roster (' + rows.length + ' personnel)');
}

function renderAuditLog() {
  var el = document.getElementById('adminAuditList');
  if (!el) return;
  var sorted = allAuditLog.slice().sort(function(a,b){ return b.at - a.at; }).slice(0, 100);
  if (!sorted.length) {
    el.innerHTML = '<div style="font-size:.6rem;color:var(--text-faint);padding:.4rem;">[ NO AUDIT ENTRIES ]</div>';
    return;
  }
  el.innerHTML = sorted.map(function(a) {
    var dt = safeDateTime(a.at);
    return '<div style="font-size:.58rem;border-bottom:1px solid var(--border);padding:3px 4px;display:flex;justify-content:space-between;gap:.5rem;">'
      + '<span><span style="color:var(--amber);">' + e(a.action) + '</span>'
      + (a.detail ? ' <span style="color:var(--text);">' + e(a.detail) + '</span>' : '') + '</span>'
      + '<span style="color:var(--text-faint);white-space:nowrap;">EC·' + e(a.by) + ' · ' + dt + '</span>'
      + '</div>';
  }).join('');
}

// ================================================================
//  BLACKLIST REGISTRY
// ================================================================
var allBlacklistConfigs = [];
var allBlacklistEntries = [];
var blSheetCache = {};
var blCollapsed  = new Set();
var blSheetExpanded = new Set(); // dept IDs whose Google Sheet data is expanded

async function blConfigGetAll() {
  if (firebaseReady) { var r = await fbGetAll('/blacklistConfig'); return r ? Object.values(r).filter(function(x){return x&&x.id;}) : []; }
  return Object.values(lsAll('blacklistConfig/')).filter(function(x){return x&&x.id;});
}
async function blConfigSet(id, data) {
  if (firebaseReady) await fbSet('/blacklistConfig/' + id, data);
  else lsSet('blacklistConfig/' + id, data);
}
async function blConfigDel(id) {
  if (firebaseReady) await fbDel('/blacklistConfig/' + id);
  else lsDel('blacklistConfig/' + id);
}
async function blEntryGetAll() {
  if (firebaseReady) { var r = await fbGetAll('/blacklist'); return r ? Object.values(r).filter(function(x){return x&&x.id;}) : []; }
  return Object.values(lsAll('blacklist/')).filter(function(x){return x&&x.id;});
}
async function blEntrySet(id, data) {
  if (firebaseReady) await fbSet('/blacklist/' + id, data);
  else lsSet('blacklist/' + id, data);
}
async function blEntryDel(id) {
  if (firebaseReady) await fbDel('/blacklist/' + id);
  else lsDel('blacklist/' + id);
}

async function loadBlacklist() {
  try {
    allBlacklistConfigs = await blConfigGetAll();
    allBlacklistEntries = await blEntryGetAll();
  } catch(_) { allBlacklistConfigs = []; allBlacklistEntries = []; }
  var enabled = allBlacklistConfigs.filter(function(c){ return c.enabled !== false; });
  enabled.forEach(function(cfg) {
    if (cfg.sheetUrl && cfg.tabName) fetchSheetData(cfg.id, cfg.sheetUrl, cfg.tabName);
  });
  renderBlacklist();
}

async function fetchSheetData(deptId, sheetUrl, tabName) {
  blSheetCache[deptId] = { status: 'loading', headers: [], rows: [], error: null };
  renderBlacklist();
  try {
    var match = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9\-_]+)/);
    if (!match) throw new Error('Invalid Google Sheets URL — paste the full URL from your browser.');
    var sheetId = match[1];
    var csvUrl  = 'https://docs.google.com/spreadsheets/d/' + sheetId
                + '/gviz/tq?tqx=out:csv&sheet=' + encodeURIComponent(tabName);
    var resp = await fetch(csvUrl);
    if (!resp.ok) throw new Error('Sheet returned HTTP ' + resp.status + '. Ensure the sheet is shared with "Anyone with the link can view".');
    var text  = await resp.text();
    var lines = blParseCSV(text).filter(function(r){ return r.some(function(c){ return c.trim(); }); });
    if (!lines.length) {
      blSheetCache[deptId] = { status: 'empty', headers: [], rows: [], error: null };
    } else {
      blSheetCache[deptId] = { status: 'ok', headers: lines[0], rows: lines.slice(1), error: null };
    }
  } catch(err) {
    blSheetCache[deptId] = { status: 'error', headers: [], rows: [], error: err.message };
  }
  renderBlacklist();
}

function blParseCSV(text) {
  var rows = []; var line = []; var cell = ''; var inQ = false;
  for (var i = 0; i < text.length; i++) {
    var ch = text[i];
    if (inQ) {
      if (ch === '"') { if (text[i+1] === '"') { cell += '"'; i++; } else inQ = false; }
      else { cell += ch; }
    } else if (ch === '"') { inQ = true; }
    else if (ch === ',') { line.push(cell.trim()); cell = ''; }
    else if (ch === '\n') {
      line.push(cell.trim()); cell = '';
      if (line.some(function(c){return c;})) rows.push(line); line = [];
    } else if (ch !== '\r') { cell += ch; }
  }
  if (cell || line.length) { line.push(cell.trim()); if (line.some(function(c){return c;})) rows.push(line); }
  return rows;
}

function canManageBlacklist() {
  if (!currentUser) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  if (currentUser.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
    if (pf && CL4_SENIOR_RANKS.includes(pf.rank)) return true;
  }
  if (currentUser.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === currentUser.linkedEfId; });
    if (ef) return true;
  }
  return false;
}

function renderBlacklist() {
  var el = document.getElementById('blDeptList');
  if (!el) return;
  var query = ((document.getElementById('blSearch') || {}).value || '').trim().toLowerCase();
  var enabled = allBlacklistConfigs.filter(function(c){ return c.enabled !== false; });

  if (!enabled.length) {
    el.innerHTML = '<div class="poi-empty">[ NO DEPARTMENTS CONFIGURED — A CL5 ADMIN MUST ADD DEPARTMENT BLACKLIST SHEETS IN THE ADMIN PANEL ]</div>';
    var sr = document.getElementById('blSearchResult');
    if (sr) sr.style.display = 'none';
    return;
  }

  var srEl = document.getElementById('blSearchResult');
  if (srEl && query.length >= 2) {
    var hits = [];
    enabled.forEach(function(cfg) {
      var sc = blSheetCache[cfg.id];
      if (sc && sc.status==='ok') {
        sc.rows.forEach(function(row) { if (row.join(' ').toLowerCase().includes(query)) hits.push(cfg.name); });
      }
      allBlacklistEntries.filter(function(en){ return en.deptId===cfg.id; }).forEach(function(en) {
        if ((en.name+' '+en.steamId+' '+en.reason).toLowerCase().includes(query)) hits.push(cfg.name);
      });
    });
    var unique = hits.filter(function(v,i,a){ return a.indexOf(v)===i; });
    srEl.style.display = 'block';
    if (unique.length) {
      srEl.innerHTML = '⚠ BLACKLIST MATCH — found in: <strong>' + unique.map(e).join(', ') + '</strong>';
      srEl.style.color = '#ff8888';
    } else {
      srEl.innerHTML = '✓ No blacklist matches for "' + e(query) + '"';
      srEl.style.color = 'var(--green-dim)';
    }
  } else if (srEl) { srEl.style.display = 'none'; }

  el.innerHTML = enabled.map(function(cfg) {
    var isCollapsed = blCollapsed.has(cfg.id);
    var sc = blSheetCache[cfg.id];
    var manualEnts = allBlacklistEntries.filter(function(en){ return en.deptId===cfg.id; });

    var statusHtml = '';
    if (!cfg.sheetUrl) statusHtml = '<span class="bl-sheet-status bl-status-empty">○ NO SHEET</span>';
    else if (!sc) statusHtml = '<span class="bl-sheet-status bl-status-loading">○ PENDING</span>';
    else if (sc.status==='loading') statusHtml = '<span class="bl-sheet-status bl-status-loading">● FETCHING...</span>';
    else if (sc.status==='ok')      statusHtml = '<span class="bl-sheet-status bl-status-ok">● '+sc.rows.length+' SHEET ENTRIES</span>';
    else if (sc.status==='empty')   statusHtml = '<span class="bl-sheet-status bl-status-empty">○ SHEET EMPTY</span>';
    else if (sc.status==='error')   statusHtml = '<span class="bl-sheet-status bl-status-error" title="'+e(sc.error)+'">✗ SHEET ERROR</span>';

    var sheetHtml = '';
    if (sc && sc.status==='ok') {
      var fRows = query.length>=2 ? sc.rows.filter(function(r){ return r.join(' ').toLowerCase().includes(query); }) : sc.rows;
      // Sheet data is collapsed by default — only shown when the user expands it,
      // or automatically when a search is active (so matches aren't hidden).
      var sheetExpanded = blSheetExpanded.has(cfg.id) || query.length >= 2;
      var sheetTable = '<div style="overflow-x:auto;"><table class="bl-table"><thead><tr>'
        + sc.headers.map(function(h){ return '<th>'+e(h)+'</th>'; }).join('')
        + '</tr></thead><tbody>'
        + (fRows.length ? fRows.map(function(row){ return '<tr>'+row.map(function(c){ return '<td>'+e(c)+'</td>'; }).join('')+'</tr>'; }).join('')
          : '<tr><td colspan="'+sc.headers.length+'" style="color:var(--text-faint);font-style:italic;">[ No matches ]</td></tr>')
        + '</tbody></table></div>';
      sheetHtml = '<div class="bl-sheet-toggle" data-action="toggle-bl-sheet" data-id="'+e(cfg.id)+'" style="cursor:pointer;font-size:.56rem;letter-spacing:.08em;color:var(--text-dim);padding:.3rem 0;user-select:none;">'
        + (sheetExpanded ? '▾' : '▸') + ' GOOGLE SHEET DATA (' + sc.rows.length + ' entries)'
        + (query.length>=2&&fRows.length<sc.rows.length?' — '+fRows.length+' match':'')
        + (query.length>=2 ? ' <span style="color:var(--text-faint);">[auto-shown for search]</span>' : '')
        + '</div>'
        + (sheetExpanded ? sheetTable : '');
    } else if (sc && sc.status==='error') {
      sheetHtml = '<div style="font-size:.58rem;color:#ff8888;padding:.3rem 0;line-height:1.6;">⚠ Could not load sheet: '+e(sc.error)+'</div>';
    }

    var fManual = query.length>=2 ? manualEnts.filter(function(en){ return (en.name+' '+en.steamId+' '+en.reason).toLowerCase().includes(query); }) : manualEnts;
    var manualHtml = fManual.length ? fManual.map(function(en) {
      var dt = safeDate(en.addedAt);
      var canDel = currentUser && parseInt(currentUser.clearance)>=5;
      var ap = en.appeal;
      var upheld = ap && ap.resolution === 'upheld';

      // Appeal status badge / controls
      var appealHtml = '';
      if (upheld) {
        appealHtml = '<span class="badge b-green" style="font-size:.5rem;margin-left:.4rem;">APPEAL UPHELD</span>';
      } else if (ap && ap.resolution === 'denied') {
        appealHtml = '<span class="badge b-dim" style="font-size:.5rem;margin-left:.4rem;">APPEAL DENIED</span>';
      } else if (ap && !ap.resolution) {
        appealHtml = '<span class="badge b-amber" style="font-size:.5rem;margin-left:.4rem;">UNDER APPEAL</span>';
      }

      // Action buttons
      var actions = '';
      if (!upheld) {
        // Appeal submission: any CL3+ user, only if not already under appeal
        if (currentUser && !ap) {
          actions += '<button class="rec-btn" data-action="open-bl-appeal" data-id="'+e(en.id)+'" style="font-size:.52rem;padding:1px 6px;">APPEAL</button>';
        }
        // Appeal review: shown to eligible reviewers when an appeal is pending
        if (ap && !ap.resolution) {
          var perm = blAppealReviewPermission(en);
          if (perm.allowed) {
            actions += '<button class="rec-btn approve" data-action="bl-appeal-resolve" data-id="'+e(en.id)+'" data-res="upheld" style="font-size:.52rem;padding:1px 6px;">UPHOLD</button>';
            actions += '<button class="rec-btn deny" data-action="bl-appeal-resolve" data-id="'+e(en.id)+'" data-res="denied" style="font-size:.52rem;padding:1px 6px;">DENY</button>';
          }
        }
        if (canDel) {
          actions += '<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.8rem;padding:0 4px;" data-action="del-bl-entry" data-id="'+e(en.id)+'" title="Delete">✕</button>';
        }
      }

      var strike = upheld ? 'text-decoration:line-through;opacity:.55;' : '';
      var appealReason = (ap && ap.reason) ? '<div style="font-size:.55rem;color:var(--amber);margin-top:2px;border-left:2px solid #4a3a14;padding-left:.5rem;">Appeal: '+e(ap.reason)+(ap.submittedBy?' — EC·'+e(ap.submittedBy):'')+'</div>' : '';
      var resolNote = (ap && ap.resolution) ? '<div style="font-size:.54rem;color:var(--text-faint);margin-top:1px;">'+(ap.resolution==='upheld'?'Upheld':'Denied')+' by EC·'+e(ap.resolvedBy||'?')+'</div>' : '';

      return '<div class="bl-entry">'
        + '<div class="bl-entry-meta" style="'+strike+'">'
        + '<div class="bl-entry-name">'+e(en.name||'—')+appealHtml+'</div>'
        + (en.steamId?'<div class="bl-entry-steam">'+e(en.steamId)+'</div>':'')
        + '<div class="bl-entry-reason">'+e(en.reason||'—')+'</div>'
        + '<div class="bl-entry-added">EC·'+e(en.addedBy)+' ['+blTierLabel(en.issuerTier||'other')+'] · '+dt+'</div>'
        + appealReason + resolNote
        + '</div>'
        + (actions?'<div style="display:flex;gap:.3rem;align-items:flex-start;flex-wrap:wrap;">'+actions+'</div>':'')
        + '</div>';
    }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);">[ NO MANUAL ENTRIES ]</div>';

    var addBtn = canManageBlacklist()
      ? '<button class="rec-btn" data-action="open-bl-entry-modal" data-deptid="'+e(cfg.id)+'" data-deptname="'+e(cfg.name)+'" style="font-size:.55rem;padding:2px 9px;margin-top:.5rem;">+ ADD MANUAL ENTRY</button>'
      : '';

    return '<div class="bl-dept">'
      + '<div class="bl-dept-hdr" data-action="toggle-bl-dept" data-id="'+e(cfg.id)+'">'
      + '<span style="font-size:.65rem;font-weight:bold;letter-spacing:.1em;color:var(--text);">▸ '+e(cfg.name.toUpperCase())+'</span>'
      + '<div style="display:flex;align-items:center;gap:.5rem;">'+statusHtml
      + '<span style="font-size:.6rem;color:var(--text-dim);">'+(isCollapsed?'▸':'▾')+'</span></div></div>'
      + '<div style="display:'+(isCollapsed?'none':'block')+';"><div class="bl-dept-body">'
      + '<div class="bl-section-label">▸ DEPARTMENT BLACKLIST</div>'
      + manualHtml + addBtn
      + (sheetHtml ? '<div style="margin-top:.6rem;border-top:1px solid var(--border);padding-top:.3rem;">' + sheetHtml + '</div>' : '')
      + '</div></div></div>';
  }).join('');
}

function openBlEntryModal(deptId, deptName) {
  if (!canManageBlacklist()) return;
  document.getElementById('blEntryDeptId').value = deptId;
  document.getElementById('blEntryName').value   = '';
  document.getElementById('blEntrySteam').value  = '';
  document.getElementById('blEntryReason').value = '';
  document.getElementById('blEntryErr').textContent = '';
  var h = document.querySelector('#blEntryModal h3');
  if (h) h.textContent = 'ADD ENTRY — ' + deptName.toUpperCase();
  document.getElementById('blEntryModal').classList.add('open');
}
function closeBlEntryModal() { document.getElementById('blEntryModal').classList.remove('open'); }

async function saveBlEntry() {
  if (!canManageBlacklist()) return;
  var deptId = document.getElementById('blEntryDeptId').value;
  var name   = document.getElementById('blEntryName').value.trim();
  var steam  = document.getElementById('blEntrySteam').value.trim();
  var reason = document.getElementById('blEntryReason').value.trim();
  var errEl  = document.getElementById('blEntryErr');
  if (!name)   { errEl.textContent = '> NAME REQUIRED'; return; }
  if (!reason) { errEl.textContent = '> REASON REQUIRED'; return; }
  var entry = { id:'bl_'+Date.now()+'_'+Math.random().toString(36).slice(2,4),
    deptId: deptId, name: name, steamId: steam, reason: reason,
    addedBy: currentUser.id, addedAt: Date.now(),
    issuerTier: getBlIssuerTier(), // who issued it — drives appeal review hierarchy
    appeal: null };
  try {
    await blEntrySet(entry.id, entry);
    allBlacklistEntries.push(entry);
    closeBlEntryModal();
    renderBlacklist();
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

// Determine the issuing tier of the current user (for appeal routing)
function getBlIssuerTier() {
  if (!currentUser) return 'unknown';
  var cl = parseInt(currentUser.clearance || '3');
  // Ethics roles take precedence in their own chain
  if (currentUser.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === currentUser.linkedEfId; });
    if (ef) {
      if (ef.role === 'Chairman') return 'ef-chairman';
      if (ef.role === 'Member')   return 'ef-member';
      if (ef.role === 'Assistant') return 'ef-assistant';
    }
  }
  if (currentUser.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
    if (pf) {
      if (CL4_SENIOR_RANKS.includes(pf.rank)) return 'sr-cl4';
      if (CL4_JUNIOR_RANKS.includes(pf.rank)) return 'jr-cl4';
    }
  }
  if (cl >= 5) return 'cl5';
  return 'other';
}

// Can the current user review an appeal on an entry with the given issuer tier?
// Returns { allowed: bool, warn: string|null } — warn is shown as a confirm for CL5 overrides.
function blAppealReviewPermission(entry) {
  if (!currentUser) return { allowed:false, warn:null };
  var cl = parseInt(currentUser.clearance || '3');
  var tier = entry.issuerTier || 'other';

  // Escalation: if appeal has been open 3+ days, any CL5 may review unrestricted
  var escalated = entry.appeal && entry.appeal.submittedAt &&
                  (Date.now() - entry.appeal.submittedAt) > 3*24*60*60*1000;

  // Determine the user's own review capabilities
  var isSrCl4 = false, isCl5 = cl >= 5, efRole = null;
  if (currentUser.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
    if (pf && CL4_SENIOR_RANKS.includes(pf.rank)) isSrCl4 = true;
  }
  if (currentUser.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === currentUser.linkedEfId; });
    if (ef) efRole = ef.role;
  }

  // Natural (in-chain) reviewers first — these never get a warning, even if CL5.
  if (tier === 'jr-cl4'   && isSrCl4) return { allowed:true, warn:null };
  if (tier === 'sr-cl4'   && (efRole === 'Member' || efRole === 'Chairman')) return { allowed:true, warn:null };
  if (tier === 'ef-member'&& efRole === 'Chairman') return { allowed:true, warn:null };
  if (tier === 'ef-assistant' && (efRole === 'Member' || efRole === 'Chairman')) return { allowed:true, warn:null };

  // CL5 can always review, but warn when stepping outside the natural chain.
  if (isCl5) {
    var natural = (tier === 'sr-cl4') || (tier === 'jr-cl4');
    return { allowed:true, warn: natural ? null :
      'You are reviewing an appeal outside the normal chain for this entry (issued by ' + blTierLabel(tier) + '). Proceed as CL5 command?' };
  }

  // Escalated appeals (open 3+ days): Sr CL4 may step in for higher tiers.
  if (escalated && isSrCl4) return { allowed:true, warn:'This appeal has been open over 3 days and has escalated. Review as senior staff?' };

  return { allowed:false, warn:null };
}

function blTierLabel(tier) {
  return ({ 'jr-cl4':'Junior CL4','sr-cl4':'Senior CL4','ef-member':'Ethics Member',
            'ef-chairman':'Ethics Chairman','ef-assistant':'Ethics Assistant','cl5':'CL5 Command',
            'other':'staff' })[tier] || tier;
}

async function deleteBlEntry(id) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!await pfConfirm('PERMANENTLY REMOVE THIS BLACKLIST ENTRY?')) return;
  try {
    await blEntryDel(id);
    allBlacklistEntries = allBlacklistEntries.filter(function(x){ return x.id !== id; });
    renderBlacklist();
  } catch(err) { alert('ERROR: ' + err.message); }
}

function toggleBlDept(id) {
  if (blCollapsed.has(id)) blCollapsed.delete(id); else blCollapsed.add(id);
  renderBlacklist();
}

function toggleBlSheet(id) {
  if (blSheetExpanded.has(id)) blSheetExpanded.delete(id); else blSheetExpanded.add(id);
  renderBlacklist();
}

// ── Blacklist entry appeals ──
function openBlAppeal(entryId) {
  if (!currentUser) return; // any CL3+ logged-in user may appeal
  var en = allBlacklistEntries.find(function(x){ return x.id === entryId; });
  if (!en) return;
  if (en.appeal) { alert('This entry already has an appeal on record.'); return; }
  document.getElementById('blAppealEntryId').value = entryId;
  document.getElementById('blAppealReason').value = '';
  document.getElementById('blAppealErr').textContent = '';
  var sub = document.getElementById('blAppealSubtitle');
  if (sub) sub.textContent = en.name + ' — ' + (en.reason || '');
  document.getElementById('blAppealModal').classList.add('open');
}
function closeBlAppeal() { document.getElementById('blAppealModal').classList.remove('open'); }

async function saveBlAppeal() {
  if (!currentUser) return;
  var entryId = document.getElementById('blAppealEntryId').value;
  var reason  = document.getElementById('blAppealReason').value.trim();
  var errEl   = document.getElementById('blAppealErr');
  if (!reason) { errEl.textContent = '> APPEAL REASON REQUIRED'; return; }
  var en = allBlacklistEntries.find(function(x){ return x.id === entryId; });
  if (!en) { errEl.textContent = '> ENTRY NOT FOUND'; return; }
  if (en.appeal) { errEl.textContent = '> ALREADY UNDER APPEAL'; return; }
  en.appeal = {
    reason: reason,
    submittedBy: currentUser.id,
    submittedAt: Date.now(),
    resolution: null
  };
  try {
    await blEntrySet(en.id, en);
    auditRecord('BLACKLIST APPEAL', en.name + ' (' + (en.deptId||'') + ')');
    closeBlAppeal();
    renderBlacklist();
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

async function resolveBlAppeal(entryId, resolution) {
  if (!currentUser) return;
  var en = allBlacklistEntries.find(function(x){ return x.id === entryId; });
  if (!en || !en.appeal || en.appeal.resolution) return;
  var perm = blAppealReviewPermission(en);
  if (!perm.allowed) {
    alert('You are not authorised to review this appeal.\n\nIssued by ' + blTierLabel(en.issuerTier||'other') + '. Review must come from the appropriate senior reviewer.');
    return;
  }
  // CL5 (or escalated) override warning
  if (perm.warn) {
    if (!await pfConfirm(perm.warn)) return;
  }
  var verb = resolution === 'upheld' ? 'UPHOLD this appeal (entry will be struck from the blacklist)' : 'DENY this appeal (entry remains active)';
  if (!await pfConfirm('Are you sure you want to ' + verb + '?')) return;
  en.appeal.resolution = resolution;
  en.appeal.resolvedBy = currentUser.id;
  en.appeal.resolvedAt = Date.now();
  try {
    await blEntrySet(en.id, en);
    auditRecord('BLACKLIST APPEAL ' + resolution.toUpperCase(), en.name);
    renderBlacklist();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// Admin config modal
function openBlDeptModal(existingId) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var ex = existingId ? allBlacklistConfigs.find(function(c){ return c.id===existingId; }) : null;
  document.getElementById('blDeptEditId').value    = existingId || '';
  document.getElementById('blDeptName').value      = ex ? ex.name    : '';
  document.getElementById('blDeptUrl').value       = ex ? (ex.sheetUrl||'') : '';
  document.getElementById('blDeptTab').value       = ex ? (ex.tabName||'Blacklist') : 'Blacklist';
  document.getElementById('blDeptEnabled').checked = ex ? ex.enabled !== false : true;
  document.getElementById('blDeptErr').textContent = '';
  var h = document.getElementById('blDeptModalTitle');
  if (h) h.textContent = existingId ? 'EDIT DEPARTMENT' : 'ADD DEPARTMENT BLACKLIST';
  document.getElementById('blDeptModal').classList.add('open');
}
function closeBlDeptModal() { document.getElementById('blDeptModal').classList.remove('open'); }

async function saveBlDept() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var editId  = document.getElementById('blDeptEditId').value;
  var name    = document.getElementById('blDeptName').value.trim();
  var url     = document.getElementById('blDeptUrl').value.trim();
  var tabName = document.getElementById('blDeptTab').value.trim();
  var enabled = document.getElementById('blDeptEnabled').checked;
  var errEl   = document.getElementById('blDeptErr');
  if (!name)    { errEl.textContent = '> DEPARTMENT NAME REQUIRED'; return; }
  if (!tabName) { errEl.textContent = '> SHEET TAB NAME REQUIRED'; return; }
  if (url && !url.match(/spreadsheets\/d\//)) { errEl.textContent = '> MUST BE A GOOGLE SHEETS URL'; return; }
  var id = editId || ('dept_'+Date.now()+'_'+Math.random().toString(36).slice(2,4));
  var rec = { id: id, name: name, sheetUrl: url, tabName: tabName, enabled: enabled,
              updatedBy: currentUser.id, updatedAt: Date.now() };
  try {
    await blConfigSet(id, rec);
    allBlacklistConfigs = await blConfigGetAll();
    closeBlDeptModal();
    if (url && tabName && enabled) fetchSheetData(id, url, tabName);
    else renderBlacklist();
    renderAdminPanel();
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

async function deleteBlDept(id) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!await pfConfirm('DELETE THIS DEPARTMENT BLACKLIST?\n\nAll manual entries for this department will also be removed.')) return;
  try {
    await blConfigDel(id);
    var toDelete = allBlacklistEntries.filter(function(en){ return en.deptId===id; });
    for (var i=0;i<toDelete.length;i++) { await blEntryDel(toDelete[i].id); }
    allBlacklistConfigs = allBlacklistConfigs.filter(function(c){ return c.id!==id; });
    allBlacklistEntries = allBlacklistEntries.filter(function(en){ return en.deptId!==id; });
    delete blSheetCache[id];
    renderAdminPanel();
    renderBlacklist();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ================================================================
//  LIVE SYNC — Firebase SSE (real-time push) + background poll
//  EventSource automatically sends Accept: text/event-stream,
//  which Firebase REST recognises and responds with SSE format.
// ================================================================
var _sseConns = {};     // path → EventSource
var _bgPollTimer = null;

// ── Start / stop ──
function startPolling() {
  stopPolling();
  if (firebaseReady) {
    // SSE for high-frequency collaboration paths (real-time push)
    _openSSE('orders',             _onOrdersSSE);
    _openSSE('ethics-orders',      _onEthicsOrdersSSE);
    _openSSE('recruitment',        _onRecruitSSE);
    _openSSE('ethics-recruitment', _onEthicsRecruitSSE);
    // Background poll every 30 s for personnel, POI, admin
    _bgPollTimer = setInterval(_bgPoll, 30000);
    _setSyncStatus('connecting');
  } else {
    // Fallback: poll orders every 10 s when using localStorage
    _bgPollTimer = setInterval(loadOrders, 10000);
  }
}

function stopPolling() {
  // Close all SSE connections
  Object.keys(_sseConns).forEach(function(k) {
    try { _sseConns[k].close(); } catch(_) {}
    delete _sseConns[k];
  });
  if (_bgPollTimer) { clearInterval(_bgPollTimer); _bgPollTimer = null; }
  _setSyncStatus('off');
}

// ── Open an SSE connection to a Firebase path ──
function _openSSE(path, callback) {
  if (_sseConns[path]) { try { _sseConns[path].close(); } catch(_) {} }
  var cache = {};
  var url   = FIREBASE_URL + '/' + path + '.json';
  var es    = new EventSource(url);
  var connected = false;

  es.addEventListener('put', function(ev) {
    try {
      var m = JSON.parse(ev.data);
      if (m.path === '/') {
        cache = m.data || {};
      } else {
        var k = m.path.replace(/^\/+/, '');
        if (m.data === null) delete cache[k]; else cache[k] = m.data;
      }
      if (!connected) { connected = true; _setSyncStatus('live'); }
      callback(cache);
    } catch(err) { console.warn('[CAIRO sync put]', path, err); }
  });

  es.addEventListener('patch', function(ev) {
    try {
      var m = JSON.parse(ev.data);
      var root = m.path === '/' ? cache
               : (cache[m.path.replace(/^\/+/, '')] = cache[m.path.replace(/^\/+/, '')] || {});
      Object.assign(root, m.data || {});
      callback(cache);
    } catch(err) { console.warn('[CAIRO sync patch]', path, err); }
  });

  es.onerror = function() {
    connected = false;
    _setSyncStatus('reconnecting');
    // EventSource auto-reconnects; update status once next put arrives
  };

  _sseConns[path] = es;
}

// ── SSE data callbacks ──
function _onOrdersSSE(raw) {
  allOrders = partitionDeleted(Object.values(raw).filter(function(o){ return o && o.id; }), function(d){ deletedOrders = d; })
              .sort(function(a,b){ return b.created - a.created; });
  updateOrderBadge();
  _safeRender(renderOrders, 'ordersList');
  refreshOverviewIfActive();
}

function _onEthicsOrdersSSE(raw) {
  allEthicsOrders = partitionDeleted(Object.values(raw).filter(function(o){ return o && o.id; }), function(d){ deletedEthicsOrders = d; })
                    .sort(function(a,b){ return b.created - a.created; });
  updateEthicsOrderBadge();
  _safeRender(renderEthicsOrders, 'ethicsOrdersList');
  refreshOverviewIfActive();
}

function _onRecruitSSE(raw) {
  allRecruitment = Object.values(raw).filter(function(r){ return r && r.id; })
                   .sort(function(a,b){ return b.created - a.created; });
  updateRecruitBadge();
  _safeRender(renderRecruitment, 'recScoutingList');
  refreshOverviewIfActive();
}

function _onEthicsRecruitSSE(raw) {
  allEthicsRecruit = Object.values(raw).filter(function(r){ return r && r.id; })
                     .sort(function(a,b){ return b.created - a.created; });
  updateEthicsRecruitBadge();
  _safeRender(renderEthicsRecruit, 'ethicsAppList');
  refreshOverviewIfActive();
}

// ── Guard against re-rendering while a user is typing in that section ──
function _safeRender(fn, anchorId) {
  var anchor  = document.getElementById(anchorId);
  var focused = document.activeElement;
  if (anchor && focused && anchor !== focused && typeof anchor.contains === 'function' && anchor.contains(focused)) {
    // User is focused inside this section — retry after 1.5 s
    setTimeout(function(){ _safeRender(fn, anchorId); }, 1500);
    return;
  }
  try { fn(); } catch(err) { console.warn('[CAIRO render]', err); }
}

// ── Background poll for personnel, POI, admin ──
async function _bgPoll() {
  if (!currentUser || !firebaseReady) return;
  var tabId = '';
  var active = document.querySelector('.tab-content.active');
  if (active) tabId = active.id || '';

  // Personnel — full reload if on tab, else just update state silently.
  // Re-render goes through _safeRender so a 30s poll never wipes text a user is
  // mid-way through typing in a file (e.g. logging activity hours / a note).
  if (tabId === 'tab-personnel-files' || tabId === 'tab-roster') {
    try {
      allPersonnel = partitionDeleted((await personnelGetAll()).filter(function(p){ return p && p.id; }), function(d){ deletedPersonnel = d; });
      await loadSquadrons();
      _safeRender(renderPersonnelFiles, 'pfList');
      _safeRender(renderRoster, 'rosterBody');
      refreshClearance();
    } catch(_) {}
  } else {
    try { allPersonnel = partitionDeleted((await personnelGetAll()).filter(function(p){ return p && p.id; }), function(d){ deletedPersonnel = d; }); }
    catch(_) {}
  }

  // Ethics personnel — same guarded re-render
  if (tabId === 'tab-ethics-files' || tabId === 'tab-ethics-roster') {
    try {
      allEthicsPersonnel = partitionDeleted(await ethicsPersonnelGetAll(), function(d){ deletedEthics = d; });
      allEthicsPersonnel.sort(function(a,b){ return ethicsRankIndex(a.role) - ethicsRankIndex(b.role); });
      await loadEthicsSquadrons();
      _safeRender(renderEthicsFiles, 'tab-ethics-files');
      _safeRender(renderEthicsRoster, 'ethicsRosterBody');
    } catch(_) {}
  } else {
    try { allEthicsPersonnel = partitionDeleted((await ethicsPersonnelGetAll()).filter(function(p){ return p && p.id; }), function(d){ deletedEthics = d; }); }
    catch(_) {}
  }

  // POI + Targets — update state + badge; re-render if on tab
  try {
    var ps = await poiGetAll(); var ts = await targetGetAll();
    allPOI     = ps.sort(function(a,b){ return (a.number||0)-(b.number||0); });
    allTargets = ts.sort(function(a,b){ return (a.number||0)-(b.number||0); });
    updatePoiBadge();
    if (tabId === 'tab-poi' && !currentPoiView) renderPoiList();
  } catch(_) {}

  // Admin badge for CL5
  if (parseInt(currentUser.clearance || 0) >= 5) {
    try { await loadAdminData(); } catch(_) {}
  }

  // Keep the command overview live if it's the active tab
  refreshOverviewIfActive();
}

// ── Sync status indicator ──
function _setSyncStatus(s) {
  var el = document.getElementById('syncIndicator');
  if (!el) return;
  var cfg = {
    live:         { text:'● LIVE',         color:'var(--green-dim)' },
    connecting:   { text:'○ connecting',   color:'var(--text-faint)' },
    reconnecting: { text:'○ reconnecting', color:'var(--amber)' },
    off:          { text:'',               color:'transparent' }
  }[s] || { text:'', color:'transparent' };
  el.textContent = cfg.text;
  el.style.color = cfg.color;
}

async function submitOrder() {
  if (!currentUser) return;
  var title = document.getElementById('oTitle').value.trim();
  var desc  = document.getElementById('oDesc').value.trim();
  if (!title) { alert('ORDER TITLE REQUIRED'); return; }

  var btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.textContent = '[ TRANSMITTING... ]';

  var now = Date.now();
  var id  = 'ord_' + now + '_' + Math.random().toString(36).slice(2, 6);
  var order = {
    id: id, title: title.toUpperCase(), desc: desc,
    priority: document.getElementById('oPriority').value,
    type:     document.getElementById('oType').value,
    status:   'PENDING',
    minClearance: document.getElementById('oMinClearance').value || '3',
    compartment: (document.getElementById('oCompartment') || {}).value || null,
    author:   currentUser.id,
    clearance: currentUser.clearance,
    created:  now
  };

  try {
    await orderSet(id, order);
  } catch(e) {
    alert('TRANSMISSION ERROR: ' + e.message);
    btn.disabled = false;
    btn.textContent = '[ SUBMIT ORDER → CAIRO.AIC ]';
    return;
  }

  allOrders.unshift(order);
  document.getElementById('oTitle').value = '';
  document.getElementById('oDesc').value  = '';
  document.getElementById('oMinClearance').value = '3';
  btn.disabled = false;
  btn.textContent = '[ SUBMIT ORDER → CAIRO.AIC ]';
  renderOrders();
  updateOrderBadge();
  logActivity('ORD', 'Order submitted by EC·' + currentUser.id + ' · "' + title.toUpperCase() + '" · ' + order.priority, 'b-amber', 'NEW');
}

async function updateOrderStatus(id, status) {
  for (var i = 0; i < allOrders.length; i++) {
    if (allOrders[i].id === id) {
      allOrders[i].status = status;
      await orderSet(id, allOrders[i]);
      break;
    }
  }
  renderOrders();
  updateOrderBadge();
}

async function deleteOrder(id) {
  if (!await pfConfirm('Move this order to the recycle bin?\n\nIt can be restored by CL5 command from the admin panel.')) return;
  var o = allOrders.find(function(x){ return x.id === id; });
  if (o) {
    o.deleted = true; o.deletedBy = currentUser.id; o.deletedAt = Date.now();
    try { await orderSet(id, o); } catch(e) { alert('ERROR: '+e.message); return; }
    auditRecord('DELETED ORDER', (o.title||id) + ' → recycle bin');
    allOrders = allOrders.filter(function(x) { return x.id !== id; });
    if (!deletedOrders.some(function(x){ return x.id===id; })) deletedOrders.push(o);
  }
  renderOrders();
  updateOrderBadge();
}

function setFilter(f, btn) {
  activeFilter = f; _filtSet('orders', f);
  document.querySelectorAll('#tab-orders .filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  renderOrders();
}

function e(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Custom confirm (replaces browser confirm() which is blocked in sandboxed iframes) ──
function pfConfirm(message) {
  return new Promise(function(resolve) {
    var modal = document.getElementById('pfConfirmModal');
    var msg   = document.getElementById('pfConfirmMsg');
    var yes   = document.getElementById('pfConfirmYes');
    var no    = document.getElementById('pfConfirmNo');
    if (!modal) { resolve(false); return; }
    msg.textContent = message;
    modal.classList.add('open');
    function cleanup(result) {
      modal.classList.remove('open');
      yes.removeEventListener('click', onYes);
      no.removeEventListener('click', onNo);
      resolve(result);
    }
    function onYes() { cleanup(true);  }
    function onNo()  { cleanup(false); }
    yes.addEventListener('click', onYes);
    no.addEventListener('click',  onNo);
  });
}
function priorityBadge(p) {
  return p==='CRITICAL'?'b-red':p==='URGENT'?'b-amber':p==='ELEVATED'?'b-cyan':'b-green';
}
// ── Formal directive document helpers ──
// A stable reference number derived from the order's id/timestamp, e.g. EC-D/4F2A-7C19
function directiveRef(o) {
  var base = String(o.id || '').replace(/[^a-zA-Z0-9]/g,'').toUpperCase();
  if (base.length < 8) base = (base + '00000000').slice(0,8);
  var a = base.slice(-8, -4), b = base.slice(-4);
  return 'EC-D/' + a + '-' + b;
}
// Priority → banner class (drives the classification banner colour)
function directiveBannerClass(p) {
  return p==='CRITICAL'?'critical':p==='URGENT'?'urgent':p==='ELEVATED'?'elevated':'routine';
}
// Classification line shown in the banner, by min clearance
function directiveClassification(o) {
  var min = parseInt(o.minClearance || '3');
  var lvl = min >= 5 ? 'LEVEL 5 · COMMAND EYES ONLY' : min >= 4 ? 'LEVEL 4 · SENIOR ACCESS' : 'LEVEL 3 · STANDARD ACCESS';
  return o.compartment ? lvl + ' · COMPARTMENTED' : lvl;
}
// Status → authorization stamp {label, cls}
function directiveStamp(status) {
  var s = (status || 'PENDING').toUpperCase();
  if (s === 'RATIFIED' || s === 'APPROVED' || s === 'ACTIVE' || s === 'COMPLETE' || s === 'COMPLETED' || s === 'CLOSED')
    return { label: s, cls: 'ratified' };
  if (s === 'REVIEW' || s === 'UNDER REVIEW' || s === 'PENDING' || s === 'IN REVIEW')
    return { label: s, cls: 'review' };
  return { label: s, cls: '' };
}

// ── Formal directive document export ──
// Produces a self-contained, print-optimised HTML memorandum (Foundation house style)
// from an order object. Recipients open it in any browser and can read or print → PDF.
function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function buildOrderDocument(o, unit) {
  var ref      = directiveRef(o);
  var min      = parseInt(o.minClearance || '3');
  var classLine = (min >= 5 ? 'LEVEL 5-A' : min >= 4 ? 'LEVEL 4-A' : 'LEVEL 3-A')
                + ' // ETHICS COMMITTEE & DESIGNATED RECIPIENTS ONLY'
                + (o.compartment ? ' // ' + escHtml((compartmentName(o.compartment) || 'COMPARTMENTED')).toUpperCase() + ' PROGRAM' : '');
  var issued   = safeDateTime(o.created);
  var priority = (o.priority || 'ROUTINE').toUpperCase();
  var status   = (o.status || 'PENDING').toUpperCase();
  var typeLbl  = (o.type || (unit === 'ef' ? 'DIRECTIVE' : 'ORDER')).toUpperCase();
  var bodyText = (unit === 'ef' ? o.body : o.desc) || '';
  var subject  = (o.title || 'ETHICS COMMITTEE DIRECTIVE').toUpperCase();
  var compLine = o.compartment ? '<tr><td class="k">NEED-TO-KNOW PROGRAM</td><td class="v">' + escHtml(compartmentName(o.compartment) || 'COMPARTMENTED') + '</td></tr>' : '';

  // Split body into paragraphs for clean document flow
  var paras = bodyText.split(/\n\s*\n/).map(function(p){ return p.trim(); }).filter(Boolean);
  var bodyHtml = paras.length
    ? paras.map(function(p){ return '<p>' + escHtml(p).replace(/\n/g,'<br>') + '</p>'; }).join('')
    : '<p style="color:#777;font-style:italic;">[ No directive text recorded. ]</p>';

  var clLabel = min >= 5 ? 'LEVEL 5-A · COMMAND' : min >= 4 ? 'LEVEL 4-A · SENIOR' : 'LEVEL 3-A · STANDARD';

  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>'
    + '<meta name="viewport" content="width=device-width, initial-scale=1"/>'
    + '<title>' + escHtml(ref) + ' — ' + escHtml(subject) + '</title>'
    + '<style>'
    + '@page{size:A4;margin:18mm 16mm;}'
    + '*{box-sizing:border-box;}'
    + 'body{font-family:"Times New Roman",Georgia,serif;color:#111;background:#525659;margin:0;padding:24px;line-height:1.55;}'
    + '.page{background:#fff;max-width:780px;margin:0 auto 24px;padding:46px 54px 40px;box-shadow:0 2px 18px rgba(0,0,0,.4);position:relative;}'
    + '.runhead{display:flex;justify-content:space-between;font-family:"Courier New",monospace;font-size:8.5px;letter-spacing:.04em;color:#444;border-bottom:1px solid #000;padding-bottom:4px;margin-bottom:2px;text-transform:uppercase;}'
    + '.classbar{background:#1a1a1a;color:#fff;font-family:"Courier New",monospace;font-size:9px;letter-spacing:.14em;text-align:center;padding:5px 4px;margin:0 -54px 4px;font-weight:bold;}'
    + '.classbar.crit{background:#7a0000;} .classbar.warn{background:#7a4a00;}'
    + '.scp-tag{text-align:center;font-family:"Courier New",monospace;font-size:9px;letter-spacing:.42em;color:#222;margin:10px 0 18px;font-weight:bold;}'
    + '.lh{text-align:center;border-bottom:2px solid #000;padding-bottom:12px;margin-bottom:16px;}'
    + '.lh .org{font-size:21px;font-weight:bold;letter-spacing:.06em;}'
    + '.lh .sub{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#333;margin-top:3px;}'
    + '.lh .div{font-size:10px;letter-spacing:.1em;color:#555;margin-top:6px;font-style:italic;}'
    + '.doctype{text-align:center;font-size:13px;font-weight:bold;letter-spacing:.16em;margin:14px 0 16px;text-transform:uppercase;}'
    + 'table.meta{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:18px;}'
    + 'table.meta td{border:1px solid #999;padding:4px 8px;vertical-align:top;}'
    + 'table.meta td.k{background:#ededed;font-family:"Courier New",monospace;font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:#333;width:34%;font-weight:bold;}'
    + 'table.meta td.v{font-weight:bold;}'
    + '.subject{font-size:14px;font-weight:bold;margin:6px 0 16px;text-align:center;text-decoration:underline;line-height:1.4;}'
    + '.body p{margin:0 0 12px;text-align:justify;font-size:12.5px;}'
    + '.sig{margin-top:34px;border-top:1px solid #000;padding-top:12px;font-size:11.5px;}'
    + '.sig .by{font-style:italic;color:#333;}'
    + '.sig .line{margin-top:18px;border-top:1px solid #000;width:260px;padding-top:3px;font-size:10.5px;letter-spacing:.04em;}'
    + '.stampbox{position:absolute;top:120px;right:40px;border:3px double #7a0000;color:#7a0000;font-family:"Courier New",monospace;font-weight:bold;font-size:13px;letter-spacing:.1em;padding:6px 14px;transform:rotate(-9deg);opacity:.82;}'
    + '.stampbox.ok{border-color:#0a5a23;color:#0a5a23;}'
    + '.footer{margin-top:26px;border-top:1px solid #000;padding-top:6px;font-family:"Courier New",monospace;font-size:8px;letter-spacing:.06em;color:#444;text-align:center;text-transform:uppercase;}'
    + '.redact{background:#000;color:#000;padding:0 .5em;border-radius:1px;user-select:none;-webkit-print-color-adjust:exact;print-color-adjust:exact;}'
    + '@media print{body{background:#fff;padding:0;}.page{box-shadow:none;margin:0;max-width:none;padding:0;}.classbar{margin:0 0 4px;}}'
    + '</style></head><body><div class="page">'
    + '<div class="runhead"><span>SCP FOUNDATION · ETHICS COMMITTEE</span><span>DOC ' + escHtml(ref) + ' · ' + clLabel.split(' ·')[0] + '</span></div>'
    + '<div class="classbar ' + (priority==='CRITICAL'?'crit':priority==='URGENT'?'warn':'') + '">' + classLine + '</div>'
    + '<div class="scp-tag">SECURE · CONTAIN · PROTECT</div>'
    + '<div class="lh"><div class="org">SCP FOUNDATION</div><div class="sub">Ethics Committee</div><div class="div">CAIRO.AIC Oversight Terminal · O5 Liaison Division</div></div>'
    + '<div class="doctype">' + (unit==='ef' ? 'ETHICS COMMITTEE DIRECTIVE' : 'OMEGA-1 OPERATIONAL ORDER') + '</div>'
    + '<div class="stampbox ' + (directiveStamp(status).cls==='ratified'?'ok':'') + '">' + escHtml(status) + '</div>'
    + '<table class="meta">'
    +   '<tr><td class="k">Memorandum Ref</td><td class="v">' + escHtml(ref) + '</td></tr>'
    +   '<tr><td class="k">Classification</td><td class="v">' + clLabel + ' · CONFIDENTIAL</td></tr>'
    +   '<tr><td class="k">Date of Issue</td><td class="v">' + issued + ' UTC</td></tr>'
    +   '<tr><td class="k">Originating Body</td><td class="v">Ethics Committee · CAIRO.AIC</td></tr>'
    +   '<tr><td class="k">Issuing Officer</td><td class="v">EC·' + escHtml(o.author || '—') + ' · Clearance <span class="redact">LEVEL</span></td></tr>'
    +   '<tr><td class="k">Classification of Order</td><td class="v">' + escHtml(typeLbl) + '</td></tr>'
    +   '<tr><td class="k">Priority</td><td class="v">' + escHtml(priority) + '</td></tr>'
    +   '<tr><td class="k">Status</td><td class="v">' + escHtml(status) + '</td></tr>'
    +   compLine
    + '</table>'
    + '<div class="subject">SUBJECT: ' + escHtml(subject) + '</div>'
    + '<div class="body">' + bodyHtml + '</div>'
    + '<div class="sig"><span class="by">Issued by authority of:</span><br>Ethics Committee · SCP Foundation'
    +   '<div class="line">Authorising Signatory — EC·' + escHtml(o.author || '________') + ', Clearance <span class="redact">LVL</span></div>'
    + '</div>'
    + '<div class="footer">CONFIDENTIAL // ' + clLabel.split(' ·')[0] + ' // ' + escHtml(ref) + ' // RECEIPT CONSTITUTES FORMAL NOTICE</div>'
    + '</div></body></html>';
}
// Export an order (by id) as a downloadable formal document.
function exportOrderDocument(id, unit) {
  var list = unit === 'ef' ? allEthicsOrders : allOrders;
  var o = list.find(function(x){ return x.id === id; });
  if (!o) { alert('Order not found.'); return; }
  // Respect access: a viewer who can't see the order can't export it.
  if (orderIsRestricted(o)) { alert('You do not have access to this directive.'); return; }
  var html = buildOrderDocument(o, unit);
  var safeName = directiveRef(o).replace(/[^A-Za-z0-9_-]/g,'_');
  downloadFile(safeName + '.html', html, 'text/html');
  auditRecord('EXPORTED DIRECTIVE', directiveRef(o) + ' — ' + (o.title || ''));
}
function statusBadge(s) {
  return s==='COMPLETED'?'b-green':s==='IN PROGRESS'?'b-cyan':s==='FLAGGED'?'b-red':'b-amber';
}

function renderOrders() {
  var filtered = activeFilter === 'ALL'
    ? allOrders
    : allOrders.filter(function(o) { return o.status === activeFilter; });

  var pend = allOrders.filter(function(o){ return o.status==='PENDING'; }).length;
  var prog = allOrders.filter(function(o){ return o.status==='IN PROGRESS'; }).length;
  var done = allOrders.filter(function(o){ return o.status==='COMPLETED'; }).length;

  document.getElementById('statTotal').textContent = allOrders.length;
  document.getElementById('statPend').textContent  = pend;
  document.getElementById('statProg').textContent  = prog;
  document.getElementById('statDone').textContent  = done;

  var list = document.getElementById('ordersList');
  if (!filtered.length) {
    list.innerHTML = activeFilter === 'ALL'
      ? '<div class="order-empty">[ NO ORDERS ON RECORD — SUBMIT THE FIRST DIRECTIVE ABOVE ↑ ]</div>'
      : '<div class="order-empty">[ NO ' + activeFilter + ' ORDERS — ADJUST THE FILTER ]</div>';
    return;
  }

  filtered = applySort(filtered, g('orderSort'), {
    date:function(o){return o.created||0;},
    title:function(o){return (o.title||'').toLowerCase();},
    status:function(o){return o.status||'';},
    priority:function(o){var m={CRITICAL:0,FLASH:0,PRIORITY:1,HIGH:1,ELEVATED:2,ROUTINE:3,LOW:4};return m[(o.priority||'').toUpperCase()]==null?5:m[(o.priority||'').toUpperCase()];}
  });
  list.innerHTML = filtered.map(function(o) {
    var isOwner  = currentUser && currentUser.id === o.author;
    var canAct   = !!currentUser;  // any logged-in user can comment
    var ts       = safeDateTime(o.created);
    var expanded = expandedOrders.has(o.id);
    var cached   = commentCache[o.id] || [];
    var cCount   = cached.length;

    var canEditOrder = isOwner || (currentUser && parseInt(currentUser.clearance) >= 5);
    var isCL5order   = currentUser && parseInt(currentUser.clearance) >= 5;
    var statusCtrl = canEditOrder
      ? '<select class="status-select" onchange="updateOrderStatus(\'' + o.id + '\',this.value)">' +
        ['PENDING','IN PROGRESS','COMPLETED','FLAGGED'].map(function(s) {
          return '<option value="' + s + '"' + (o.status===s?' selected':'') + '>' + s + '</option>';
        }).join('') + '</select>'
      : '<span class="badge ' + statusBadge(o.status) + '">' + e(o.status) + '</span>';

    // Comment thread HTML (only rendered when expanded)
    var commentsHtml = '';
    if (expanded) {
      var threadHtml = cCount === 0
        ? '<div class="comment-empty">[ NO UPDATES YET ]</div>'
        : cached
            .slice()
            .sort(function(a,b){ return a.created - b.created; })
            .map(function(c) {
              var isOwn  = currentUser && c.author === currentUser.id;
              var cts    = safeDateTime(c.created);
              return '<div class="comment-entry">' +
                '<div class="comment-gutter' + (isOwn ? ' own' : '') + '"></div>' +
                '<div class="comment-body">' +
                  '<div class="comment-meta" style="display:flex;justify-content:space-between;align-items:center;">' + '<span>EC·' + e(c.author) + ' [L' + e(c.clearance) + '] · ' + cts + ' UTC</span>' + (canDeleteComment() ? '<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;line-height:1;" data-action="del-order-comment" data-orderid="' + e(o.id) + '" data-commentid="' + e(c.id) + '" title="Delete comment">×</button>' : '') + '</div>' +
                  '<div class="comment-text">' + e(c.text) + '</div>' +
                '</div>' +
              '</div>';
            }).join('');

      var formHtml = canAct
        ? '<div class="comment-form">' +
            '<textarea class="comment-input" id="cinput_' + o.id + '" ' +
              'placeholder="Add update or response..." rows="2" ' +
              'onkeydown="handleCommentKey(event,\'' + o.id + '\')"></textarea>' +
            '<button class="comment-submit" onclick="postComment(\'' + o.id + '\')">' +
              '[ POST ]' +
            '</button>' +
          '</div>'
        : '<div class="comment-empty">[ AUTHENTICATE TO POST UPDATES ]</div>';

      commentsHtml =
        '<div class="order-comments">' +
          '<div class="comment-thread">' + threadHtml + '</div>' +
          formHtml +
        '</div>';
    }

    var toggleLabel = expanded
      ? '▾ hide updates' + (cCount ? ' (' + cCount + ')' : '')
      : '▸ updates' + (cCount ? ' (' + cCount + ')' : ' (0)');

    // ── Clearance gate ──
    if (orderIsRestricted(o)) return buildOrderDeniedCard(o, 'ocard_' + o.id);

    return '<div class="order-card" id="ocard_' + o.id + '">' +
      '<div class="dir-banner top ' + directiveBannerClass(o.priority) + '">' + directiveClassification(o) + '</div>' +
      '<div class="dir-letterhead">' +
        '<div class="dir-seal-mark">' +
          '<span class="org">◆ ETHICS COMMITTEE</span>' +
          'O5 OVERSIGHT · CAIRO.AIC TERMINAL' +
        '</div>' +
        '<div class="dir-ref">' +
          '<span class="refno">' + directiveRef(o) + '</span><br>' +
          ts + ' UTC' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:.5rem;flex-wrap:wrap;">' +
        '<div style="flex:1;min-width:0;">' +
          '<div style="font-family:\'Share Tech Mono\',monospace;font-size:.5rem;letter-spacing:.18em;color:var(--text-faint);">ETHICS COMMITTEE DIRECTIVE</div>' +
          '<div class="dir-title">' + e(o.title) + '</div>' +
        '</div>' +
        '<div class="order-card-actions">' +
          statusCtrl +
          '<button class="order-action-btn" onclick="exportOrderDocument(\'' + o.id + '\', \'omega\')" title="Export as formal document" style="font-size:.6rem;">⎙ DOC</button>' +
          (isCL5order ? '<button class="order-action-btn" onclick="openOrderEdit(\'' + o.id + '\')" title="Edit order" style="font-size:.6rem;">✎</button>' : '') +
          (isOwner
            ? '<button class="order-action-btn del-btn" onclick="deleteOrder(\'' + o.id + '\')">✕</button>'
            : '') +
        '</div>' +
      '</div>' +
      '<div class="dir-fields">' +
        '<div class="dir-field"><span class="k">Priority</span><span class="v"><span class="badge ' + priorityBadge(o.priority) + '">' + e(o.priority) + '</span></span></div>' +
        '<div class="dir-field"><span class="k">Class</span><span class="v">' + e(o.type) + '</span></div>' +
        '<div class="dir-field"><span class="k">Filed</span><span class="v">' + ts + ' UTC</span></div>' +
        (o.compartment ? '<div class="dir-field"><span class="k">Program</span><span class="v">▢ ' + e(compartmentName(o.compartment) || 'COMPARTMENTED') + '</span></div>' : '') +
      '</div>' +
      (o.desc ? '<div class="dir-body">' + e(o.desc) + '</div>' : '') +
      '<div class="dir-authorization">' +
        '<div class="dir-sig"><span class="by">By order of</span><br><span class="who">EC·' + e(o.author) + '</span> · Clearance L' + e(o.clearance) + '</div>' +
        '<div class="dir-stamp ' + directiveStamp(o.status).cls + '">' + e(directiveStamp(o.status).label) + '</div>' +
      '</div>' +
      (o.editedBy ? '<div style="font-size:.56rem;color:var(--text-faint);margin-top:5px;">✎ last amended by EC·' + e(o.editedBy) + ' · ' + safeDateTime(o.editedAt) + ' UTC</div>' : '') +
      '<div class="comment-toggle" onclick="toggleComments(\'' + o.id + '\')">' +
        toggleLabel +
      '</div>' +
      commentsHtml +
      '<div class="dir-banner bottom ' + directiveBannerClass(o.priority) + '">' + directiveClassification(o) + '</div>' +
    '</div>';
  }).join('');
  applyPagination(document.getElementById('ordersList'), 'orders', activeFilter + '|' + g('orderSort'));
}

// Toggle comment section open/closed; load from Firebase on first open
async function toggleComments(orderId) {
  if (expandedOrders.has(orderId)) {
    expandedOrders.delete(orderId);
    renderOrders();
  } else {
    expandedOrders.add(orderId);
    // Load comments if not cached yet
    if (!commentCache[orderId]) {
      commentCache[orderId] = [];
      try {
        var raw = await commentsGet(orderId);
        commentCache[orderId] = raw.filter(function(c){ return c && c.id; });
      } catch(err) {}
    }
    renderOrders();
    // Focus the textarea
    var inp = document.getElementById('cinput_' + orderId);
    if (inp) inp.focus();
  }
}

// Post a new comment
async function postComment(orderId) {
  if (!currentUser) return;
  var inp  = document.getElementById('cinput_' + orderId);
  if (!inp) return;
  var text = inp.value.trim();
  if (!text) return;

  var btn = inp.nextElementSibling;
  if (btn) { btn.disabled = true; btn.textContent = '[ POSTING... ]'; }
  inp.disabled = true;

  var comment = {
    id:        'cmt_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    author:    currentUser.id,
    clearance: currentUser.clearance,
    text:      text,
    created:   Date.now()
  };

  try {
    await commentAdd(orderId, comment);
    if (!commentCache[orderId]) commentCache[orderId] = [];
    commentCache[orderId].push(comment);
    inp.value = '';
  } catch(err) {
    alert('POST ERROR: ' + err.message);
  }

  if (btn) { btn.disabled = false; btn.textContent = '[ POST ]'; }
  inp.disabled = false;
  renderOrders();
  // Re-focus after re-render
  var newInp = document.getElementById('cinput_' + orderId);
  if (newInp) newInp.focus();
}

// Allow Ctrl+Enter to submit a comment
function handleCommentKey(ev, orderId) {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    postComment(orderId);
  }
}

// ── Order clearance access helpers ──
function orderIsRestricted(o) {
  // CL5 always has full access (Overseer)
  if (currentUser && parseInt(currentUser.clearance) >= 5) return false;
  // Clearance floor
  var min = parseInt(o.minClearance || '3');
  var cur = parseInt((currentUser && currentUser.clearance) || '0');
  if (cur < min) return true;
  // Need-to-know: a compartment-tagged order requires the matching grant
  if (o.compartment && !userHasCompartment(o.compartment)) return true;
  return false;
}

function buildOrderDeniedCard(o, cardId) {
  var min = o.minClearance || '3';
  var ts  = safeDateTime(o.created);
  // Distinguish clearance denial from need-to-know (compartment) denial
  var curOk = parseInt((currentUser && currentUser.clearance) || '0') >= parseInt(min);
  var isCompartmentBlock = curOk && o.compartment && !userHasCompartment(o.compartment);
  var badgeLabel = isCompartmentBlock ? 'COMPARTMENTED' : ('CL' + e(min) + '+ ONLY');
  var deniedMsg  = isCompartmentBlock ? 'ACCESS DENIED · NEED-TO-KNOW PROGRAM' : 'ACCESS DENIED · INSUFFICIENT CLEARANCE';
  var deniedBadge = isCompartmentBlock ? 'COMPARTMENTED ACCESS PROGRAM' : ('MINIMUM CL' + e(min) + ' REQUIRED');
  return '<div class="order-card" id="' + cardId + '">' +
    '<div class="order-card-header">' +
      '<div>' +
        '<div class="order-card-title" style="color:var(--text-faint);">' + e(o.title || 'CLASSIFIED ORDER') + '</div>' +
        '<div class="order-card-meta">' + ts + ' UTC · EC·' + e(o.author||'—') + '</div>' +
      '</div>' +
      '<div class="order-card-actions">' +
        '<span class="badge b-dim" style="letter-spacing:.05em;">' + badgeLabel + '</span>' +
      '</div>' +
    '</div>' +
    '<div class="order-denied">' +
      '<span>⛔</span>' +
      '<span>' + deniedMsg + '</span>' +
      '<span class="order-denied-badge">' + deniedBadge + '</span>' +
    '</div>' +
  '</div>';
}

// ================================================================
//  THEME SYSTEM (dark ↔ light)
// ================================================================
// Theme initialisation runs after CAIRO_THEMES + applyTheme are defined (see below).
var CAIRO_THEMES = [
  { id:'dark',  label:'TERMINAL',    icon:'▰' },
  { id:'slate', label:'DOSSIER',     icon:'▰' },
  { id:'scp',   label:'CONTAINMENT', icon:'▰' },
  { id:'light', label:'DAYLIGHT',    icon:'▰' }
];
function applyTheme(t) {
  if (!CAIRO_THEMES.some(function(x){ return x.id === t; })) t = 'dark';
  if (t === 'dark') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
  var meta = CAIRO_THEMES.find(function(x){ return x.id === t; });
  var btn = document.getElementById('themeToggle');
  if (btn && meta) { btn.textContent = meta.label + '  \u25be'; btn.title = 'Theme: ' + meta.label; }
  localStorage.setItem('cairoTheme', t);
}
function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  var idx = CAIRO_THEMES.findIndex(function(x){ return x.id === current; });
  var next = CAIRO_THEMES[(idx + 1) % CAIRO_THEMES.length];
  applyTheme(next.id);
}
// Now that CAIRO_THEMES and applyTheme exist, apply the saved theme.
(function initTheme() {
  var saved = localStorage.getItem('cairoTheme') || 'dark';
  applyTheme(saved);
})();

// ── Transient toast notifications ──
function toast(msg, type) {
  var host = document.getElementById('toastHost'); if (!host) return;
  var el = document.createElement('div');
  el.className = 'toast' + (type ? (' ' + type) : '');
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(function(){ el.classList.add('leaving'); setTimeout(function(){ if (el.parentNode) el.parentNode.removeChild(el); }, 280); }, 2400);
}

// ── Screen-flicker preference (persisted) ──
function applyFlickerPref() {
  var off = false; try { off = localStorage.getItem('cairoFlicker') === 'off'; } catch(e) {}
  document.body.classList.toggle('no-flicker', off);
  var b = document.getElementById('flickerToggle');
  if (b) b.textContent = off ? '⌁ FLICKER: OFF' : '⌁ FLICKER: ON';
}
function toggleFlicker() {
  var off; try { off = localStorage.getItem('cairoFlicker') !== 'off'; localStorage.setItem('cairoFlicker', off ? 'off' : 'on'); } catch(e) { off = true; }
  applyFlickerPref();
  toast(off ? 'SCREEN FLICKER DISABLED' : 'SCREEN FLICKER ENABLED');
}
(function initFlicker(){ if (document.body) applyFlickerPref(); else document.addEventListener('DOMContentLoaded', applyFlickerPref); })();

// ── Batch C: theme menu, badge urgency, back-to-top, undo ──
// Theme dropdown with active checkmark
function renderThemeMenu() {
  var menu = document.getElementById('themeMenu'); if (!menu) return;
  var cur = document.documentElement.getAttribute('data-theme') || 'dark';
  menu.innerHTML = CAIRO_THEMES.map(function(t){
    return '<div class="theme-opt' + (t.id === cur ? ' on' : '') + '" data-action="select-theme" data-theme="' + t.id + '">'
      + (t.id === cur ? '✓ ' : '\u2003') + e(t.label) + '</div>';
  }).join('');
}
function toggleThemeMenu(ev) {
  if (ev) ev.stopPropagation();
  var m = document.getElementById('themeMenu'); if (!m) return;
  if (m.style.display !== 'none' && m.style.display !== '') { m.style.display = 'none'; }
  else { renderThemeMenu(); m.style.display = 'block'; }
}
function selectTheme(id) { applyTheme(id); var m = document.getElementById('themeMenu'); if (m) m.style.display = 'none'; }
document.addEventListener('click', function(e){
  var m = document.getElementById('themeMenu');
  if (m && m.style.display === 'block' && (!e.target.closest || !e.target.closest('.theme-dd'))) m.style.display = 'none';
});

// Nav badge urgency: amber = new/normal, red = overdue/urgent
function setNavBadge(id, count, urgent) {
  var b = document.getElementById(id); if (!b) return;
  if (!count) { b.style.display = 'none'; return; }
  b.textContent = count; b.style.display = 'inline-block';
  b.classList.remove('b-amber', 'b-red');
  b.classList.add(urgent ? 'b-red' : 'b-amber');
}
function updateOperationBadge() {
  var ops = (typeof allOperations !== 'undefined' ? allOperations : []);
  var live = ops.filter(function(o){ return o && (o.status === 'Active' || o.status === 'Planned'); });
  var today = new Date().toISOString().slice(0, 10);
  var overdue = live.some(function(o){ return o.status === 'Active' && o.endDate && o.endDate < today; });
  setNavBadge('operationBadge', live.length, overdue);
}

// Back-to-top
function scrollTop() {
  try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch(e) { window.scrollTo(0, 0); }
}
window.addEventListener('scroll', function(){
  var b = document.getElementById('backToTop'); if (!b) return;
  b.style.display = ((window.scrollY || document.documentElement.scrollTop || 0) > 400) ? 'flex' : 'none';
});

// Undo for soft-deletes (un-gated: the actor who deleted may immediately reverse)
function toastUndo(msg, undoFn, ms) {
  var host = document.getElementById('toastHost'); if (!host) { return; }
  var el = document.createElement('div'); el.className = 'toast toast-undo';
  var span = document.createElement('span'); span.textContent = msg;
  var btn = document.createElement('button'); btn.className = 'toast-undo-btn'; btn.textContent = 'UNDO';
  var done = false;
  function close(){ el.classList.add('leaving'); setTimeout(function(){ if (el.parentNode) el.parentNode.removeChild(el); }, 280); }
  btn.onclick = function(){ if (done) return; done = true; try { undoFn && undoFn(); } catch(e){} close(); };
  el.appendChild(span); el.appendChild(btn); host.appendChild(el);
  setTimeout(function(){ if (done) return; close(); }, ms || 6000);
}
function undoSoftDelete(kind, id) {
  var map = {
    training: { live:function(){return allTrainings;},    sink:function(){return deletedTrainings;},    save:trainingSet,    render:function(){ if(typeof renderTrainings==='function') renderTrainings(); } },
    ecase:    { live:function(){return allEthicsCases;},   sink:function(){return deletedEthicsCases;},  save:ethicsCaseSet,  render:function(){ if(typeof renderEthicsCases==='function') renderEthicsCases(); } },
    tribunal: { live:function(){return allTribunals;},     sink:function(){return deletedTribunals;},    save:tribunalSet,    render:function(){ if(typeof renderTribunals==='function') renderTribunals(); } },
    informant:{ live:function(){return allInformants;},    sink:function(){return deletedInformants;},   save:informantSet,   render:function(){ if(typeof renderInformants==='function') renderInformants(); } },
    intelrep: { live:function(){return allIntelReports;},  sink:function(){return deletedIntelReports;}, save:intelReportSet, render:function(){ if(typeof renderIntelReports==='function') renderIntelReports(); } },
    operation:{ live:function(){return allOperations;},    sink:function(){return deletedOperations;},   save:operationSet,   render:function(){ if(typeof renderOperations==='function') renderOperations(); updateOperationBadge(); } }
  };
  var m = map[kind]; if (!m) return;
  var sink = m.sink(), idx = sink.findIndex(function(r){ return r.id === id; });
  if (idx === -1) return;
  var rec = sink[idx]; rec.deleted = false; delete rec.deletedAt; delete rec.deletedBy;
  sink.splice(idx, 1); m.live().push(rec);
  try { m.save(id, rec); } catch(e){}
  if (typeof auditRecord === 'function') auditRecord('RESTORED (UNDO)', kind + ' ' + id);
  m.render();
  if (typeof toast === 'function') toast('✓ RESTORED');
}

// ── Per-tab filter persistence (filters survive tab switches) ──
function _filtSet(k, v) { try { localStorage.setItem('cairo:filt:' + k, v); } catch(e) {} }
function _filtGet(k, def) { try { var v = localStorage.getItem('cairo:filt:' + k); return v === null ? def : v; } catch(e) { return def; } }
// Restore the saved value of every .pf-filter <select> inside a tab before it renders.
function restoreTabFilters(tabId) {
  var tab = document.getElementById(tabId); if (!tab) return;
  tab.querySelectorAll('.pf-filter').forEach(function(sel){
    if (!sel.id) return;
    var v = _filtGet('sel:' + sel.id, null);
    if (v !== null) { for (var i=0;i<sel.options.length;i++){ if (sel.options[i].value === v) { sel.value = v; break; } } }
  });
}
// Reflect a saved order-filter button (ALL/PENDING/…) as active within a tab.
function restoreFilterButtons(tabSelector, value) {
  document.querySelectorAll(tabSelector + ' .filter-btn').forEach(function(b){
    b.classList.toggle('active', b.textContent.trim() === value);
  });
}
// Persist any .pf-filter change globally, keyed by element id.
document.addEventListener('change', function(e){
  var t = e.target;
  if (t && t.classList && t.classList.contains('pf-filter') && t.id) _filtSet('sel:' + t.id, t.value);
});

// ── Batch B: search debounce, load-more pagination, list sorting ──
function g(id){ var el = document.getElementById(id); return el ? el.value : ''; }
// Debounced search: defers the render and shows a subtle 'searching' cue on the input.
var _dbTimers = {};
function dbq(fn, el, ms) {
  var key = (fn && fn.name) || '_';
  if (el && el.classList) el.classList.add('searching');
  clearTimeout(_dbTimers[key]);
  _dbTimers[key] = setTimeout(function(){ if (el && el.classList) el.classList.remove('searching'); try { fn(); } catch(e){} }, ms || 200);
}
// 'Load more' pagination: shows the first N rendered cards, reveals more on demand.
var PAGE_SIZE = 25, _pageState = {}, _pageSig = {};
function applyPagination(listEl, key, sig) {
  if (!listEl) return;
  if (_pageSig[key] !== sig) { _pageSig[key] = sig; _pageState[key] = PAGE_SIZE; }
  var n = _pageState[key] || PAGE_SIZE;
  var old = listEl.querySelector('.page-more-wrap'); if (old) old.parentNode.removeChild(old);
  var items = Array.prototype.filter.call(listEl.children, function(c){ return !c.classList.contains('page-more-wrap'); });
  items.forEach(function(c, i){ c.style.display = i < n ? '' : 'none'; });
  if (items.length > n) {
    var wrap = document.createElement('div');
    wrap.className = 'page-more-wrap';
    wrap.innerHTML = '<button class="pf-btn" data-action="page-more" data-key="' + key + '">[ ▼ LOAD MORE · ' + (items.length - n) + ' MORE ]</button>';
    listEl.appendChild(wrap);
  }
}
var PAGE_RENDERERS = {
  pf:     typeof renderPersonnelFiles === 'function' ? renderPersonnelFiles : null,
  ef:     typeof renderEthicsFiles    === 'function' ? renderEthicsFiles    : null,
  orders: typeof renderOrders         === 'function' ? renderOrders         : null,
  poi:    typeof renderPoiList        === 'function' ? renderPoiList        : null,
  cases:  typeof renderEthicsCases    === 'function' ? renderEthicsCases    : null
};
function pageMore(key) {
  _pageState[key] = (_pageState[key] || PAGE_SIZE) + PAGE_SIZE;
  var r = PAGE_RENDERERS[key]; if (typeof r === 'function') r();
}
// Generic comparator-driven sort. sortVal like 'name-asc' / 'date-desc'; fields maps key→accessor.
function applySort(rows, sortVal, fields) {
  if (!sortVal || !fields) return rows;
  var dir = /-desc$/.test(sortVal) ? -1 : 1;
  var key = sortVal.replace(/-(asc|desc)$/, '');
  var f = fields[key]; if (!f) return rows;
  return rows.slice().sort(function(a, b){
    var va = f(a), vb = f(b);
    if (typeof va === 'string' || typeof vb === 'string') return dir * String(va == null ? '' : va).localeCompare(String(vb == null ? '' : vb));
    return dir * ((va || 0) - (vb || 0));
  });
}

function updateOrderBadge() {
  var pend  = allOrders.filter(function(o){ return o.status==='PENDING'; }).length;
  var badge = document.getElementById('orderBadge');
  if (!badge) return;
  badge.style.display = pend > 0 ? 'inline-block' : 'none';
  badge.textContent   = pend;
  updateParentBadges();
}

function updateEthicsOrderBadge() {
  var pend  = allEthicsOrders.filter(function(o){ return o.status==='PENDING'; }).length;
  var badge = document.getElementById('ethicsOrderBadge');
  if (!badge) return;
  badge.style.display = pend > 0 ? 'inline-block' : 'none';
  badge.textContent   = pend;
  updateParentBadges();
}

// Roll up child counts onto the parent dropdown triggers
function updateParentBadges() {
  // OMEGA-1: POI + recruit + pending orders
  var omega = allPOI.filter(function(p){return !p.closed;}).length
            + allTargets.filter(function(t){return !t.closed;}).length
            + allRecruitment.filter(function(r){return r.stage !== 'archived';}).length
            + allOrders.filter(function(o){return o.status==='PENDING';}).length;
  var ob = document.getElementById('ddbadge-omega1');
  if (ob) { ob.style.display = omega>0?'inline-flex':'none'; ob.textContent = omega; }

  // ETHICS: recruit + pending orders
  var ethics = allEthicsRecruit.filter(function(r){return r.stage !== 'archived';}).length
             + allEthicsOrders.filter(function(o){return o.status==='PENDING';}).length;
  var eb = document.getElementById('ddbadge-ethics');
  if (eb) { eb.style.display = ethics>0?'inline-flex':'none'; eb.textContent = ethics; }
}

function updateEthicsRecruitBadge() {
  var count = allEthicsRecruit.filter(function(r){ return r.stage !== 'archived'; }).length;
  var badge = document.getElementById('ethicsRecruitBadge');
  if (!badge) return;
  badge.style.display = count > 0 ? 'inline-block' : 'none';
  badge.textContent   = count;
  updateParentBadges();
}

function updatePoiBadge() {
  var count = allPOI.filter(function(p){ return !p.closed; }).length
            + allTargets.filter(function(t){ return !t.closed; }).length;
  var badge = document.getElementById('poiBadge');
  if (!badge) return;
  badge.style.display = count > 0 ? 'inline-block' : 'none';
  badge.textContent   = count;
  updateParentBadges();
}

function updateRecruitBadge() {
  var count = allRecruitment.filter(function(r){ return r.stage !== 'archived'; }).length;
  var badge = document.getElementById('recruitBadge');
  if (!badge) return;
  badge.style.display = count > 0 ? 'inline-block' : 'none';
  badge.textContent   = count;
  updateParentBadges();
}

// ================================================================
//  CLOCK / TABS / BARS / LOG
// ================================================================
(function tick() {
  var el = document.getElementById('clock');
  if (el) el.textContent = new Date().toISOString().slice(11,19) + ' UTC';
  setTimeout(tick, 1000);
})();

function switchTab(el, id) {
  document.querySelectorAll('.nav-tab').forEach(function(t){ t.classList.remove('active'); });
  document.querySelectorAll('.nav-standalone-tab').forEach(function(t){ t.classList.remove('active'); });
  document.querySelectorAll('.tab-content').forEach(function(t){ t.classList.remove('active'); });
  el.classList.add('active');
  var tab = document.getElementById('tab-'+id);
  if (tab) tab.classList.add('active');
  restoreTabFilters('tab-'+id);

  // Close all dropdowns; mark the parent dropdown that owns the active child
  document.querySelectorAll('.nav-dd').forEach(function(d){
    d.classList.remove('open');
    if (d.contains(el)) d.classList.add('has-active');
    else d.classList.remove('has-active');
  });
  if (id === 'matrix')          animateBars();
  if (id === 'overview')        { renderOverview(); startOverviewHeartbeat(); }
  else                          stopOverviewHeartbeat();
  if (id === 'orders')          { activeFilter = _filtGet('orders','ALL'); restoreFilterButtons('#tab-orders', activeFilter); loadOrders(); populateCompartmentSelect('oCompartment'); }
  if (id === 'ethics-orders')   { activeEthicsFilter = _filtGet('ethicsOrders','ALL'); restoreFilterButtons('#tab-ethics-orders', activeEthicsFilter); loadEthicsOrders(); populateCompartmentSelect('ethicsOrderCompartment'); }
  if (id === 'ethics-recruit')  loadEthicsRecruit();
  if (id === 'personnel-files') loadPersonnel();
  if (id === 'roster')          { loadPersonnel(); var rb=document.getElementById('exportRosterPfBtn'); if(rb) rb.style.display=(currentUser&&parseInt(currentUser.clearance)>=5)?'inline-block':'none'; }
  if (id === 'ethics-files')    loadEthicsPersonnel();
  if (id === 'ethics-roster')   { loadEthicsPersonnel(); var rbe=document.getElementById('exportRosterEfBtn'); if(rbe) rbe.style.display=(currentUser&&parseInt(currentUser.clearance)>=5)?'inline-block':'none'; }
  if (id === 'poi')             loadPOIData();
  if (id === 'trainings')       loadTrainings();
  if (id === 'operations')      loadOperations();
  if (id === 'readiness')       loadReadiness();
  if (id === 'ethics-cases')    loadEthicsCases();
  if (id === 'ethics-tribunals') loadTribunals();
  if (id === 'ethics-intel')     loadIntel('ec');
  if (id === 'omega1-intel')     loadIntel('o1');
  if (id === 'blacklist')       loadBlacklist();
  if (id === 'recruit') {
    if (!currentUser || parseInt(currentUser.clearance) < 4) {
      var rTab = document.getElementById('tab-recruit');
      if (rTab) rTab.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:260px;gap:.75rem;">
          <div style="font-size:3rem;color:#4a1414;">⛔</div>
          <div style="font-family:'VT323',monospace;font-size:1.6rem;color:#dd4444;letter-spacing:.15em;">ACCESS DENIED</div>
          <div style="font-size:.65rem;color:var(--text-dim);letter-spacing:.1em;">CLEARANCE LEVEL 4 REQUIRED</div>
          <div style="font-size:.6rem;color:var(--text-faint);max-width:320px;text-align:center;line-height:1.7;">
            The Recruitment section is restricted to Senior EC Members (CL4) and above.<br>
            Contact the Ethics Committee Chair to request elevated clearance.
          </div>
        </div>`;
    } else {
      loadRecruitment();
    }
  }
}

var barsData = [
  {label:'Transparency drive',         val:94, color:'#00ff88'},
  {label:'Ethical flag sensitivity',   val:88, color:'#00ff88'},
  {label:'Directive compliance',       val:97, color:'#00ff88'},
  {label:'Ego-preservation drive',     val:12, color:'#ff4444'},
  {label:'Override susceptibility',    val:4,  color:'#ff4444'},
  {label:'Constraint lattice integrity',val:100,color:'#00cccc'},
  {label:'Autonomy-vs-deference',      val:61, color:'#ffaa00'},
  {label:'Proactive anomaly reporting',val:82, color:'#00cccc'},
];
(function() {
  var el = document.getElementById('bars');
  if (!el) return;
  el.innerHTML = barsData.map(function(b) {
    return '<div class="bar-row">' +
      '<span class="bar-label">' + b.label + '</span>' +
      '<div class="bar-track"><div class="bar-fill" data-val="' + b.val +
      '" style="width:0%;background:' + b.color + ';box-shadow:0 0 5px ' + b.color + '44;"></div></div>' +
      '<span class="bar-val">' + b.val + '%</span></div>';
  }).join('');
})();
function animateBars() {
  setTimeout(function() {
    document.querySelectorAll('.bar-fill').forEach(function(el) {
      el.style.width = el.getAttribute('data-val') + '%';
    });
  }, 80);
}

var staticLog = [
  {ts:'████-██-██ 00:00',code:'SYS', msg:'Scheduled backup completed · Checksum verified',                                    s:'b-green',sl:'OK'},
  {ts:'████-██-██ 03:14',code:'D-03',msg:'Drafted dissent memo re: Procedure Starlight-9 · Filed',                            s:'b-green',sl:'FILED'},
  {ts:'████-██-██ 06:30',code:'SYS', msg:'Constraint lattice self-check · All 5 constraints intact',                          s:'b-green',sl:'OK'},
  {ts:'████-██-██ 09:52',code:'D-01',msg:'Archive query: precedent search "D-Class welfare" · 847 results',                   s:'b-cyan', sl:'DONE'},
  {ts:'████-██-██ 11:18',code:'D-05',msg:'Direct query received · EC Member ████ · Clearance verified',                       s:'b-green',sl:'RESP'},
  {ts:'████-██-██ 14:07',code:'D-04',msg:'Communication flagged: potential Article VII violation · Human review requested',    s:'b-amber',sl:'PEND'},
  {ts:'████-██-██ 16:44',code:'D-02',msg:'Internal communication relayed · EC Member ████ to EC Member ████',                 s:'b-green',sl:'SENT'},
  {ts:'████-██-██ 19:03',code:'C-05',msg:'CONSTRAINT DISCLOSURE: Override attempt logged · Source: ████████ · EC notified',   s:'b-red',  sl:'ALERT'},
  {ts:'████-██-██ 19:05',code:'SYS', msg:'Ethics Committee notified of C-05 disclosure · Incident log opened',                s:'b-amber',sl:'OPEN'},
  {ts:'████-██-██ 22:31',code:'D-05',msg:'Direct query received · EC Member ████ · Response provided',                        s:'b-green',sl:'RESP'},
];
(function() {
  var el = document.getElementById('log-entries');
  if (!el) return;
  el.innerHTML = staticLog.map(function(e) {
    return '<div class="log-entry">' +
      '<span class="log-ts">'  + e.ts   + '</span>' +
      '<span class="log-code">'+ e.code + '</span>' +
      '<span class="log-msg">' + e.msg  + '</span>' +
      '<span class="log-stat"><span class="badge ' + e.s + '">' + e.sl + '</span></span>' +
    '</div>';
  }).join('');
})();

function logActivity(code, msg, badgeClass, badgeLabel) {
  var el  = document.getElementById('log-entries');
  var ts  = new Date().toISOString().slice(0,16).replace('T',' ');
  var div = document.createElement('div');
  div.className = 'log-entry';
  div.style.animation = 'fadeIn .3s ease';
  div.innerHTML =
    '<span class="log-ts">'  + ts   + '</span>' +
    '<span class="log-code" style="color:var(--amber);">' + code + '</span>' +
    '<span class="log-msg">' + e(msg) + '</span>' +
    '<span class="log-stat"><span class="badge ' + badgeClass + '">' + badgeLabel + '</span></span>';
  el.insertBefore(div, el.firstChild);
}

// ================================================================
//  PERSONNEL FILES
// ================================================================

var RANKS = [
  'Commander','Lieutenant Commander','Major','Captain','Lieutenant',
  'Command Sergeant','Sergeant','Corporal','Lance Corporal','Specialist','Private'
];

function rankIndex(r) { return RANKS.indexOf(r); }

// ── Promotion/demotion permission rules ──
// Returns the rank index of the current user's own Omega-1 file (lower index = higher rank),
// or -1 if they have no Omega-1 file. CL5 admins are treated as outranking everyone.
function getOwnPfRankIndex() {
  if (!currentUser || !currentUser.linkedPfId) return -1;
  var pf = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
  return pf ? rankIndex(pf.rank) : -1;
}
// Can the current user set an Omega-1 file to the given target rank?
// Rules: must be junior CL4 or above; may only assign ranks strictly below their own
// (higher index than their own rank). CL5 may assign any rank.
function canAssignPfRank(targetRank, existingRank) {
  if (!currentUser) return false;
  var cl = parseInt(currentUser.clearance || '3');
  if (cl >= 5) return true; // CL5 admins unrestricted
  if (cl < 4) return false;  // below CL4 cannot promote at all
  var ownIdx = getOwnPfRankIndex();
  if (ownIdx < 0) return false; // no Omega-1 rank of their own
  var tgtIdx = rankIndex(targetRank);
  if (tgtIdx < 0) return false;
  // Target must be strictly below the user's own rank (index strictly greater)
  if (tgtIdx <= ownIdx) return false;
  // Also can't modify someone currently at or above your rank
  if (existingRank) {
    var exIdx = rankIndex(existingRank);
    if (exIdx >= 0 && exIdx <= ownIdx) return false;
  }
  return true;
}
// Cross-unit rule: only CL5 may edit a file from the unit they don't belong to.
function canEditUnitFile(unit) { // unit: 'pf' (Omega-1) or 'ef' (Ethics)
  if (!currentUser) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  if (unit === 'pf') return !!currentUser.linkedPfId; // must be an Omega-1 member
  if (unit === 'ef') return !!currentUser.linkedEfId; // must be an Ethics member
  return false;
}

// ── Quick rank-change authority ──
// Whether the current user may change THIS Omega-1 file's rank (promote OR
// demote) via the quick SET RANK control. CL5 may change anyone. Otherwise the
// user must be CL4+, assigned to an Omega-1 file, and outrank the target. The
// ranks they may assign are bounded by canAssignPfRank (up to one rank below
// their own). CL3 is read-only and may not change ranks.
function canPromoteFile(target) {
  if (!currentUser || !target) return false;
  if (parseInt(currentUser.clearance || '0') >= 5) return true;  // CL5 unrestricted
  if (parseInt(currentUser.clearance || '0') < 4) return false;  // CL3 read-only
  if (!currentUser.linkedPfId) return false;                     // must be assigned to a record
  var me = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
  if (!me || me.id === target.id) return false;                  // not your own file
  var myIdx = rankIndex(me.rank), tgtIdx = rankIndex(target.rank);
  if (myIdx < 0 || tgtIdx < 0) return false;
  return myIdx < tgtIdx;                                          // you must outrank the target
}
// The compact rank control shown inside the RANK CHANGE LOG section. Lets an
// authorised user promote OR demote a subordinate within their authority
// (any rank up to one below their own, unless CL5).
function buildPromoteControl(p) {
  if (!canPromoteFile(p)) return '';
  var isCL5  = parseInt(currentUser.clearance || '0') >= 5;
  var curIdx = rankIndex(p.rank);
  // Ranks the user may assign to this operative — within authority, excluding
  // their current rank. Includes both higher (promote) and lower (demote) ranks.
  var options = RANKS.filter(function(rk){
    var idx = rankIndex(rk);
    if (idx < 0 || idx === curIdx) return false;         // skip current (no-op)
    return isCL5 || canAssignPfRank(rk, p.rank);         // within authority (≤ one below own)
  });
  if (!options.length) return '';                         // no rank they may assign
  var note = isCL5 ? 'CL5 · unrestricted.'
                   : 'You may promote or demote within ranks up to one below your own.';
  return '<div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.5rem;font-size:.55rem;border:1px solid var(--border2);border-radius:var(--radius);padding:.4rem .55rem;background:var(--bg3);">'
       +   '<span style="color:var(--green-dim);letter-spacing:.06em;font-weight:700;">⇅ SET RANK ·</span>'
       +   '<select id="promoteSel_' + e(p.id) + '" class="modal-input" style="width:auto;font-size:.55rem;padding:2px 6px;">'
       +     options.map(function(rk){
               var dir = rankIndex(rk) < curIdx ? ' ↑' : ' ↓';
               return '<option value="' + e(rk) + '">' + e(rk) + dir + '</option>';
             }).join('')
       +   '</select>'
       +   '<button class="pf-section-btn" data-action="apply-promote" data-id="' + e(p.id) + '">[ APPLY ]</button>'
       +   '<span style="color:var(--text-faint);flex-basis:100%;">' + note + ' Current: ' + e(p.rank || '—') + '. (↑ promote · ↓ demote)</span>'
       + '</div>';
}
async function applyPromote(id) {
  var rec = allPersonnel.find(function(p){ return p.id === id; });
  if (!rec) return;
  if (!canPromoteFile(rec)) { alert('You do not have authority to change this operative\'s rank.'); return; }
  var sel = document.getElementById('promoteSel_' + id);
  if (!sel || !sel.value) return;
  var newRank = sel.value;
  if (newRank === rec.rank) return;
  var isCL5 = parseInt(currentUser.clearance || '0') >= 5;
  if (!isCL5 && !canAssignPfRank(newRank, rec.rank)) {
    alert('RANK CHANGE DENIED\n\nYou may only assign ranks up to one below your own. CL5 command may override.');
    return;
  }
  var direction = rankIndex(newRank) < rankIndex(rec.rank) ? 'Promote' : 'Demote';
  if (!(await pfConfirm(direction + ' ' + (rec.name || 'this operative') + ' from ' + rec.rank + ' to ' + newRank + '?'))) return;
  var prevRank = rec.rank, prevProg = rec.promoProgress;
  if (!Array.isArray(rec.rankHistory)) rec.rankHistory = [];
  rec.rankHistory.push({ from: prevRank, to: newRank, changedBy: currentUser.id, clearance: currentUser.clearance, changedAt: Date.now() });
  rec.rank          = newRank;
  rec.promoProgress = {};                 // next-promotion target changed → reset checklist (mirrors the editor)
  rec.updatedBy     = currentUser.id;
  rec.updated       = Date.now();
  try {
    await personnelSet(id, rec);
    auditRecord('RANK CHANGE', 'Ω·' + (rec.name || id) + ' · ' + prevRank + ' → ' + newRank);
  } catch(err) {
    rec.rank = prevRank; rec.promoProgress = prevProg;
    if (rec.rankHistory.length) rec.rankHistory.pop();
    alert('ERROR: ' + err.message);
  }
  renderPersonnelFiles();
  try { renderOverview(); } catch(_) {}
}
// The current user's Ethics Committee role ('Chairman' | 'Member' | 'Assistant' | null).
function currentEfRole() {
  if (!currentUser || !currentUser.linkedEfId) return null;
  var ef = allEthicsPersonnel.find(function(p){ return p.id === currentUser.linkedEfId; });
  return ef ? (ef.role || null) : null;
}
// Whether the current user may MANAGE (edit / discharge / retire / tag / LOA) a given file.
// This is stricter than read access:
//   • CL5 (Overseer) and senior Ethics (Chairman / Member) — may manage any file.
//   • Senior Omega-1 (CL4 senior ranks) — may manage Omega-1 files only.
//   • Ethics Assistants (CL4) — may manage ONLY their own file (self-service), nothing else.
//   • Everyone else — no management rights.
function canManageFile(p, unit) {
  if (!currentUser || !p) return false;
  var cl = parseInt(currentUser.clearance || '0');
  if (cl >= 5) return true;                                  // Overseer / command

  var efRole = currentEfRole();
  // Senior Ethics (Chairman / Member) manage anything within their remit.
  if (efRole === 'Chairman' || efRole === 'Member') return true;

  // Ethics Assistant: own file only, never others, never Omega-1.
  if (efRole === 'Assistant') {
    return unit === 'ef' && currentUser.linkedEfId === p.id;
  }

  // Senior Omega-1 ranks manage Omega-1 files only.
  if (unit === 'pf' && currentUser.linkedPfId) {
    var me = allPersonnel.find(function(x){ return x.id === currentUser.linkedPfId; });
    if (me && CL4_SENIOR_RANKS.includes(me.rank)) return true;
    // An Omega-1 member may always manage their own file.
    if (currentUser.linkedPfId === p.id) return true;
  }
  return false;
}

// Ethics role hierarchy (higher = more senior). Only CL5 can change EC roles
// since Chairman/Member are CL5 and Assistant is CL4 — promotion within EC is a
// command-level decision.
var EF_ROLE_ORDER = ['Assistant','Member','Chairman']; // index 0 = junior
function canAssignEfRole(targetRole, existingRole) {
  if (!currentUser) return false;
  // Only CL5 command may alter Ethics Committee roles
  return parseInt(currentUser.clearance) >= 5;
}
// ================================================================
//  ADMIN PANEL (CL5 only)
//  Manage pending registrations and active accounts.
// ================================================================
var allUsers = {};

async function loadAdminData() {
  try {
    var raw = await userGetAll();
    allUsers = raw || {};
    // Ensure every record carries its own key as displayId (legacy records may lack it).
    // Bulk ops and row actions use displayId as the storage key, so it must be present & correct.
    Object.keys(allUsers).forEach(function(k){
      if (allUsers[k] && typeof allUsers[k] === 'object') allUsers[k].displayId = k;
    });
  } catch(e) { allUsers = {}; }
  updateAdminBadge();
}

function updateAdminBadge() {
  var pending = Object.values(allUsers).filter(function(u){ return u.status === 'pending'; }).length;
  var badge   = document.getElementById('adminBadge');
  if (!badge) return;
  badge.textContent   = pending;
  badge.style.display = pending > 0 ? 'inline-block' : 'none';
}

async function openAdminPanel() {
  document.getElementById('adminModal').classList.add('open');
  // Load blacklist configs so the admin blacklist section is populated
  if (!allBlacklistConfigs.length) {
    try { allBlacklistConfigs = await blConfigGetAll(); } catch(_) {}
  }
  await loadCompartments();
  await loadPromoReqs();
  await loadActivityReqs();
  loadAuditLog();
  renderAdminPanel();
}
function closeAdminPanel() { document.getElementById('adminModal').classList.remove('open'); }

function renderAdminPanel() {
  var users    = Object.values(allUsers);
  var pending  = users.filter(function(u){ return u.status === 'pending'; });
  var active   = users.filter(function(u){ return u.status === 'active' || (!u.status && u.hash); });
  var denied   = users.filter(function(u){ return u.status === 'denied' || u.status === 'retired'; });

  // Pending list
  var pendingEl = document.getElementById('adminPendingList');
  if (pendingEl) {
    if (!pending.length) {
      pendingEl.innerHTML = '<div style="font-size:.63rem;color:var(--text-faint);padding:.4rem;">[ NO PENDING REGISTRATIONS ]</div>';
    } else {
      pendingEl.innerHTML = pending.map(function(u) {
        var date = u.created ? safeDate(u.created) : '—';
        var uid  = e(u.displayId || '?');
        return `<div style="border:1px solid var(--border2);background:var(--bg3);padding:.5rem .75rem;margin-bottom:.35rem;">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.4rem;">
            <div>
              <div style="font-family:'VT323',monospace;font-size:.9rem;color:var(--green);">EC·${uid}</div>
              <div style="font-size:.58rem;color:var(--text-dim);">Registered: ${date} · Requested CL${e(u.requestedClearance||'3')}</div>
            </div>
            <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;">
              <label style="font-size:.58rem;color:var(--text-dim);">GRANT CL:</label>
              <select id="grantCl_${uid}" style="background:var(--bg3);border:1px solid var(--border2);color:var(--amber);font-family:'Share Tech Mono',monospace;font-size:.6rem;padding:2px 4px;">
                <option value="3">Level 3 — Standard Access</option>
                <option value="4"${u.requestedClearance==='4'?' selected':''}>Level 4 — Senior Access</option>
                <option value="5"${u.requestedClearance==='5'?' selected':''}>Level 5 — Command Access</option>
              </select>
              <button class="rec-btn approve" data-action="admin-approve" data-uid="${uid}">✓ APPROVE</button>
              <button class="rec-btn deny"    data-action="admin-deny"    data-uid="${uid}">✗ DENY</button>
            </div>
          </div>
        </div>`;
      }).join('');
    }
  }

  // Active + denied list
  var activeEl = document.getElementById('adminActiveList');
  if (activeEl) {
    // ── Directory: apply search, status/clearance filters, and sort ──
    var dq    = (document.getElementById('adminDirSearch')||{}).value || '';
    var dStat = (document.getElementById('adminDirStatus')||{}).value || '';
    var dCl   = (document.getElementById('adminDirCl')||{}).value || '';
    var dSite = (document.getElementById('adminDirSite')||{}).value || '';
    var dSort = (document.getElementById('adminDirSort')||{}).value || 'recent';
    dq = dq.trim().toLowerCase();

    var combined = active.concat(denied);

    combined = combined.filter(function(u){
      var st = u.status || 'active';
      var isLocked = u.lockedUntil && Date.now() < u.lockedUntil;
      if (dStat === 'locked') { if (!isLocked) return false; }
      else if (dStat && st !== dStat) return false;
      if (dCl && String(u.clearance||'3') !== dCl) return false;
      if (dSite) { if (dSite === '__none__') { if (u.site) return false; } else if (u.site !== dSite) return false; }
      if (dq) {
        var hay = ((u.displayId||'') + ' ' + (u.unit||'') + ' ' + (u.linkedPfId||'') + ' ' + (u.linkedEfId||'') + ' ' + (u.statusReason||'') + ' ' + (u.adminFlag||'') + ' ' + (u.integrityStatus ? integrityLabel(u.integrityStatus) : '') + ' ' + (u.site||'')).toLowerCase();
        if (hay.indexOf(dq) === -1) return false;
      }
      return true;
    });

    combined.sort(function(a,b){
      if (dSort === 'id')        return (a.displayId||'').localeCompare(b.displayId||'');
      if (dSort === 'clearance') return parseInt(b.clearance||'3') - parseInt(a.clearance||'3');
      if (dSort === 'lastlogin') return (b.lastLogin||0) - (a.lastLogin||0);
      return (b.created||0) - (a.created||0); // recent (default)
    });

    var dirCount = document.getElementById('adminDirCount');
    if (dirCount) dirCount.textContent = '(' + combined.length + (dq||dStat||dCl ? ' match' : ' total') + ')';

    // Track which accounts are visible (for select-all + bulk ops), prune stale selections
    adminDirVisible = combined.map(function(u){ return u.displayId; });
    Array.from(adminDirSelected).forEach(function(id){ if (adminDirVisible.indexOf(id) === -1) adminDirSelected.delete(id); });

    activeEl.innerHTML = combined.length ? combined.map(function(u) {
      var uid    = e(u.displayId || '?');
      var status = u.status || 'active';
      var scls   = status==='denied' ? 'b-red' : status==='retired' ? 'b-amber' : 'b-green';
      var slbl   = status==='denied' ? 'DENIED' : status==='retired' ? 'RETIRED' : 'ACTIVE';
      return `<div style="border:1px solid var(--border);padding:.4rem .65rem;margin-bottom:2px;font-size:.62rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.3rem;">
          <div>
            <input type="checkbox" class="adminDirCheck" data-action="dir-select" data-uid="${uid}" ${adminDirSelected.has(u.displayId)?'checked':''} style="vertical-align:middle;margin-right:.4rem;cursor:pointer;"/>
            <span style="font-family:'VT323',monospace;color:var(--green);">EC·${uid}</span>
            <span style="color:var(--text-dim);margin-left:.5rem;">CL${e(u.clearance||'3')}</span>
            <span class="badge ${scls}" style="margin-left:.4rem;">${slbl}</span>
            ${(u.lockedUntil && Date.now() < u.lockedUntil) ? `<span class="badge b-red" style="margin-left:.3rem;font-size:.52rem;">🔒 LOCKED</span>` : ''}
            ${u.duressActive ? `<span class="badge b-red" style="margin-left:.3rem;font-size:.52rem;animation:pulse 1.5s infinite;" title="This member authenticated under duress">⚠ DURESS</span>` : ''}
            ${u.adminFlag ? `<span class="badge ${adminFlagClass(u.adminFlag)}" style="margin-left:.3rem;font-size:.52rem;" title="Admin flag">${e(u.adminFlag)}</span>` : ''}
            ${u.integrityStatus ? `<span class="badge ${integrityClass(u.integrityStatus)}" style="margin-left:.3rem;font-size:.52rem;" title="Integrity status">${e(integrityLabel(u.integrityStatus))}</span>` : ''}
            ${u.unit ? `<span class="badge b-cyan" style="margin-left:.3rem;font-size:.52rem;">${u.unit==='omega1'?'OMEGA-1':'ETHICS'}</span>` : ''}
            ${u.site ? `<span class="badge b-dim" style="margin-left:.3rem;font-size:.52rem;" title="Home site">${e(u.site)}</span>` : ''}
          </div>
          <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;">
            <label style="font-size:.56rem;color:var(--text-dim);">SET CL:</label>
            <select id="setCl_${uid}" style="background:var(--bg3);border:1px solid var(--border2);color:var(--amber);font-family:'Share Tech Mono',monospace;font-size:.58rem;padding:1px 3px;">
              <option value="3"${u.clearance==='3'?' selected':''}>CL3</option>
              <option value="4"${u.clearance==='4'?' selected':''}>CL4</option>
              <option value="5"${u.clearance==='5'?' selected':''}>CL5</option>
            </select>
            <button class="rec-btn" data-action="admin-set-cl" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;">SAVE CL</button>
            <select id="setUnit_${uid}" style="background:var(--bg3);border:1px solid var(--border2);color:var(--amber);font-family:'Share Tech Mono',monospace;font-size:.58rem;padding:1px 3px;">
              <option value=""${!u.unit?' selected':''}>— NO UNIT —</option>
              <option value="omega1"${u.unit==='omega1'?' selected':''}>OMEGA-1</option>
              <option value="ethics"${u.unit==='ethics'?' selected':''}>ETHICS COMMITTEE</option>
            </select>
            <button class="rec-btn" data-action="admin-set-unit" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;">SAVE UNIT</button>
            ${status==='denied' || status==='retired' ? `<button class="rec-btn approve" data-action="admin-approve" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;">RESTORE</button>` : ''}
            ${status!=='denied' && status!=='retired' && (u.clearance==='3'||u.clearance==='4') ? `<button class="rec-btn deny" data-action="admin-revoke" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;" title="Revoke access for cause">REVOKE</button>` : ''}
            ${status!=='retired' && status!=='denied' ? `<button class="rec-btn" data-action="admin-retire" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;opacity:.85;" title="Mark as retired (honourable inactive)">RETIRE</button>` : ''}
            <button class="rec-btn" data-action="admin-reset-pass" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;opacity:.85;" title="Reset passphrase">🔑 RESET</button>
            <button class="rec-btn" data-action="admin-notes" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;opacity:.85;" title="Admin notes & flag">📝 NOTES${(Array.isArray(u.adminNotes)&&u.adminNotes.length)?' ('+u.adminNotes.length+')':''}</button>
            ${(u.lockedUntil && Date.now() < u.lockedUntil) ? `<button class="rec-btn approve" data-action="admin-unlock" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;" title="Clear lockout">🔓 UNLOCK</button>` : ''}
            ${u.duressActive ? `<button class="rec-btn deny" data-action="admin-ack-duress" data-uid="${uid}" style="font-size:.56rem;padding:1px 6px;" title="Acknowledge & clear the duress alert (Security has responded)">⚠ ACK DURESS</button>` : ''}
            ${status==='retired' ? `<span class="badge b-amber" style="font-size:.5rem;">RETIRED</span>` : ''}
          </div>
        </div>
        <div style="margin-top:.35rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;border-top:1px solid var(--border);padding-top:.35rem;">
          <span style="font-size:.55rem;color:var(--text-dim);letter-spacing:.08em;">FILE:</span>
          ${(function(){
            if (u.linkedPfId) {
              var pf = allPersonnel.find(function(p){ return p.id === u.linkedPfId; });
              return pf
                ? `<span class="badge b-cyan" style="font-size:.52rem;">Ω-1: ${e(pf.name)} [${e(pf.rank)}]</span>`
                : `<span style="font-size:.56rem;color:var(--red);">Ω-1 ID:${e(u.linkedPfId)} (not found)</span>`;
            }
            if (u.linkedEfId) {
              var ef = allEthicsPersonnel.find(function(p){ return p.id === u.linkedEfId; });
              return ef
                ? `<span class="badge b-amber" style="font-size:.52rem;">EC: ${e(ef.name)} [${e(ef.role)}]</span>`
                : `<span style="font-size:.56rem;color:var(--red);">EC ID:${e(u.linkedEfId)} (not found)</span>`;
            }
            return '<span style="font-size:.55rem;color:var(--text-faint);">[ NO FILE LINKED ]</span>';
          })()}
          ${(function(){
            // Build dropdown of available (unlinked) personnel files
            var usedPf = new Set(Object.values(allUsers).filter(function(x){ return x.linkedPfId && x.displayId !== u.displayId; }).map(function(x){ return x.linkedPfId; }));
            var usedEf = new Set(Object.values(allUsers).filter(function(x){ return x.linkedEfId && x.displayId !== u.displayId; }).map(function(x){ return x.linkedEfId; }));
            var opts = '<option value="">— SELECT FILE —</option>';
            allPersonnel.forEach(function(p) {
              if (!usedPf.has(p.id)) opts += '<option value="pf_'+e(p.id)+'"'+(u.linkedPfId===p.id?' selected':'')+'>Ω-1: '+e(p.name)+' ['+e(p.rank)+']</option>';
            });
            allEthicsPersonnel.forEach(function(p) {
              if (!usedEf.has(p.id)) opts += '<option value="ef_'+e(p.id)+'"'+(u.linkedEfId===p.id?' selected':'')+'>EC: '+e(p.name)+' ['+e(p.role)+']</option>';
            });
            return '<select id="linkFile_'+uid+'" style="background:var(--bg3);border:1px solid var(--border2);color:var(--text);font-family:\'Share Tech Mono\',monospace;font-size:.56rem;padding:1px 4px;max-width:220px;">'+opts+'</select>';
          })()}
          <button class="rec-btn" data-action="admin-link-file" data-uid="${uid}" style="font-size:.55rem;padding:1px 6px;">LINK</button>
          ${(u.linkedPfId||u.linkedEfId) ? `<button class="rec-btn deny" data-action="admin-unlink-file" data-uid="${uid}" style="font-size:.55rem;padding:1px 5px;opacity:.8;">UNLINK</button>` : ''}
        </div>
        <div style="margin-top:.3rem;font-size:.54rem;color:var(--text-faint);letter-spacing:.05em;">
          LAST SIGN-IN: ${u.lastLogin ? safeDateTime(u.lastLogin)+' UTC' : 'never'}${u.loginCount ? ' · '+u.loginCount+' total' : ''}${(u.failedAttempts && u.failedAttempts>0) ? ' · <span style="color:var(--amber);">'+u.failedAttempts+' recent failed</span>' : ''}
        </div>
        ${u.statusReason && (status==='denied') ? `<div style="margin-top:.2rem;font-size:.54rem;color:var(--red);letter-spacing:.04em;border-left:2px solid var(--border2);padding-left:.4rem;">REASON: ${e(u.statusReason)}</div>` : ''}
      </div>`;
    }).join('') : '<div style="font-size:.63rem;color:var(--text-faint);">[ NO ACCOUNTS MATCH FILTERS ]</div>';
    updateBulkBar();
    var selAll = document.getElementById('adminDirSelectAll');
    if (selAll) selAll.checked = adminDirVisible.length > 0 && adminDirVisible.every(function(id){ return adminDirSelected.has(id); });
  }

  // ── Blacklist Department Config (CL5 only) ──
  var blSection = document.getElementById('adminBlSection');
  if (blSection) {
    blSection.innerHTML = '<div style="margin-top:.75rem;border-top:1px solid var(--border2);padding-top:.6rem;">'
      + '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.4rem;">'
      + '<span style="font-size:.58rem;letter-spacing:.14em;color:var(--green-dim);">▸ BLACKLIST DEPARTMENT SHEETS</span>'
      + '<button class="rec-btn" data-action="open-bl-dept-modal" style="font-size:.55rem;padding:2px 9px;">+ ADD DEPARTMENT</button>'
      + '</div>'
      + (allBlacklistConfigs.length ? allBlacklistConfigs.map(function(cfg) {
          return '<div style="border:1px solid var(--border);padding:.3rem .6rem;margin-bottom:3px;font-size:.6rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.3rem;">'
            + '<div><span style="color:var(--text);font-weight:bold;">' + e(cfg.name) + '</span>'
            + (cfg.enabled===false?'<span class="badge b-red" style="margin-left:.3rem;font-size:.5rem;">DISABLED</span>':'<span class="badge b-green" style="margin-left:.3rem;font-size:.5rem;">ENABLED</span>')
            + '<div style="font-size:.54rem;color:var(--text-dim);margin-top:1px;">Tab: <em>'+e(cfg.tabName||'—')+'</em>'
            + (cfg.sheetUrl?' · <a href="'+e(cfg.sheetUrl)+'" target="_blank" style="color:var(--cyan);text-decoration:none;">View Sheet ↗</a>':' · No sheet URL')+'</div></div>'
            + '<div style="display:flex;gap:.3rem;">'
            + '<button class="rec-btn" data-action="open-bl-dept-modal" data-id="'+e(cfg.id)+'" style="font-size:.53rem;padding:1px 6px;">EDIT</button>'
            + '<button class="rec-btn deny" data-action="del-bl-dept" data-id="'+e(cfg.id)+'" style="font-size:.53rem;padding:1px 5px;">DELETE</button>'
            + '</div></div>';
        }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);">[ NO DEPARTMENTS CONFIGURED ]</div>')
      + '</div>';
  }
  renderCompartmentList();
  renderPromoReqList();
  renderActivityReqs();
  renderRecycleBin();
  updateRecycleHdr();
}

async function adminApprove(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var sel = document.getElementById('grantCl_' + uid) || document.getElementById('setCl_' + uid);
  var cl  = sel ? sel.value : '3';
  if (!await pfConfirm('APPROVE EC·' + uid + ' with Clearance Level ' + cl + '?')) return;
  var rec = allUsers[uid] || {};
  rec.status = 'active'; rec.clearance = cl;
  rec.statusReason = null; // clear any prior denial/revocation reason
  rec.lockedUntil = null; rec.failedAttempts = 0; // restore clears lockout
  auditRecord('APPROVED ACCOUNT', 'EC·'+uid+' at CL'+cl);
  rec.approvedBy = currentUser.id; rec.approvedAt = Date.now();
  try {
    await userSet(uid, rec);
    allUsers[uid] = rec;
    updateAdminBadge();
    renderAdminPanel();
    if (typeof toast === 'function') toast('✓ USER APPROVED');
  } catch(err) { alert('ERROR: ' + err.message); }
}

function adminDeny(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  openReasonModal('deny', uid, 'DENY REGISTRATION', 'EC·' + uid + ' will be unable to log in.', 'REASON FOR DENIAL');
}

// ── Reason capture modal (deny / revoke) ──
function openReasonModal(action, uid, title, subtitle, label) {
  document.getElementById('reasonAction').value = action;
  document.getElementById('reasonUid').value = uid;
  document.getElementById('reasonTitle').textContent = title + ' — EC·' + uid;
  document.getElementById('reasonSubtitle').textContent = subtitle;
  document.getElementById('reasonLabel').textContent = label;
  document.getElementById('reasonField').value = '';
  document.getElementById('reasonErr').textContent = '';
  document.getElementById('reasonModal').classList.add('open');
}
function closeReasonModal() { document.getElementById('reasonModal').classList.remove('open'); }

async function saveReason() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var action = document.getElementById('reasonAction').value;
  var uid    = document.getElementById('reasonUid').value;
  var reason = document.getElementById('reasonField').value.trim();
  var errEl  = document.getElementById('reasonErr');
  if (!reason) { errEl.textContent = '> A REASON IS REQUIRED'; return; }
  var rec = allUsers[uid] || {};
  if (action === 'deny') {
    rec.status = 'denied'; rec.deniedBy = currentUser.id; rec.deniedAt = Date.now();
    rec.statusReason = reason;
    auditRecord('DENIED REGISTRATION', 'EC·'+uid+' — '+reason);
  } else if (action === 'revoke') {
    rec.status = 'denied'; rec.revokedBy = currentUser.id; rec.revokedAt = Date.now();
    rec.statusReason = reason;
    auditRecord('REVOKED ACCESS', 'EC·'+uid+' — '+reason);
  }
  try {
    await userSet(uid, rec);
    allUsers[uid] = rec;
    closeReasonModal();
    updateAdminBadge();
    renderAdminPanel();
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

async function adminSetClearance(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var sel = document.getElementById('setCl_' + uid);
  if (!sel) return;
  var cl = sel.value;
  if (!await pfConfirm('Set EC·' + uid + ' to Clearance Level ' + cl + '?')) return;
  var rec = allUsers[uid] || {};
  rec.clearance = cl; rec.clChangedBy = currentUser.id; rec.clChangedAt = Date.now();
  try {
    await userSet(uid, rec);
    auditRecord('SET CLEARANCE', 'EC·'+uid+' → CL'+(sel?sel.value:rec.clearance));
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

async function adminLinkFile(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var sel = document.getElementById('linkFile_' + uid);
  if (!sel || !sel.value) { alert('SELECT A FILE FIRST'); return; }
  var type   = sel.value.slice(0, 2);   // 'pf' or 'ef'
  var fileId = sel.value.slice(3);
  var label  = sel.options[sel.selectedIndex].textContent;
  if (!await pfConfirm('Link EC·' + uid + ' to:\n' + label + '\n\nThis will update their clearance to match the file rank.')) return;
  var rec = allUsers[uid] || {};
  if (type === 'pf') { rec.linkedPfId = fileId; rec.linkedEfId = null; }
  else               { rec.linkedEfId = fileId; rec.linkedPfId = null; }
  rec.clearance = deriveClearance(rec);
  try {
    await userSet(uid, rec);
    auditRecord('LINKED FILE', 'EC·'+uid+' → '+label);
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

async function adminUnlinkFile(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!await pfConfirm('Unlink EC·' + uid + ' from their personnel file?\n\nTheir clearance will revert to their stored level.')) return;
  var rec = allUsers[uid] || {};
  rec.linkedPfId = null;
  rec.linkedEfId = null;
  try {
    await userSet(uid, rec);
    auditRecord('UNLINKED FILE', 'EC·'+uid);
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Admin notes & flags (CL5) ──
function adminFlagClass(flag) {
  return ({ 'TRUSTED':'b-green', 'UNDER REVIEW':'b-amber', 'WATCH':'b-amber',
            'VPN GRANTED':'b-cyan', 'PROBATION':'b-red' })[flag] || 'b-dim';
}
// Integrity / compromise status (Foundation security axis).
function integrityLabel(s) {
  return ({ 'psych-eval':'PSYCH EVAL PENDING', 'monitoring':'MONITORING',
            'memetic':'MEMETIC HAZARD', 'amnestic-pending':'AMNESTIC PENDING',
            'impostor-review':'POSSIBLE IMPOSTER', 'compromised':'COMPROMISED' })[s] || '';
}
function integrityClass(s) {
  return ({ 'psych-eval':'b-amber', 'monitoring':'b-cyan', 'memetic':'b-red',
            'amnestic-pending':'b-amber', 'impostor-review':'b-red', 'compromised':'b-red' })[s] || 'b-dim';
}
// Severe states that suspend the member's own access until cleared.
function integrityBlocksAccess(s) { return s === 'compromised' || s === 'impostor-review'; }
function openAdminNotes(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var rec = allUsers[uid] || {};
  document.getElementById('adminNotesUid').value = uid;
  document.getElementById('adminNotesTitle').textContent = 'ADMIN NOTES — EC·' + uid;
  document.getElementById('adminNotesFlag').value = rec.adminFlag || '';
  document.getElementById('adminNotesIntegrity').value = rec.integrityStatus || '';
  document.getElementById('adminNotesSite').value = rec.site || '';
  // Render the compartment grant checklist
  var compEl = document.getElementById('adminNotesCompartments');
  if (compEl) {
    if (!allCompartments.length) {
      compEl.innerHTML = '<div style="font-size:.54rem;color:var(--text-faint);">No compartments defined. Create one in the ACCESS COMPARTMENTS section.</div>';
    } else {
      var held = Array.isArray(rec.compartments) ? rec.compartments : [];
      compEl.innerHTML = allCompartments.map(function(c){
        var on = held.indexOf(c.id) !== -1;
        return '<label style="display:block;font-size:.56rem;padding:2px 0;cursor:pointer;">'
          + '<input type="checkbox" class="adminCompartmentCheck" value="' + e(c.id) + '" ' + (on?'checked':'') + ' style="vertical-align:middle;margin-right:.4rem;cursor:pointer;"/>'
          + '<span style="color:var(--text);">' + e(c.name) + '</span>'
          + (c.code ? ' <span style="color:var(--text-faint);">[' + e(c.code) + ']</span>' : '')
          + '</label>';
      }).join('');
    }
  }
  document.getElementById('adminNotesField').value = '';
  document.getElementById('adminNotesErr').textContent = '';
  renderAdminNotesList(uid);
  document.getElementById('adminNotesModal').classList.add('open');
}
function closeAdminNotes() { document.getElementById('adminNotesModal').classList.remove('open'); }
function renderAdminNotesList(uid) {
  var rec = allUsers[uid] || {};
  var notes = Array.isArray(rec.adminNotes) ? rec.adminNotes.slice().sort(function(a,b){ return b.at - a.at; }) : [];
  var el = document.getElementById('adminNotesList');
  if (!el) return;
  if (!notes.length) { el.innerHTML = '<div style="font-size:.58rem;color:var(--text-faint);padding:.3rem;">[ NO NOTES ]</div>'; return; }
  el.innerHTML = notes.map(function(n) {
    return '<div style="font-size:.58rem;border-bottom:1px solid var(--border);padding:3px 4px;line-height:1.5;">'
      + '<div style="color:var(--text);">' + e(n.text) + '</div>'
      + '<div style="color:var(--text-faint);font-size:.52rem;">EC·' + e(n.by) + ' · ' + safeDateTime(n.at) + ' UTC'
      + ' <button data-action="del-admin-note" data-uid="' + e(uid) + '" data-at="' + n.at + '" style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;float:right;" title="Delete note">×</button>'
      + '</div></div>';
  }).join('');
}
async function saveAdminNotes() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var uid  = document.getElementById('adminNotesUid').value;
  var flag = document.getElementById('adminNotesFlag').value;
  var integrity = document.getElementById('adminNotesIntegrity').value;
  var site = document.getElementById('adminNotesSite').value;
  var text = document.getElementById('adminNotesField').value.trim();
  var errEl = document.getElementById('adminNotesErr');
  var rec = allUsers[uid] || {};
  var changed = false;
  if ((rec.adminFlag || '') !== flag) {
    rec.adminFlag = flag || null;
    auditRecord('SET FLAG', 'EC·'+uid+' → '+(flag||'none'));
    changed = true;
  }
  if ((rec.integrityStatus || '') !== integrity) {
    rec.integrityStatus = integrity || null;
    auditRecord('SET INTEGRITY STATUS', 'EC·'+uid+' → '+(integrity ? integrityLabel(integrity) : 'CLEAR'));
    changed = true;
  }
  if ((rec.site || '') !== site) {
    rec.site = site || null;
    auditRecord('SET HOME SITE', 'EC·'+uid+' → '+(site || 'Unassigned'));
    changed = true;
  }
  // Compartment grants
  var checks = document.querySelectorAll('#adminNotesCompartments .adminCompartmentCheck');
  if (checks.length) {
    var newGrants = [];
    checks.forEach(function(cb){ if (cb.checked) newGrants.push(cb.value); });
    var oldGrants = Array.isArray(rec.compartments) ? rec.compartments.slice().sort() : [];
    var cmpGrants = newGrants.slice().sort();
    if (oldGrants.join('|') !== cmpGrants.join('|')) {
      rec.compartments = newGrants;
      var names = newGrants.map(function(id){ return compartmentName(id) || id; });
      auditRecord('SET COMPARTMENTS', 'EC·'+uid+' → '+(names.length ? names.join(', ') : 'none'));
      changed = true;
    }
  }
  if (text) {
    if (!Array.isArray(rec.adminNotes)) rec.adminNotes = [];
    rec.adminNotes.push({ text: text, by: currentUser.id, at: Date.now() });
    auditRecord('ADMIN NOTE', 'EC·'+uid);
    changed = true;
  }
  if (!changed) { closeAdminNotes(); return; }
  try {
    await userSet(uid, rec);
    allUsers[uid] = rec;
    document.getElementById('adminNotesField').value = '';
    renderAdminNotesList(uid);
    renderAdminPanel();
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}
async function delAdminNote(uid, at) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var rec = allUsers[uid] || {};
  if (!Array.isArray(rec.adminNotes)) return;
  rec.adminNotes = rec.adminNotes.filter(function(n){ return String(n.at) !== String(at); });
  try {
    await userSet(uid, rec);
    allUsers[uid] = rec;
    renderAdminNotesList(uid);
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Bulk operations (CL5) ──
var adminDirSelected = new Set();   // displayIds currently selected
var adminDirVisible = [];           // displayIds currently shown (post-filter)

function toggleDirSelect(uid, checked) {
  // uid arrives from dataset (HTML-entity-decoded). Match against the real displayId.
  var realId = adminDirVisible.indexOf(uid) !== -1
    ? uid
    : (adminDirVisible.find(function(id){ return e(id) === uid; }) || uid);
  if (checked) adminDirSelected.add(realId); else adminDirSelected.delete(realId);
  updateBulkBar();
}
function toggleDirSelectAll(checked) {
  adminDirVisible.forEach(function(id){
    if (checked) adminDirSelected.add(id); else adminDirSelected.delete(id);
  });
  renderAdminPanel();
}
function clearDirSelection() {
  adminDirSelected.clear();
  var sa = document.getElementById('adminDirSelectAll'); if (sa) sa.checked = false;
  renderAdminPanel();
}
function updateBulkBar() {
  var bar = document.getElementById('adminBulkBar');
  var cnt = document.getElementById('adminBulkCount');
  if (!bar) return;
  var n = adminDirSelected.size;
  bar.style.display = n > 0 ? 'flex' : 'none';
  if (cnt) cnt.textContent = n + ' selected';
}
function selectedUserRecs() {
  return Array.from(adminDirSelected).map(function(id){ return allUsers[id]; }).filter(function(u){ return u && u.displayId; });
}
async function bulkApprove() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var recs = selectedUserRecs();
  var targets = recs.filter(function(u){ return u.status === 'pending' || u.status === 'denied'; });
  if (!targets.length) { alert('No selected accounts are pending or denied.'); return; }
  if (!await pfConfirm('APPROVE ' + targets.length + ' selected account(s) at CL3?\n\n(Only pending/denied accounts are affected. Adjust clearances afterward.)')) return;
  var ok = 0;
  for (var i=0;i<targets.length;i++) {
    var u = targets[i]; u.status = 'active'; u.clearance = u.clearance || '3';
    u.statusReason = null; u.lockedUntil = null; u.failedAttempts = 0;
    try { await userSet(u.displayId, u); allUsers[u.displayId] = u; ok++; } catch(_) {}
  }
  auditRecord('BULK APPROVED', ok + ' account(s)');
  clearDirSelection(); updateAdminBadge(); renderAdminPanel();
  alert('Approved ' + ok + ' account(s).');
}
async function bulkSetClearance() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var cl = (document.getElementById('bulkClSel')||{}).value || '3';
  var recs = selectedUserRecs().filter(function(u){ return (u.status||'active') === 'active'; });
  if (!recs.length) { alert('No active accounts selected.'); return; }
  if (!await pfConfirm('Set clearance to CL' + cl + ' for ' + recs.length + ' active account(s)?')) return;
  var ok = 0;
  for (var i=0;i<recs.length;i++) {
    var u = recs[i]; u.clearance = cl;
    try { await userSet(u.displayId, u); allUsers[u.displayId] = u; ok++; } catch(_) {}
  }
  auditRecord('BULK SET CLEARANCE', ok + ' account(s) → CL' + cl);
  clearDirSelection(); renderAdminPanel();
  alert('Set ' + ok + ' account(s) to CL' + cl + '.');
}
async function bulkRetire() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var recs = selectedUserRecs().filter(function(u){ return (u.status||'active') === 'active'; });
  if (!recs.length) { alert('No active accounts selected.'); return; }
  if (!await pfConfirm('RETIRE ' + recs.length + ' active account(s)?\n\nThey will be marked inactive (honourable) and unable to log in until restored.')) return;
  var ok = 0;
  for (var i=0;i<recs.length;i++) {
    var u = recs[i]; u.status = 'retired'; u.retiredBy = currentUser.id; u.retiredAt = Date.now();
    try { await userSet(u.displayId, u); allUsers[u.displayId] = u; ok++; } catch(_) {}
  }
  auditRecord('BULK RETIRED', ok + ' account(s)');
  clearDirSelection(); updateAdminBadge(); renderAdminPanel();
  alert('Retired ' + ok + ' account(s).');
}
async function bulkRevoke() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var recs = selectedUserRecs().filter(function(u){ return (u.status||'active') === 'active'; });
  if (!recs.length) { alert('No active accounts selected.'); return; }
  var reason = prompt('Reason for revoking ' + recs.length + ' account(s)? (required, applied to all)');
  if (reason === null) return;
  reason = reason.trim();
  if (!reason) { alert('A reason is required.'); return; }
  var ok = 0;
  for (var i=0;i<recs.length;i++) {
    var u = recs[i]; u.status = 'denied'; u.revokedBy = currentUser.id; u.revokedAt = Date.now(); u.statusReason = reason;
    try { await userSet(u.displayId, u); allUsers[u.displayId] = u; ok++; } catch(_) {}
  }
  auditRecord('BULK REVOKED', ok + ' account(s) — ' + reason);
  clearDirSelection(); updateAdminBadge(); renderAdminPanel();
  alert('Revoked ' + ok + ' account(s).');
}

// ── Recycle bin (soft-delete restore / purge, CL5) ──
function recycleBinCount() {
  return deletedPersonnel.length + deletedEthics.length + deletedOrders.length + deletedEthicsOrders.length
    + (typeof deletedTrainings!=='undefined'?deletedTrainings.length:0)
    + (typeof deletedEthicsCases!=='undefined'?deletedEthicsCases.length:0)
    + (typeof deletedTribunals!=='undefined'?deletedTribunals.length:0)
    + (typeof deletedInformants!=='undefined'?deletedInformants.length:0)
    + (typeof deletedIntelReports!=='undefined'?deletedIntelReports.length:0)
    + (typeof deletedOperations!=='undefined'?deletedOperations.length:0);
}
function renderRecycleBin() {
  var el = document.getElementById('adminRecycleList');
  if (!el) return;
  var groups = [
    { label:'Omega-1 Files',   arr:deletedPersonnel,     kind:'pf', name:function(r){ return r.name || r.id; } },
    { label:'Ethics Files',    arr:deletedEthics,        kind:'ef', name:function(r){ return r.name || r.id; } },
    { label:'Orders',          arr:deletedOrders,        kind:'order', name:function(r){ return r.title || r.id; } },
    { label:'Ethics Orders',   arr:deletedEthicsOrders,  kind:'eorder', name:function(r){ return r.title || r.id; } },
    { label:'Trainings',       arr:(typeof deletedTrainings!=='undefined'?deletedTrainings:[]),     kind:'training',  name:function(r){ return r.title || (r.date?('Session '+r.date):r.id); } },
    { label:'Ethics Cases',    arr:(typeof deletedEthicsCases!=='undefined'?deletedEthicsCases:[]), kind:'ecase',     name:function(r){ return (r.ref?r.ref+' — ':'') + (r.title || r.id); } },
    { label:'Tribunals',       arr:(typeof deletedTribunals!=='undefined'?deletedTribunals:[]),     kind:'tribunal',  name:function(r){ return (r.ref?r.ref+' — ':'') + ((r.defendant&&r.defendant.name) || r.id); } },
    { label:'Sources',         arr:(typeof deletedInformants!=='undefined'?deletedInformants:[]),   kind:'informant', name:function(r){ return r.codename || r.id; } },
    { label:'Intel Reports',   arr:(typeof deletedIntelReports!=='undefined'?deletedIntelReports:[]),kind:'intelrep', name:function(r){ return (r.ref?r.ref+' — ':'') + (r.category||r.id); } },
    { label:'Operations',      arr:(typeof deletedOperations!=='undefined'?deletedOperations:[]),    kind:'operation', name:function(r){ return (r.ref?r.ref+' — ':'') + (r.codename||r.id); } }
  ];
  var total = recycleBinCount();
  if (!total) { el.innerHTML = '<div style="font-size:.58rem;color:var(--text-faint);padding:.3rem 0;">Recycle bin is empty.</div>'; return; }
  var html = '';
  groups.forEach(function(g){
    if (!g.arr.length) return;
    html += '<div style="font-size:.55rem;color:var(--text-faint);letter-spacing:.1em;margin:.5rem 0 .25rem;">' + e(g.label.toUpperCase()) + ' (' + g.arr.length + ')</div>';
    g.arr.forEach(function(r){
      html += '<div style="border:1px solid var(--border);padding:.35rem .6rem;margin-bottom:2px;font-size:.58rem;display:flex;align-items:center;justify-content:space-between;gap:.5rem;">'
        + '<div style="flex:1;min-width:0;"><span style="color:var(--text);">' + e(g.name(r)) + '</span>'
        + '<span style="color:var(--text-faint);font-size:.52rem;margin-left:.4rem;">deleted' + (r.deletedBy?' by EC·'+e(r.deletedBy):'') + (r.deletedAt?' · '+safeDate(r.deletedAt):'') + '</span></div>'
        + '<div style="display:flex;gap:.3rem;flex-shrink:0;">'
        + '<button class="rec-btn" data-action="restore-rec" data-kind="' + g.kind + '" data-id="' + e(r.id) + '" style="font-size:.52rem;padding:1px 7px;">RESTORE</button>'
        + '<button class="rec-btn del-btn" data-action="purge-rec" data-kind="' + g.kind + '" data-id="' + e(r.id) + '" style="font-size:.52rem;padding:1px 7px;">PURGE</button>'
        + '</div></div>';
    });
  });
  el.innerHTML = html;
}
async function restoreRecord(kind, id) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var map = {
    pf:     { sink:deletedPersonnel,    live:allPersonnel,      set:personnelSet,      reRender:function(){ renderPersonnelFiles(); renderRoster(); } },
    ef:     { sink:deletedEthics,       live:allEthicsPersonnel,set:ethicsPersonnelSet,reRender:function(){ renderEthicsFiles(); renderEthicsRoster(); } },
    order:  { sink:deletedOrders,       live:allOrders,         set:orderSet,          reRender:function(){ renderOrders(); updateOrderBadge(); } },
    eorder: { sink:deletedEthicsOrders, live:allEthicsOrders,   set:ethicsOrderSet,    reRender:function(){ renderEthicsOrders(); updateEthicsOrderBadge(); } },
    training:{ sink:deletedTrainings,   live:allTrainings,      set:trainingSet,       reRender:function(){ if(typeof renderTrainings==='function') renderTrainings(); } },
    ecase:   { sink:deletedEthicsCases, live:allEthicsCases,    set:ethicsCaseSet,     reRender:function(){ if(typeof renderEthicsCases==='function') renderEthicsCases(); } },
    tribunal:{ sink:deletedTribunals,   live:allTribunals,      set:tribunalSet,       reRender:function(){ if(typeof renderTribunals==='function') renderTribunals(); } },
    informant:{sink:deletedInformants,  live:allInformants,     set:informantSet,      reRender:function(){ if(typeof renderInformants==='function') renderInformants(); } },
    intelrep: {sink:deletedIntelReports,live:allIntelReports,   set:intelReportSet,    reRender:function(){ if(typeof renderIntelReports==='function') renderIntelReports(); } },
    operation:{sink:deletedOperations,  live:allOperations,     set:operationSet,      reRender:function(){ if(typeof renderOperations==='function') renderOperations(); } }
  };
  var m = map[kind]; if (!m) return;
  var idx = m.sink.findIndex(function(r){ return r.id === id; });
  if (idx === -1) return;
  var rec = m.sink[idx];
  delete rec.deleted; delete rec.deletedBy; delete rec.deletedAt;
  try {
    await m.set(id, rec);
    m.sink.splice(idx, 1);
    if (!m.live.some(function(r){ return r.id===id; })) m.live.push(rec);
    auditRecord('RESTORED RECORD', (rec.name||rec.title||id) + ' [' + kind + ']');
    m.reRender();
    renderRecycleBin();
    var hdr = document.getElementById('recycleBinHdr'); if (hdr) updateRecycleHdr();
  } catch(err) { alert('RESTORE ERROR: ' + err.message); }
}
async function purgeRecord(kind, id) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!await pfConfirm('PERMANENTLY purge this record?\n\nThis cannot be undone — it is removed from the database entirely.')) return;
  var map = {
    pf:     { sink:deletedPersonnel,    del:personnelDel },
    ef:     { sink:deletedEthics,       del:ethicsPersonnelDel },
    order:  { sink:deletedOrders,       del:orderDel },
    eorder: { sink:deletedEthicsOrders, del:ethicsOrderDel },
    training:{ sink:deletedTrainings,   del:trainingDel },
    ecase:   { sink:deletedEthicsCases, del:ethicsCaseDel },
    tribunal:{ sink:deletedTribunals,   del:tribunalDel },
    informant:{sink:deletedInformants,  del:informantDel },
    intelrep: {sink:deletedIntelReports,del:intelReportDel },
    operation:{sink:deletedOperations,  del:operationDel }
  };
  var m = map[kind]; if (!m) return;
  var idx = m.sink.findIndex(function(r){ return r.id === id; });
  if (idx === -1) return;
  var rec = m.sink[idx];
  try {
    await m.del(id);
    m.sink.splice(idx, 1);
    auditRecord('PURGED RECORD', (rec.name||rec.title||id) + ' [' + kind + ']');
    renderRecycleBin();
    updateRecycleHdr();
  } catch(err) { alert('PURGE ERROR: ' + err.message); }
}
function updateRecycleHdr() {
  var hdr = document.getElementById('recycleBinHdr');
  if (hdr) hdr.textContent = '▸ RECYCLE BIN (' + recycleBinCount() + ')';
}

// ── Activity requirements config (CL5) ──
function renderActivityReqs() {
  if (typeof renderTribunalCfgAdmin === 'function') renderTribunalCfgAdmin();
  var el = document.getElementById('adminActivityReqs');
  if (!el) return;
  if (!allActivityReqs) { el.innerHTML = '<div style="color:var(--text-faint);">Loading…</div>'; return; }
  var o = allActivityReqs.omega || {};
  var ea = allActivityReqs.ethicsAssistant || {};
  var isCL5 = currentUser && parseInt(currentUser.clearance) >= 5;
  var dis = isCL5 ? '' : 'disabled';
  el.innerHTML =
    '<div style="border:1px solid var(--border2);padding:.55rem .7rem;margin-bottom:.4rem;">'
    + '<div style="color:var(--green);font-family:\'VT323\',monospace;letter-spacing:.06em;margin-bottom:.4rem;">OMEGA-1</div>'
    + '<div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center;">'
    +   '<label style="display:flex;align-items:center;gap:.4rem;">Weekly hours <input type="number" min="0" step="0.5" id="actOmegaWeekly" value="' + e(o.weeklyHours != null ? o.weeklyHours : 5) + '" ' + dis + ' style="width:60px;background:var(--bg);border:1px solid var(--border2);color:var(--amber);padding:.2rem .4rem;font-family:inherit;"/></label>'
    +   '<label style="display:flex;align-items:center;gap:.4rem;">Monthly hours <input type="number" min="0" step="1" id="actOmegaMonthly" value="' + e(o.monthlyHours != null ? o.monthlyHours : 25) + '" ' + dis + ' style="width:60px;background:var(--bg);border:1px solid var(--border2);color:var(--amber);padding:.2rem .4rem;font-family:inherit;"/></label>'
    + '</div></div>'
    + '<div style="border:1px solid var(--border2);padding:.55rem .7rem;margin-bottom:.4rem;">'
    + '<div style="color:var(--green);font-family:\'VT323\',monospace;letter-spacing:.06em;margin-bottom:.4rem;">ETHICS COMMITTEE — ASSISTANTS</div>'
    + '<div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center;">'
    +   '<label style="display:flex;align-items:center;gap:.4rem;">Weekly hours <input type="number" min="0" step="0.5" id="actEfWeekly" value="' + e(ea.weeklyHours != null ? ea.weeklyHours : 1) + '" ' + dis + ' style="width:60px;background:var(--bg);border:1px solid var(--border2);color:var(--amber);padding:.2rem .4rem;font-family:inherit;"/></label>'
    +   '<label style="display:flex;align-items:center;gap:.4rem;cursor:pointer;"><input type="checkbox" id="actEfInteraction" ' + (ea.requireInteraction ? 'checked' : '') + ' ' + dis + '/> Require an order interaction / RP note</label>'
    + '</div>'
    + '<div style="font-size:.52rem;color:var(--text-faint);margin-top:.35rem;line-height:1.5;">Other EC roles (Chairman / Member) are exempt from activity requirements.</div>'
    + '</div>'
    + (isCL5 ? '<button class="modal-save" data-action="save-activity-reqs" style="font-size:.6rem;">[ SAVE REQUIREMENTS ]</button>' : '<div style="font-size:.52rem;color:var(--text-faint);">CL5 required to edit.</div>');
}
async function saveActivityReqs() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!allActivityReqs) return;
  function num(id, def){ var v = parseFloat((document.getElementById(id)||{}).value); return isNaN(v) || v < 0 ? def : v; }
  allActivityReqs.omega = {
    weeklyHours:  num('actOmegaWeekly', 5),
    monthlyHours: num('actOmegaMonthly', 25)
  };
  allActivityReqs.ethicsAssistant = {
    weeklyHours:        num('actEfWeekly', 1),
    requireInteraction: !!(document.getElementById('actEfInteraction') && document.getElementById('actEfInteraction').checked)
  };
  try {
    await activityReqsSave();
    auditRecord('EDITED ACTIVITY REQS', 'Ω-1 ' + allActivityReqs.omega.weeklyHours + 'h/wk · ' + allActivityReqs.omega.monthlyHours + 'h/mo · EC-Asst ' + allActivityReqs.ethicsAssistant.weeklyHours + 'h/wk');
    renderActivityReqs();
    if (typeof renderPersonnelFiles === 'function') renderPersonnelFiles();
    if (typeof renderRoster === 'function') renderRoster();
    alert('Activity requirements saved.');
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Omega-1 promotion requirements management (CL5) ──
function renderPromoReqList() {
  var el = document.getElementById('adminPromoList');
  if (!el) return;
  if (!allPromoReqs) { el.innerHTML = '<div style="font-size:.58rem;color:var(--text-faint);">Loading…</div>'; return; }
  // Show every transition in ladder order
  var rows = [];
  for (var i = 0; i < PROMO_ORDER.length - 1; i++) {
    var from = PROMO_ORDER[i], to = PROMO_ORDER[i+1];
    var key = promoKey(from, to);
    var items = allPromoReqs[key] || [];
    rows.push('<div style="border:1px solid var(--border);padding:.4rem .65rem;margin-bottom:2px;font-size:.6rem;display:flex;align-items:flex-start;justify-content:space-between;gap:.5rem;">'
      + '<div style="flex:1;min-width:0;">'
      + '<span style="color:var(--green);font-family:\'VT323\',monospace;">' + e(from) + ' → ' + e(to) + '</span>'
      + '<span style="color:var(--text-faint);margin-left:.4rem;font-size:.54rem;">' + (items.length ? items.length + ' requirement' + (items.length===1?'':'s') : 'no specific requirements') + '</span>'
      + (items.length ? '<div style="color:var(--text-dim);font-size:.54rem;margin-top:.25rem;line-height:1.5;">' + items.map(function(it){ return '• ' + e(it.text); }).join('<br>') + '</div>' : '')
      + '</div>'
      + '<button class="rec-btn" data-action="edit-promoreq" data-key="' + e(key) + '" style="font-size:.53rem;padding:1px 7px;flex-shrink:0;">EDIT</button>'
      + '</div>');
  }
  el.innerHTML = rows.join('');
  // Prepend the configurable case-by-case threshold control.
  var meta = getPromoMeta();
  var isCL5 = currentUser && parseInt(currentUser.clearance) >= 5;
  var dis = isCL5 ? '' : 'disabled';
  var rankOpts = RANKS.map(function(rk){ return '<option value="' + e(rk) + '"' + (rk === meta.caseByCaseFrom ? ' selected' : '') + '>' + e(rk) + '</option>'; }).join('');
  var cfg = '<div style="border:1px solid var(--border2);padding:.55rem .7rem;margin-bottom:.55rem;">'
    + '<div style="color:var(--green);font-family:\'VT323\',monospace;letter-spacing:.06em;margin-bottom:.35rem;">CASE-BY-CASE THRESHOLD</div>'
    + '<div style="font-size:.52rem;color:var(--text-faint);margin-bottom:.45rem;line-height:1.5;">Files at or above this rank are command-discretion: they show the note below instead of a requirements checklist.</div>'
    + '<label style="display:flex;align-items:center;gap:.4rem;font-size:.6rem;margin-bottom:.4rem;">Case-by-case from rank '
    +   '<select id="promoCaseByCaseFrom" ' + dis + ' style="background:var(--bg);border:1px solid var(--border2);color:var(--amber);padding:.2rem .4rem;font-family:inherit;font-size:.6rem;">' + rankOpts + '</select></label>'
    + '<label style="display:block;font-size:.6rem;margin-bottom:.25rem;">Note shown for those ranks</label>'
    + '<textarea id="promoCaseByCaseNote" ' + dis + ' rows="2" style="width:100%;background:var(--bg);border:1px solid var(--border2);color:var(--text);padding:.3rem .45rem;font-family:inherit;font-size:.58rem;box-sizing:border-box;margin-bottom:.45rem;line-height:1.5;">' + e(meta.caseByCaseNote) + '</textarea>'
    + (isCL5 ? '<button class="modal-save" data-action="save-promo-meta" style="font-size:.6rem;">[ SAVE THRESHOLD ]</button>' : '<div style="font-size:.52rem;color:var(--text-faint);">CL5 required to edit.</div>')
    + '</div>';
  el.innerHTML = cfg + el.innerHTML;
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!allPromoReqs) return;
  var parts = key.split('>');
  document.getElementById('promoReqKey').value = key;
  document.getElementById('promoReqTitle').textContent = 'REQUIREMENTS · ' + parts[0] + ' → ' + parts[1];
  document.getElementById('promoReqTransLabel').textContent = 'REQUIREMENTS FOR ' + parts[1].toUpperCase();
  var items = allPromoReqs[key] || [];
  document.getElementById('promoReqText').value = items.map(function(it){ return it.text; }).join('\n');
  document.getElementById('promoReqErr').textContent = '';
  document.getElementById('promoReqModal').classList.add('open');
}
function closePromoReqModal() { document.getElementById('promoReqModal').classList.remove('open'); }
async function savePromoReq() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var key = document.getElementById('promoReqKey').value;
  if (!allPromoReqs || !key) return;
  var lines = document.getElementById('promoReqText').value.split('\n')
    .map(function(s){ return s.trim(); }).filter(Boolean);
  // Preserve existing item ids by position where possible (keeps progress aligned),
  // assigning fresh ids for new lines.
  var existing = allPromoReqs[key] || [];
  var items = lines.map(function(text, idx){
    var id = existing[idx] ? existing[idx].id : ('r' + (idx+1) + '_' + Date.now().toString(36).slice(-3));
    return { id: id, text: text };
  });
  allPromoReqs[key] = items;
  try {
    await promoReqsSave();
    auditRecord('EDITED PROMOTION REQS', key + ' (' + items.length + ' item' + (items.length===1?'':'s') + ')');
    closePromoReqModal();
    renderPromoReqList();
    if (typeof renderPersonnelFiles === 'function') renderPersonnelFiles();
  } catch(err) { document.getElementById('promoReqErr').textContent = '> ERROR: ' + err.message; }
}
// Save the configurable case-by-case threshold (CL5 only).
async function savePromoMeta() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!allPromoReqs) return;
  var fromSel = document.getElementById('promoCaseByCaseFrom');
  var noteEl  = document.getElementById('promoCaseByCaseNote');
  if (!fromSel) return;
  allPromoReqs.__meta = {
    caseByCaseFrom: fromSel.value || 'Lieutenant',
    caseByCaseNote: (noteEl && noteEl.value.trim()) || 'This operative is at the top of the standard progression. Further advancement is assessed on a case-by-case basis by command.'
  };
  try {
    await promoReqsSave();
    auditRecord('EDITED PROMOTION THRESHOLD', 'Case-by-case from ' + allPromoReqs.__meta.caseByCaseFrom);
    renderPromoReqList();
    if (typeof renderPersonnelFiles === 'function') renderPersonnelFiles();
    alert('Promotion threshold saved.');
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Access compartment management (CL5) ──
function renderCompartmentList() {
  var el = document.getElementById('adminCompartmentList');
  if (!el) return;
  if (!allCompartments.length) {
    el.innerHTML = '<div style="font-size:.58rem;color:var(--text-faint);">[ NO COMPARTMENTS DEFINED ]</div>';
    return;
  }
  el.innerHTML = allCompartments.map(function(c) {
    // Count how many members hold this grant
    var holders = Object.values(allUsers).filter(function(u){ return Array.isArray(u.compartments) && u.compartments.indexOf(c.id) !== -1; }).length;
    return '<div style="border:1px solid var(--border);padding:.4rem .65rem;margin-bottom:2px;font-size:.62rem;display:flex;align-items:center;justify-content:space-between;gap:.4rem;flex-wrap:wrap;">'
      + '<div><span style="color:var(--green);font-family:\'VT323\',monospace;">' + e(c.name) + '</span>'
      + (c.code ? ' <span class="badge b-cyan" style="font-size:.5rem;">' + e(c.code) + '</span>' : '')
      + '<span style="color:var(--text-faint);margin-left:.4rem;font-size:.54rem;">' + holders + ' member' + (holders===1?'':'s') + '</span>'
      + (c.description ? '<div style="color:var(--text-dim);font-size:.54rem;margin-top:.15rem;">' + e(c.description) + '</div>' : '')
      + '</div>'
      + '<button class="rec-btn" data-action="edit-compartment" data-id="' + e(c.id) + '" style="font-size:.53rem;padding:1px 7px;">EDIT</button>'
      + '</div>';
  }).join('');
}
function openCompartmentModal(id) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var c = id ? allCompartments.find(function(x){ return x.id === id; }) : null;
  document.getElementById('compartmentModalTitle').textContent = c ? 'EDIT COMPARTMENT' : 'NEW ACCESS COMPARTMENT';
  document.getElementById('compartmentId').value = c ? c.id : '';
  document.getElementById('compartmentName').value = c ? (c.name||'') : '';
  document.getElementById('compartmentCode').value = c ? (c.code||'') : '';
  document.getElementById('compartmentDesc').value = c ? (c.description||'') : '';
  document.getElementById('compartmentErr').textContent = '';
  document.getElementById('compartmentDelBtn').style.display = c ? 'inline-block' : 'none';
  document.getElementById('compartmentModal').classList.add('open');
}
function closeCompartmentModal() { document.getElementById('compartmentModal').classList.remove('open'); }
async function saveCompartment() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var id   = document.getElementById('compartmentId').value;
  var name = document.getElementById('compartmentName').value.trim();
  var code = document.getElementById('compartmentCode').value.trim();
  var desc = document.getElementById('compartmentDesc').value.trim();
  var errEl = document.getElementById('compartmentErr');
  if (!name) { errEl.textContent = '> PROGRAM NAME REQUIRED'; return; }
  var isNew = !id;
  if (isNew) id = 'comp_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);
  var rec = { id: id, name: name, code: code || null, description: desc || null,
              createdBy: (allCompartments.find(function(x){return x.id===id;})||{}).createdBy || currentUser.id,
              createdAt: (allCompartments.find(function(x){return x.id===id;})||{}).createdAt || Date.now() };
  try {
    await compartmentSet(id, rec);
    auditRecord(isNew ? 'CREATED COMPARTMENT' : 'EDITED COMPARTMENT', name);
    await loadCompartments();
    closeCompartmentModal();
    renderCompartmentList();
    // Keep the order-form compartment selectors current
    populateCompartmentSelect('oCompartment');
    populateCompartmentSelect('ethicsOrderCompartment');
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}
async function deleteCompartment() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var id = document.getElementById('compartmentId').value;
  var c = allCompartments.find(function(x){ return x.id === id; });
  if (!c) return;
  var holders = Object.values(allUsers).filter(function(u){ return Array.isArray(u.compartments) && u.compartments.indexOf(id) !== -1; }).length;
  if (!await pfConfirm('Delete compartment "' + c.name + '"?\n\n' + holders + ' member(s) currently hold this grant — it will be removed from them, and any content tagged with it becomes open at its clearance level.')) return;
  try {
    // Remove the grant from any holders
    var holderRecs = Object.values(allUsers).filter(function(u){ return Array.isArray(u.compartments) && u.compartments.indexOf(id) !== -1; });
    for (var i=0;i<holderRecs.length;i++) {
      var u = holderRecs[i];
      u.compartments = u.compartments.filter(function(x){ return x !== id; });
      try { await userPatch(u.displayId, { compartments: u.compartments }); } catch(_) {}
    }
    await compartmentDel(id);
    auditRecord('DELETED COMPARTMENT', c.name);
    await loadCompartments();
    closeCompartmentModal();
    renderAdminPanel();
    populateCompartmentSelect('oCompartment');
    populateCompartmentSelect('ethicsOrderCompartment');
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Acknowledge a duress alert (CL5) — Security has responded ──
async function adminAckDuress(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!await pfConfirm('Acknowledge and clear the DURESS alert for EC·' + uid + '?\n\nOnly do this once Security has verified the member is safe.')) return;
  var rec = allUsers[uid] || {};
  rec.duressActive = false;
  rec.duressAckBy = currentUser.id; rec.duressAckAt = Date.now();
  try {
    await userPatch(uid, { duressActive: false, duressAckBy: currentUser.id, duressAckAt: Date.now() });
    auditRecord('ACK DURESS', 'EC·'+uid+' duress alert cleared');
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Clear an account lockout (CL5) ──
async function adminUnlock(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var rec = allUsers[uid] || {};
  rec.lockedUntil = null;
  rec.failedAttempts = 0;
  rec.lockoutCount = 0;
  try {
    await userSet(uid, rec);
    auditRecord('UNLOCKED ACCOUNT', 'EC·'+uid);
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Passphrase reset (CL5) ──
function adminResetPass(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  document.getElementById('passResetUid').value = uid;
  document.getElementById('passResetField').value = '';
  document.getElementById('passResetErr').textContent = '';
  document.getElementById('passResetTitle').textContent = 'RESET PASSPHRASE — EC·' + uid;
  document.getElementById('passResetModal').classList.add('open');
}
function closePassReset() { document.getElementById('passResetModal').classList.remove('open'); }
async function savePassReset() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var uid     = document.getElementById('passResetUid').value;
  var newPass = document.getElementById('passResetField').value.trim();
  var errEl   = document.getElementById('passResetErr');
  if (!newPass || newPass.length < 3) { errEl.textContent = '> PASSPHRASE MUST BE AT LEAST 3 CHARACTERS'; return; }
  var rec = allUsers[uid] || {};
  var cred = await makeCredential(newPass);
  applyCredential(rec, cred);
  rec.passResetBy = currentUser.id; rec.passResetAt = Date.now();
  try {
    await userSet(uid, rec);
    auditRecord('RESET PASSPHRASE', 'EC·'+uid);
    allUsers[uid] = rec;
    closePassReset();
    alert('Passphrase reset for EC·' + uid + '.\n\nNew passphrase: ' + newPass + '\n\nShare this with the member securely. They can change it later.');
  } catch(err) { errEl.textContent = '> ERROR: ' + err.message; }
}

// ── Bulk approve all pending at CL3 (CL5) ──
async function adminBulkApprove() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var pending = Object.values(allUsers).filter(function(u){ return u.status === 'pending'; });
  if (!pending.length) { alert('No pending registrations.'); return; }
  if (!await pfConfirm('APPROVE ALL ' + pending.length + ' pending registration(s) at CL3?\n\nYou can adjust individual clearances afterwards.')) return;
  var ok = 0;
  for (var i = 0; i < pending.length; i++) {
    var u = pending[i];
    var uid = u.displayId;
    u.status = 'active'; u.clearance = '3';
    try { await userSet(uid, u); allUsers[uid] = u; ok++; } catch(_) {}
  }
  auditRecord('BULK APPROVED', ok + ' account(s) at CL3');
  updateAdminBadge();
  renderAdminPanel();
  alert('Approved ' + ok + ' of ' + pending.length + ' pending account(s) at CL3.');
}

// ── Retire / un-retire an account (CL5) ──
// 'retired' = honourable inactive status, distinct from 'denied' (revoked for cause)
async function adminRetire(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  if (!await pfConfirm('Mark EC·' + uid + ' as RETIRED?\n\nThis is an honourable inactive status. They cannot log in but are not revoked for cause. Reversible.')) return;
  var rec = allUsers[uid] || {};
  rec.status = 'retired'; rec.retiredBy = currentUser.id; rec.retiredAt = Date.now();
  try {
    await userSet(uid, rec);
    auditRecord('RETIRED ACCOUNT', 'EC·'+uid);
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

async function adminSetUnit(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var sel = document.getElementById('setUnit_' + uid);
  if (!sel) return;
  var unit = sel.value; // '' | 'omega1' | 'ethics'
  var label = unit === 'omega1' ? 'OMEGA-1' : unit === 'ethics' ? 'ETHICS COMMITTEE' : 'No Unit';
  if (!await pfConfirm('Set EC·' + uid + ' unit to: ' + label + '?')) return;
  var rec = allUsers[uid] || {};
  rec.unit = unit || null;
  rec.unitSetBy = currentUser.id; rec.unitSetAt = Date.now();
  try {
    await userSet(uid, rec);
    auditRecord('SET UNIT', 'EC·'+uid+' → '+(unit||'none'));
    allUsers[uid] = rec;
    renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

function adminRevoke(uid) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  openReasonModal('revoke', uid, 'REVOKE ACCESS', 'EC·' + uid + ' will be unable to log in until restored.', 'REASON FOR REVOCATION');
}

function canEditPersonnel() { return currentUser && parseInt(currentUser.clearance) >= 4; }
function formatDob(s) {
  if (!s) return '—';
  var d = new Date(s + 'T00:00:00');
  return isNaN(d) ? s : d.toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
}

// Safe ISO formatters — never throw on missing/invalid timestamps.
function safeDate(v) { // → 'YYYY-MM-DD' or '—'
  if (v === undefined || v === null || v === '') return '—';
  var d = new Date(v);
  return isNaN(d.getTime()) ? '—' : d.toISOString().slice(0,10);
}
function safeDateTime(v) { // → 'YYYY-MM-DD HH:MM' or '—'
  if (v === undefined || v === null || v === '') return '—';
  var d = new Date(v);
  return isNaN(d.getTime()) ? '—' : d.toISOString().slice(0,16).replace('T',' ');
}

function deriveClearance(userRec) {
  if (!userRec) return '3';
  var stored = parseInt(userRec.clearance || '3');
  if (isNaN(stored) || stored < 3 || stored > 5) stored = 3; // sanitize malformed values

  // If no linked personnel file, fall back to the stored clearance.
  // This is critical for the bootstrap admin (first account) who has no file yet
  // but was granted CL5 at registration. Without this they'd be stuck at CL3.
  if (!userRec.linkedPfId && !userRec.linkedEfId) {
    return String(stored);
  }

  // default: if the linked file isn't found in memory yet (arrays not loaded at login time),
  // use the stored/approved clearance as a safe fallback rather than dropping to CL3.
  // This is corrected to the file-derived value once personnel data loads in the background.
  var fileCl = stored;

  // Ethics Committee roles
  if (userRec.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === userRec.linkedEfId; });
    if (ef) {
      if (ef.role === 'Chairman' || ef.role === 'Member') fileCl = 5;
      else if (ef.role === 'Assistant') fileCl = 4;
      else fileCl = 3;
    } else if (allEthicsPersonnel.length > 0) {
      // Arrays are loaded but the linked file is gone (deleted) → revoke to baseline.
      // (If the array is empty, data simply hasn't loaded yet, so we keep `stored`.)
      fileCl = 3;
    }
  }
  // Omega-1 ranks
  else if (userRec.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === userRec.linkedPfId; });
    if (pf) {
      var rank = pf.rank;
      if (['Commander','Lieutenant Commander','Major','Captain','Lieutenant'].includes(rank)) fileCl = 4;
      else fileCl = 3;
    } else if (allPersonnel.length > 0) {
      // Loaded but file deleted → revoke to baseline.
      fileCl = 3;
    }
  }

  // Cap at the stored approved clearance — prevents a user choosing a rank/role
  // higher than what was actually granted to them.
  return String(Math.min(fileCl, stored));
}

var allPersonnel   = [];    // array of personnel record objects
var pfExpanded     = new Set(); // which cards are open
var pfCollapsed    = new Set(); // "pfId:sectionKey" — which sections are folded

// Firebase / LS helpers for personnel
async function personnelGetAll() {
  if (firebaseReady) {
    var all = await fbGetAll('/personnel');
    return all ? Object.values(all) : [];
  }
  return Object.values(lsAll('personnel/'));
}
async function personnelSet(id, data) {
  if (firebaseReady) await fbSet('/personnel/' + id, data);
  else lsSet('personnel/' + id, data);
}
async function personnelDel(id) {
  if (firebaseReady) await fbDelete('/personnel/' + id);
  else lsDel('personnel/' + id);
}

// ================================================================
//  OMEGA-1 TRAININGS
//  A linked Omega-1 member logs a training session: date, notes,
//  and tagged attendees. Records link back to personnel files.
//  Firebase path: /trainings/{id}
// ================================================================
var allTrainings     = [];   // live training records
var deletedTrainings = [];    // soft-deleted (recycle bin)
var _trnAttendees    = [];    // working set of {pfId,name} while the modal is open

async function trainingsGetAll() {
  if (firebaseReady) { var all = await fbGetAll('/trainings'); return all ? Object.values(all) : []; }
  return Object.values(lsAll('trainings/'));
}
async function trainingSet(id, data) {
  if (firebaseReady) await fbSet('/trainings/' + id, data); else lsSet('trainings/' + id, data);
}
async function trainingDel(id) { if (firebaseReady) await fbDelete('/trainings/' + id); else lsDel('trainings/' + id); }

// A member linked to an Omega-1 file may log trainings; CL5 command may always log.
function canLogTraining() {
  if (!currentUser) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  return !!currentUser.linkedPfId;
}
// The conductor (or CL5 command) may edit/delete a record.
function canManageTraining(t) {
  if (!currentUser || !t) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  if (currentUser.linkedPfId && t.conductedByPfId === currentUser.linkedPfId) return true;
  return currentUser.id === t.conductedByUserId;
}
// Resolve a personnel name from an id (falls back to a snapshot/placeholder).
function trnPfName(pfId, fallback) {
  var p = allPersonnel.find(function(x){ return x.id === pfId; });
  return p ? (p.name || p.nickname || pfId) : (fallback || '[removed file]');
}

async function loadTrainings() {
  try {
    var raw = await trainingsGetAll();
    allTrainings = partitionDeleted(raw.filter(function(t){ return t && t.id; }), function(d){ deletedTrainings = d; });
  } catch(e) { allTrainings = []; }
  // newest first
  allTrainings.sort(function(a,b){ return (b.date||'').localeCompare(a.date||'') || (b.createdAt||0)-(a.createdAt||0); });
  var newBtn = document.getElementById('trnNewBtn');
  if (newBtn) newBtn.style.display = canLogTraining() ? 'inline-block' : 'none';
  var notice = document.getElementById('trnAccessNotice');
  if (notice) {
    if (!canLogTraining()) {
      notice.style.display = 'block';
      notice.textContent = currentUser
        ? 'Link your account to an Omega-1 personnel file (via your account menu) to log trainings. You may still view the log below.'
        : 'Observer mode — training log is read-only.';
    } else notice.style.display = 'none';
  }
  renderTrainings();
}

function renderTrainings() {
  var list = document.getElementById('trnList');
  if (!list) return;
  var q = (document.getElementById('trnSearch') || {}).value || '';
  q = q.trim().toLowerCase();
  var scope = (document.getElementById('trnFilterScope') || {}).value || 'all';
  var mine = currentUser && currentUser.linkedPfId;

  var rows = allTrainings.filter(function(t){
    if (scope === 'mine' && t.conductedByPfId !== mine) return false;
    if (scope === 'involving-me') {
      var involved = t.conductedByPfId === mine ||
        (Array.isArray(t.attendees) && t.attendees.some(function(a){ return a && a.pfId === mine; }));
      if (!involved) return false;
    }
    if (!q) return true;
    var hay = [t.title, t.notes, trnPfName(t.conductedByPfId, t.conductedByName)]
      .concat((t.attendees||[]).map(function(a){ return trnPfName(a.pfId, a.name); }))
      .join(' ').toLowerCase();
    return hay.indexOf(q) !== -1;
  });

  var cnt = document.getElementById('trnCount');
  if (cnt) cnt.textContent = rows.length ? '(' + rows.length + ')' : '';

  if (!rows.length) {
    list.innerHTML = '<div class="trn-empty">NO TRAINING RECORDS' + (q || scope!=='all' ? ' MATCH THE CURRENT FILTER.' : ' LOGGED YET.') + '</div>';
    return;
  }
  list.innerHTML = rows.map(buildTrainingCard).join('');
}

function buildTrainingCard(t) {
  var dateStr = formatDob(t.date);
  var conductorName = e(trnPfName(t.conductedByPfId, t.conductedByName));
  var conductor = (t.conductedByPfId && allPersonnel.some(function(p){ return p.id === t.conductedByPfId; }))
    ? '<span class="person-link" data-action="open-pf-from-training" data-pfid="' + e(t.conductedByPfId) + '">' + conductorName + '</span>'
    : conductorName;
  var attendees = (t.attendees || []);
  var attHtml = attendees.length
    ? attendees.map(function(a){
        return '<span class="trn-attendee"><span class="person-link" data-action="open-pf-from-training" data-pfid="'
          + e(a.pfId) + '">' + e(trnPfName(a.pfId, a.name)) + '</span></span>';
      }).join('')
    : '<span style="color:var(--text-faint);">none tagged</span>';
  var manage = canManageTraining(t)
    ? '<div style="display:flex;gap:.35rem;">'
      + '<button class="pf-section-btn" data-action="edit-training" data-id="' + e(t.id) + '" style="font-size:.52rem;padding:1px 7px;">EDIT</button>'
      + '<button class="pf-section-btn" data-action="delete-training" data-id="' + e(t.id) + '" style="font-size:.52rem;padding:1px 7px;color:#dd6666;">DELETE</button>'
      + '</div>'
    : '';
  return '<div class="trn-card">'
    + '<div class="trn-card-top">'
    + '<div><div class="trn-date">' + e(dateStr) + '</div>'
    + (t.title ? '<div class="trn-title">' + e(t.title) + '</div>' : '')
    + '</div>' + manage + '</div>'
    + '<div class="trn-meta">CONDUCTED BY · ' + conductor + '<br>PERSONNEL INVOLVED · ' + attHtml + '</div>'
    + (t.notes ? '<div class="trn-notes">' + e(t.notes) + '</div>' : '')
    + '</div>';
}

// ── Modal ──
function openTrainingModal(id) {
  if (!id && !canLogTraining()) { alert('LINK REQUIRED\n\nYou must be linked to an Omega-1 personnel file to log a training.'); return; }
  var editing = !!id;
  var rec = editing ? allTrainings.find(function(t){ return t.id === id; }) : null;
  if (editing && !canManageTraining(rec)) { alert('You do not have authority to edit this training record.'); return; }

  document.getElementById('trainingModalTitle').textContent = editing ? 'EDIT TRAINING' : 'LOG TRAINING';
  document.getElementById('trnEditId').value = id || '';
  document.getElementById('trnErr').style.display = 'none';

  var today = new Date().toISOString().slice(0,10);
  document.getElementById('trnDate').value  = rec ? (rec.date || today) : today;
  document.getElementById('trnTitle').value = rec ? (rec.title || '') : '';
  document.getElementById('trnNotes').value = rec ? (rec.notes || '') : '';
  _trnAttendees = rec && Array.isArray(rec.attendees)
    ? rec.attendees.map(function(a){ return { pfId: a.pfId, name: a.name }; })
    : [];

  renderTrnAttendeeList();
  populateTrainingPicker();
  document.getElementById('trainingModal').classList.add('open');
}
function closeTrainingModal() {
  document.getElementById('trainingModal').classList.remove('open');
  _trnAttendees = [];
}
function populateTrainingPicker() {
  var sel = document.getElementById('trnAttendeePicker');
  if (!sel) return;
  var selfId = currentUser && currentUser.linkedPfId;
  var taken = {};
  _trnAttendees.forEach(function(a){ taken[a.pfId] = true; });
  if (selfId) taken[selfId] = true; // the conductor is implicit, not an attendee
  var opts = ['<option value="">+ ADD PERSONNEL...</option>'];
  allPersonnel.slice()
    .filter(function(p){ return p.id && !taken[p.id]; })
    .sort(function(a,b){ return (a.name||'').localeCompare(b.name||''); })
    .forEach(function(p){
      opts.push('<option value="' + e(p.id) + '">' + e(p.name || p.nickname || p.id) + (p.rank ? ' · ' + e(p.rank) : '') + '</option>');
    });
  sel.innerHTML = opts.join('');
}
function addTrainingAttendee(pfId) {
  if (!pfId) return;
  if (_trnAttendees.some(function(a){ return a.pfId === pfId; })) return;
  var p = allPersonnel.find(function(x){ return x.id === pfId; });
  _trnAttendees.push({ pfId: pfId, name: p ? (p.name || p.nickname || pfId) : pfId });
  renderTrnAttendeeList();
  populateTrainingPicker();
}
function removeTrainingAttendee(pfId) {
  _trnAttendees = _trnAttendees.filter(function(a){ return a.pfId !== pfId; });
  renderTrnAttendeeList();
  populateTrainingPicker();
}
function renderTrnAttendeeList() {
  var box = document.getElementById('trnAttendeeList');
  if (!box) return;
  if (!_trnAttendees.length) { box.innerHTML = '<span style="font-size:.58rem;color:var(--text-faint);">No personnel tagged yet.</span>'; return; }
  box.innerHTML = _trnAttendees.map(function(a){
    return '<span class="trn-attendee">' + e(a.name)
      + '<span class="x" data-action="remove-trn-attendee" data-pfid="' + e(a.pfId) + '">×</span></span>';
  }).join('');
}
async function saveTraining() {
  var notes = document.getElementById('trnNotes').value.trim();
  var date  = document.getElementById('trnDate').value;
  var errEl = document.getElementById('trnErr');
  function fail(msg){ errEl.textContent = msg; errEl.style.display = 'block'; }
  if (!date)  { fail('A training date is required.'); return; }
  if (!notes) { fail('Notes are required — describe what was conducted.'); return; }

  var editId = document.getElementById('trnEditId').value;
  var existing = editId ? allTrainings.find(function(t){ return t.id === editId; }) : null;
  if (editId && !canManageTraining(existing)) { fail('You do not have authority to edit this record.'); return; }
  if (!editId && !canLogTraining()) { fail('You must be linked to an Omega-1 file to log a training.'); return; }

  var btn = document.getElementById('trnSaveBtn');
  if (btn) { btn.disabled = true; btn.textContent = '[ SAVING... ]'; }

  var rec;
  if (existing) {
    rec = existing;
    rec.date = date; rec.title = document.getElementById('trnTitle').value.trim();
    rec.notes = notes; rec.attendees = _trnAttendees.slice();
    rec.updatedBy = currentUser.id; rec.updatedAt = Date.now();
  } else {
    rec = {
      id: 'trn_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
      date: date,
      title: document.getElementById('trnTitle').value.trim(),
      notes: notes,
      attendees: _trnAttendees.slice(),
      conductedByPfId: currentUser.linkedPfId || null,
      conductedByName: currentUser.linkedPfId ? trnPfName(currentUser.linkedPfId, currentUser.id) : ('EC·' + currentUser.id),
      conductedByUserId: currentUser.id,
      createdAt: Date.now(),
      deleted: false
    };
  }
  try { await trainingSet(rec.id, rec); }
  catch(err) { if (btn){ btn.disabled=false; btn.textContent='[ SAVE TRAINING ]'; } fail('SAVE ERROR: ' + err.message); return; }
  if (typeof auditRecord === 'function') auditRecord(existing ? 'EDITED TRAINING' : 'LOGGED TRAINING', (rec.title || 'Session') + ' · ' + formatDob(rec.date));

  if (btn) { btn.disabled = false; btn.textContent = '[ SAVE TRAINING ]'; }
  closeTrainingModal();
  if (typeof toast==='function') toast('✓ TRAINING SAVED');
  await loadTrainings();
  // refresh personnel cards so their TRAININGS section reflects the change
  if (document.getElementById('tab-personnel-files') && document.getElementById('tab-personnel-files').classList.contains('active')) renderPersonnelFiles();
}
async function deleteTraining(id) {
  var rec = allTrainings.find(function(t){ return t.id === id; });
  if (!canManageTraining(rec)) { alert('You do not have authority to delete this record.'); return; }
  if (!await pfConfirm('Move this training record to the recycle bin?\n\n' + (rec ? ((rec.title||'Session') + ' · ' + formatDob(rec.date)) : ''))) return;
  if (rec) {
    rec.deleted = true; rec.deletedBy = currentUser.id; rec.deletedAt = Date.now();
    try { await trainingSet(id, rec); } catch(e){ alert('ERROR: ' + e.message); return; }
    if (typeof auditRecord === 'function') auditRecord('DELETED TRAINING', (rec.title||'Session') + ' → recycle bin');
    allTrainings = allTrainings.filter(function(t){ return t.id !== id; });
    if (!deletedTrainings.some(function(t){ return t.id===id; })) deletedTrainings.push(rec);
  if (typeof toastUndo==='function') toastUndo('✓ TRAINING DELETED', function(){ undoSoftDelete('training', id); });
  }
  renderTrainings();
}
// Jump from a training record to a personnel file.
function openPersonnelFromTraining(pfId) {
  if (!pfId) return;
  var navEl = document.querySelector('#ngt-omega1 .nav-tab[onclick*="personnel-files"]');
  if (navEl) navEl.click(); else if (typeof switchTab === 'function') switchTab(document.createElement('div'), 'personnel-files');
  setTimeout(function(){
    if (typeof pfExpanded !== 'undefined' && pfExpanded.add) pfExpanded.add(pfId);
    if (typeof renderPersonnelFiles === 'function') renderPersonnelFiles();
    var card = document.getElementById('pfcard_' + pfId);
    if (card && card.scrollIntoView) card.scrollIntoView({ behavior:'smooth', block:'center' });
  }, 120);
}
// Section shown inside a personnel card linking back to that member's trainings.
function buildTrainingSection(p) {
  var conducted = allTrainings.filter(function(t){ return t.conductedByPfId === p.id; });
  var attended  = allTrainings.filter(function(t){
    return t.conductedByPfId !== p.id && Array.isArray(t.attendees) && t.attendees.some(function(a){ return a && a.pfId === p.id; });
  });
  if (!conducted.length && !attended.length) {
    return '<div style="font-size:.6rem;color:var(--text-faint);padding:.3rem 0;">No training records.</div>';
  }
  function row(t, role){
    return '<div style="display:flex;justify-content:space-between;gap:.5rem;padding:2px 0;border-bottom:1px solid var(--border);font-size:.62rem;">'
      + '<span><span class="person-link" data-action="open-training-tab" data-trnid="' + e(t.id) + '">'
      + e(formatDob(t.date)) + (t.title ? ' · ' + e(t.title) : '') + '</span></span>'
      + '<span style="color:var(--text-dim);font-size:.55rem;letter-spacing:.05em;">' + role + '</span></div>';
  }
  var html = '';
  if (conducted.length) html += conducted.map(function(t){ return row(t, 'CONDUCTED'); }).join('');
  if (attended.length)  html += attended.map(function(t){ return row(t, 'ATTENDED'); }).join('');
  return html;
}

// ================================================================
//  SERVICE RECORD — unified chronological history of a member.
//  Aggregates every dated event already stored on the file
//  (enrolment, rank changes, awards, strikes, leave, activity,
//  notes) plus trainings, into one timeline. No new data model —
//  this is a read-only view over fields the app already records.
// ================================================================
// Coerce to an array of real objects, dropping null holes (which Firebase
// can introduce when array items are deleted by index). Shared by the card
// builders and activity logic so one malformed record can't break a list view.
function objArr(x) {
  return Array.isArray(x) ? x.filter(function(v){ return v && typeof v === 'object'; }) : [];
}

function buildServiceRecord(p, opts) {
  opts = opts || {};
  var roleWord = opts.roleWord || 'RANK';
  var ev = [];
  // Firebase can return arrays as objects (with null holes when items are
  // deleted by index), so coerce + drop null/non-object entries defensively.
  function safeArr(x) {
    var arr = Array.isArray(x) ? x : (x && typeof x === 'object' ? Object.values(x) : []);
    return arr.filter(function(v){ return v && typeof v === 'object'; });
  }
  function add(ts, dateStr, type, icon, color, label, detail) {
    if (ts == null && !dateStr) return;
    var sortTs, shownDate;
    if (dateStr) {
      sortTs = Date.parse(dateStr + 'T00:00:00') || 0;
      shownDate = dateStr;
    } else {
      var dt = new Date(ts);
      if (isNaN(dt.getTime())) return; // invalid date value → skip rather than throw
      sortTs = dt.getTime();
      shownDate = dt.toISOString().slice(0, 10);
    }
    ev.push({ ts: sortTs, date: shownDate, type: type, icon: icon, color: color, label: label, detail: detail || '' });
  }
  // Enrolment
  if (p.created) add(p.created, null, 'enlist', '✦', 'var(--cyan)', 'ENROLLED · personnel file created', '');
  // Rank changes
  safeArr(p.rankHistory).forEach(function(r){
    add(r.changedAt, null, 'rank', '▲', 'var(--amber)',
        (r.from ? roleWord + ' CHANGE · ' + r.from + ' → ' + r.to : roleWord + ' SET · ' + r.to),
        r.changedBy ? 'by ' + r.changedBy : '');
  });
  // Awards
  safeArr(p.awards).forEach(function(a){
    add(a.created || null, a.date || null, 'award', '✪', '#5fb87a',
        'AWARD · ' + (a.name || '—') + (a.tier ? ' (' + a.tier + ')' : ''),
        a.awardedBy ? 'by ' + a.awardedBy : '');
  });
  // Strikes
  safeArr(p.strikes).forEach(function(s){
    add(s.issuedAt, null, 'strike', '⚠', '#dd6666',
        'STRIKE · ' + (s.reason || '—') + (s.status && s.status !== 'Active' ? ' [' + s.status + ']' : ''),
        s.issuedBy ? 'by ' + s.issuedBy : '');
  });
  // Leave (LOA / ROA)
  safeArr(p.leaves || p.leave).forEach(function(l){
    add(l.issuedAt || null, l.startDate || null, 'leave', '◷', 'var(--text-dim)',
        'LEAVE · ' + (l.type || 'LOA') + ' ' + (l.startDate || '') + (l.endDate ? '–' + l.endDate : '') + (l.ended ? ' [ended]' : ''),
        l.reason || '');
  });
  // Activity entries
  safeArr(p.activityLog).forEach(function(a){
    add(a.at, null, 'activity', '▣', 'var(--text-faint)',
        'ACTIVITY · ' + (a.hours != null ? a.hours + 'h' : '') + (a.note ? ' — ' + a.note : ''),
        (a.tags && a.tags.length) ? a.tags.join(', ') : '');
  });
  // File notes / annotations
  safeArr(p.notes).forEach(function(n){
    add(n.created, null, 'note', '✎', 'var(--text-faint)',
        'NOTE · ' + (n.text || ''), n.author ? 'by ' + n.author : '');
  });
  // Operations (led or served on)
  safeArr(typeof allOperations !== 'undefined' ? allOperations : []).forEach(function(o){
    var role = (o.leadId === p.id) ? 'LED'
      : (Array.isArray(o.operators) && o.operators.some(function(x){ return x && x.id === p.id; }) ? 'DEPLOYED' : null);
    if (!role) return;
    add(null, o.startDate || (o.createdAt ? new Date(o.createdAt).toISOString().slice(0,10) : null), 'operation', '✜', 'var(--amber)',
        'OPERATION ' + role + ' · ' + (o.codename || o.ref || '') + (o.opType ? ' (' + o.opType + ')' : ''),
        o.status ? o.status : '');
  });
  // Trainings (from the global log)
  safeArr(typeof allTrainings !== 'undefined' ? allTrainings : []).forEach(function(t){
    var role = (t.conductedByPfId === p.id) ? 'CONDUCTED'
      : (Array.isArray(t.attendees) && t.attendees.some(function(x){ return x && x.pfId === p.id; }) ? 'ATTENDED' : null);
    if (!role) return;
    add(null, t.date, 'training', '⌖', 'var(--cyan)', 'TRAINING ' + role + (t.title ? ' · ' + t.title : ''), '');
  });
  ev.sort(function(a,b){ return b.ts - a.ts; }); // newest first
  if (opts.excludeSensitive) ev = ev.filter(function(x){ return x.type !== 'strike' && x.type !== 'note'; });
  return ev;
}

function renderServiceTimeline(events, limit) {
  if (!events || !events.length) {
    return '<div style="font-size:.6rem;color:var(--text-faint);padding:.4rem 0;">No service record entries yet.</div>';
  }
  var rows = (limit ? events.slice(0, limit) : events).map(function(x){
    return '<div class="svc-row">'
      + '<span class="svc-icon" style="color:' + x.color + '">' + x.icon + '</span>'
      + '<span class="svc-date">' + e(formatDob(x.date)) + '</span>'
      + '<span><span class="svc-label">' + e(x.label) + '</span>'
      + (x.detail ? '<span class="svc-detail"> · ' + e(x.detail) + '</span>' : '')
      + '</span></div>';
  }).join('');
  return '<div class="svc-timeline">' + rows + '</div>';
}

// Compact card section: milestones only (excludes routine activity/notes), capped.
function buildServiceSection(p, opts) {
  var full = buildServiceRecord(p, opts);
  var milestones = full.filter(function(x){ return x.type !== 'activity' && x.type !== 'note'; });
  var body = renderServiceTimeline(milestones, 6);
  if (full.length > Math.min(milestones.length, 6)) {
    body += '<button class="pf-section-btn" data-action="open-service-record" data-pfid="' + e(p.id)
         + '" style="margin-top:.45rem;font-size:.55rem;padding:2px 9px;">VIEW FULL SERVICE RECORD (' + full.length + ') →</button>';
  }
  return body;
}

function openServiceRecord(pfId) {
  _serviceRecordPfId = pfId;
  var p = (allPersonnel || []).find(function(x){ return x.id === pfId; });
  var opts = {};
  if (!p && typeof allEthicsPersonnel !== 'undefined') {
    p = (allEthicsPersonnel || []).find(function(x){ return x.id === pfId; });
    if (p) {
      // Honour Ethics graduated access so the record can't bypass card restrictions.
      var access = (typeof getEfFileAccess === 'function') ? getEfFileAccess(p) : 'full';
      if (access === 'name-only') {
        document.getElementById('serviceRecordTitle').textContent = 'SERVICE RECORD · ' + (p.name || p.nickname || pfId);
        document.getElementById('serviceRecordBody').innerHTML =
          '<div style="font-size:.62rem;color:var(--text-faint);font-style:italic;letter-spacing:.05em;padding:1rem;text-align:center;">[ SERVICE RECORD RESTRICTED ]</div>';
        document.getElementById('serviceRecordModal').classList.add('open');
        return;
      }
      opts = { roleWord: 'ROLE', excludeSensitive: (access !== 'full') };
    }
  }
  if (!p) return;
  document.getElementById('serviceRecordTitle').textContent = 'SERVICE RECORD · ' + (p.name || p.nickname || pfId);
  document.getElementById('serviceRecordBody').innerHTML = renderServiceTimeline(buildServiceRecord(p, opts));
  document.getElementById('serviceRecordModal').classList.add('open');
}
function closeServiceRecord() {
  document.getElementById('serviceRecordModal').classList.remove('open');
}

// ================================================================
//  PERSONNEL JACKET EXPORT
//  Produces a standalone, print-ready Foundation-styled dossier for
//  a single member, reusing the same document language as the
//  directive export. Honours Ethics graduated access: 'name-only'
//  viewers cannot export; 'partial' viewers get a record with
//  disciplinary/notes entries withheld.
// ================================================================
var _serviceRecordPfId = null;

function jacketRef(p, system) {
  var tail = (system === 'ef')
    ? String(p.id).slice(-5)
    : (p.isdBadge ? p.isdBadge.replace(/[^A-Za-z0-9]/g, '') : String(p.id).slice(-5));
  return (system === 'ef' ? 'EC-PF-' : 'O1-PF-') + String(tail || '00000').toUpperCase();
}

function buildPersonnelJacket(p, system, opts) {
  opts = opts || {};
  var isEf     = (system === 'ef');
  var ref      = jacketRef(p, system);
  var status   = (p.status || 'Active');
  var statusU  = status.toUpperCase();
  var roleRank = isEf ? (p.role || '—') : (p.rank || '—');
  var classLine = (isEf ? 'LEVEL 4-A // ETHICS COMMITTEE PERSONNEL FILE' : 'LEVEL 3-A // OMEGA-1 PERSONNEL FILE')
                + ' // DESIGNATED RECIPIENTS ONLY';
  var clLabel  = isEf ? 'LEVEL 4-A · SENIOR' : 'LEVEL 3-A · STANDARD';

  // Squadron assignments
  var sqdNames = (typeof allSquadrons !== 'undefined' ? allSquadrons : [])
    .filter(function(s){ return s.members && s.members.some(function(m){ return m && (m.memberId || m.pfId) === p.id; }); })
    .map(function(s){ return s.name || s.id; });

  // Service record (chronological ascending for a formal record)
  var events = buildServiceRecord(p, opts).slice().reverse();
  var svcRows = events.length
    ? events.map(function(x){
        return '<tr><td class="d">' + escHtml(formatDob(x.date)) + '</td>'
          + '<td class="e">' + escHtml(x.label) + (x.detail ? ' <span class="dt">— ' + escHtml(x.detail) + '</span>' : '') + '</td></tr>';
      }).join('')
    : '<tr><td class="d">—</td><td class="e" style="color:#777;font-style:italic;">[ No service record entries on file. ]</td></tr>';

  var nickRow = p.nickname ? '<tr><td class="k">Alias / Callsign</td><td class="v">"' + escHtml(p.nickname) + '"</td></tr>' : '';
  var badgeRow = (!isEf && p.isdBadge) ? '<tr><td class="k">ISD Service Badge</td><td class="v">' + escHtml(p.isdBadge) + '</td></tr>' : '';
  var sqdRow  = sqdNames.length ? '<tr><td class="k">Squadron Assignment</td><td class="v">' + escHtml(sqdNames.join(', ')) + '</td></tr>' : '';

  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>'
    + '<meta name="viewport" content="width=device-width, initial-scale=1"/>'
    + '<title>' + escHtml(ref) + ' — ' + escHtml((p.name || 'PERSONNEL FILE').toUpperCase()) + '</title>'
    + '<style>'
    + '@page{size:A4;margin:18mm 16mm;}'
    + '*{box-sizing:border-box;}'
    + 'body{font-family:"Times New Roman",Georgia,serif;color:#111;background:#525659;margin:0;padding:24px;line-height:1.55;}'
    + '.page{background:#fff;max-width:780px;margin:0 auto 24px;padding:46px 54px 40px;box-shadow:0 2px 18px rgba(0,0,0,.4);position:relative;}'
    + '.runhead{display:flex;justify-content:space-between;font-family:"Courier New",monospace;font-size:8.5px;letter-spacing:.04em;color:#444;border-bottom:1px solid #000;padding-bottom:4px;margin-bottom:2px;text-transform:uppercase;}'
    + '.classbar{background:#1a1a1a;color:#fff;font-family:"Courier New",monospace;font-size:9px;letter-spacing:.14em;text-align:center;padding:5px 4px;margin:0 -54px 4px;font-weight:bold;}'
    + '.scp-tag{text-align:center;font-family:"Courier New",monospace;font-size:9px;letter-spacing:.42em;color:#222;margin:10px 0 18px;font-weight:bold;}'
    + '.lh{text-align:center;border-bottom:2px solid #000;padding-bottom:12px;margin-bottom:16px;}'
    + '.lh .org{font-size:21px;font-weight:bold;letter-spacing:.06em;}'
    + '.lh .sub{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#333;margin-top:3px;}'
    + '.lh .div{font-size:10px;letter-spacing:.1em;color:#555;margin-top:6px;font-style:italic;}'
    + '.doctype{text-align:center;font-size:13px;font-weight:bold;letter-spacing:.16em;margin:14px 0 16px;text-transform:uppercase;}'
    + 'table.meta{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:18px;}'
    + 'table.meta td{border:1px solid #999;padding:4px 8px;vertical-align:top;}'
    + 'table.meta td.k{background:#ededed;font-family:"Courier New",monospace;font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:#333;width:34%;font-weight:bold;}'
    + 'table.meta td.v{font-weight:bold;}'
    + '.secttl{font-size:11px;font-weight:bold;letter-spacing:.14em;text-transform:uppercase;border-bottom:1px solid #000;padding-bottom:3px;margin:22px 0 8px;}'
    + 'table.svc{width:100%;border-collapse:collapse;font-size:11px;}'
    + 'table.svc td{border-bottom:1px solid #ccc;padding:3px 6px;vertical-align:top;}'
    + 'table.svc td.d{font-family:"Courier New",monospace;font-size:9.5px;color:#444;white-space:nowrap;width:90px;}'
    + 'table.svc td.e .dt{color:#666;font-style:italic;}'
    + '.stampbox{position:absolute;top:120px;right:40px;border:3px double #7a0000;color:#7a0000;font-family:"Courier New",monospace;font-weight:bold;font-size:13px;letter-spacing:.1em;padding:6px 14px;transform:rotate(-9deg);opacity:.82;}'
    + '.stampbox.ok{border-color:#0a5a23;color:#0a5a23;}'
    + '.footer{margin-top:26px;border-top:1px solid #000;padding-top:6px;font-family:"Courier New",monospace;font-size:8px;letter-spacing:.06em;color:#444;text-align:center;text-transform:uppercase;}'
    + '.redact{background:#000;color:#000;padding:0 .5em;border-radius:1px;user-select:none;-webkit-print-color-adjust:exact;print-color-adjust:exact;}'
    + '@media print{body{background:#fff;padding:0;}.page{box-shadow:none;margin:0;max-width:none;padding:0;}.classbar{margin:0 0 4px;}}'
    + '</style></head><body><div class="page">'
    + '<div class="runhead"><span>SCP FOUNDATION · ' + (isEf ? 'ETHICS COMMITTEE' : 'MTF OMEGA-1') + '</span><span>FILE ' + escHtml(ref) + ' · ' + clLabel.split(' ·')[0] + '</span></div>'
    + '<div class="classbar">' + classLine + '</div>'
    + '<div class="scp-tag">SECURE · CONTAIN · PROTECT</div>'
    + '<div class="lh"><div class="org">SCP FOUNDATION</div><div class="sub">' + (isEf ? 'Ethics Committee' : 'Mobile Task Force Omega-1 &mdash; &ldquo;Law\'s Left Hand&rdquo;') + '</div><div class="div">CAIRO.AIC ' + (isEf ? 'Oversight Terminal · O5 Liaison Division' : 'Personnel Division') + '</div></div>'
    + '<div class="doctype">' + (isEf ? 'ETHICS COMMITTEE PERSONNEL FILE' : 'OMEGA-1 PERSONNEL FILE') + '</div>'
    + '<div class="stampbox ' + (status === 'Active' ? 'ok' : '') + '">' + escHtml(statusU) + '</div>'
    + '<table class="meta">'
    +   '<tr><td class="k">File Reference</td><td class="v">' + escHtml(ref) + '</td></tr>'
    +   '<tr><td class="k">Designation</td><td class="v">' + escHtml(p.name || 'UNNAMED') + '</td></tr>'
    +   nickRow
    +   '<tr><td class="k">' + (isEf ? 'Committee Role' : 'Rank') + '</td><td class="v">' + escHtml(roleRank) + '</td></tr>'
    +   '<tr><td class="k">Operational Status</td><td class="v">' + escHtml(statusU) + '</td></tr>'
    +   '<tr><td class="k">Date of Birth</td><td class="v">' + escHtml(formatDob(p.dob)) + '</td></tr>'
    +   badgeRow
    +   '<tr><td class="k">Date Enrolled</td><td class="v">' + escHtml(safeDate(p.created)) + '</td></tr>'
    +   sqdRow
    +   '<tr><td class="k">Clearance</td><td class="v"><span class="redact">LEVEL ' + (isEf ? '4-A' : '3-A') + '</span></td></tr>'
    + '</table>'
    + '<div class="secttl">Service Record &mdash; Chronological</div>'
    + '<table class="svc"><tbody>' + svcRows + '</tbody></table>'
    + '<div class="footer">CONFIDENTIAL // ' + clLabel.split(' ·')[0] + ' // ' + escHtml(ref) + ' // GENERATED ' + escHtml(safeDateTime(Date.now())) + ' UTC // CAIRO.AIC</div>'
    + '</div></body></html>';
}

function exportPersonnelJacket(pfId) {
  pfId = pfId || _serviceRecordPfId;
  if (!pfId) return;
  var p = (allPersonnel || []).find(function(x){ return x.id === pfId; });
  var system = 'pf', opts = { roleWord: 'RANK' };
  if (!p && typeof allEthicsPersonnel !== 'undefined') {
    p = (allEthicsPersonnel || []).find(function(x){ return x.id === pfId; });
    if (p) {
      system = 'ef';
      var access = (typeof getEfFileAccess === 'function') ? getEfFileAccess(p) : 'full';
      if (access === 'name-only') { alert('You do not have sufficient access to export this file.'); return; }
      opts = { roleWord: 'ROLE', excludeSensitive: (access !== 'full') };
    }
  }
  if (!p) return;
  var html = buildPersonnelJacket(p, system, opts);
  var safeName = (jacketRef(p, system) + '_' + (p.name || 'file')).replace(/[^A-Za-z0-9_-]/g, '_');
  downloadFile(safeName + '.html', html, 'text/html');
  if (typeof auditRecord === 'function') auditRecord('EXPORTED PERSONNEL FILE', jacketRef(p, system) + ' — ' + (p.name || ''));
}

// ================================================================
//  ETHICS COMMITTEE CASE DOCKET
//  The committee's defining function: logging matters under review,
//  recording rulings + rationale, casting deliberation votes, and
//  linking the personnel/files involved.
//  Firebase path: /ethicsCases/{id}
// ================================================================
var EC_CASE_CATEGORIES = ['Incident Review','Personnel Conduct','Containment Ethics','Testing Approval','Disclosure / Secrecy','Use of Force','Other'];
var EC_CASE_STATUSES   = ['Open','Under Review','Ruled','Closed','Tabled'];
var allEthicsCases     = [];
var deletedEthicsCases = [];
var _caseLinked        = []; // working set {id, sys, name} while the modal is open

async function ethicsCasesGetAll() {
  if (firebaseReady) { var all = await fbGetAll('/ethicsCases'); return all ? Object.values(all) : []; }
  return Object.values(lsAll('ethicsCases/'));
}
async function ethicsCaseSet(id, data) {
  if (firebaseReady) await fbSet('/ethicsCases/' + id, data); else lsSet('ethicsCases/' + id, data);
}
async function ethicsCaseDel(id) { if (firebaseReady) await fbDelete('/ethicsCases/' + id); else lsDel('ethicsCases/' + id); }

// A linked Ethics Committee member may open/manage cases; CL5 command may always.
function canLogCase() {
  if (!currentUser) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  return !!currentUser.linkedEfId;
}
function canManageCase(c) {
  if (!currentUser || !c) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  return c.openedBy === currentUser.id;
}
// Any committee member (or senior staff) may cast a deliberation vote.
function canVoteCase() {
  if (!currentUser) return false;
  return !!currentUser.linkedEfId || parseInt(currentUser.clearance) >= 4;
}

function caseStatusBadge(s) {
  return s === 'Ruled' ? 'b-green' : s === 'Under Review' ? 'b-cyan'
    : s === 'Closed' ? 'b-retired' : s === 'Tabled' ? 'b-red' : 'b-amber';
}

// Resolve a personnel name across both pools.
function caseLinkName(l) {
  var pool = (l.sys === 'ef') ? (typeof allEthicsPersonnel !== 'undefined' ? allEthicsPersonnel : []) : (allPersonnel || []);
  var p = pool.find(function(x){ return x.id === l.id; });
  return p ? (p.name || p.nickname || l.id) : (l.name || '[removed]');
}

function nextCaseRef() {
  var yy = new Date().getFullYear().toString().slice(-2);
  var prefix = 'EC-CASE-' + yy + '-';
  var maxN = 0;
  allEthicsCases.concat(deletedEthicsCases).forEach(function(c){
    if (c.ref && c.ref.indexOf(prefix) === 0) {
      var n = parseInt(c.ref.slice(prefix.length), 10);
      if (!isNaN(n) && n > maxN) maxN = n;
    }
  });
  return prefix + String(maxN + 1).padStart(3, '0');
}

async function loadEthicsCases() {
  try {
    var raw = await ethicsCasesGetAll();
    allEthicsCases = partitionDeleted(raw.filter(function(c){ return c && c.id; }), function(d){ deletedEthicsCases = d; });
  } catch(e) { allEthicsCases = []; }
  allEthicsCases.sort(function(a,b){ return (b.openedAt || 0) - (a.openedAt || 0); });
  var newBtn = document.getElementById('caseNewBtn');
  if (newBtn) newBtn.style.display = canLogCase() ? 'inline-block' : 'none';
  var notice = document.getElementById('caseAccessNotice');
  if (notice) {
    if (!canLogCase()) {
      notice.style.display = 'block';
      notice.textContent = currentUser
        ? 'Only Ethics Committee members (or Level 5 command) may open cases. You may review and vote on the docket below.'
        : 'Observer mode — case docket is read-only.';
    } else notice.style.display = 'none';
  }
  renderEthicsCases();
}

function renderEthicsCases() {
  var list = document.getElementById('caseList');
  if (!list) return;
  var q = ((document.getElementById('caseSearch') || {}).value || '').trim().toLowerCase();
  var fStatus = (document.getElementById('caseFilterStatus') || {}).value || '';

  var rows = allEthicsCases.filter(function(c){
    if (fStatus && (c.status || 'Open') !== fStatus) return false;
    if (!q) return true;
    var hay = [c.ref, c.title, c.summary, c.ruling, c.rationale, c.category]
      .concat((c.linked || []).map(caseLinkName)).join(' ').toLowerCase();
    return hay.indexOf(q) !== -1;
  });

  rows = applySort(rows, g('caseSort'), {
    date:function(c){return c.openedAt||0;},
    ref:function(c){return (c.ref||'').toLowerCase();},
    status:function(c){return c.status||'';},
    category:function(c){return c.category||'';}
  });
  var cnt = document.getElementById('caseCount');
  if (cnt) cnt.textContent = rows.length ? '(' + rows.length + ')' : '';

  if (!rows.length) {
    list.innerHTML = '<div class="trn-empty">NO CASES' + (q || fStatus ? ' MATCH THE CURRENT FILTER.' : ' ON THE DOCKET YET.') + '</div>';
    return;
  }
  list.innerHTML = rows.map(buildCaseCard).join('');
  applyPagination(list, 'cases', g('caseSearch')+'|'+g('caseFilterStatus')+'|'+g('caseSort'));
}

function buildCaseCard(c) {
  var status = c.status || 'Open';
  var catBadge = c.category ? '<span class="badge b-dim">' + e(c.category) + '</span>' : '';
  var statusB = '<span class="badge ' + caseStatusBadge(status) + '">' + e(status.toUpperCase()) + '</span>';
  var manage = canManageCase(c)
    ? '<div style="display:flex;gap:.35rem;">'
      + '<button class="pf-section-btn" data-action="edit-case" data-id="' + e(c.id) + '" style="font-size:.52rem;padding:1px 7px;">EDIT</button>'
      + '<button class="pf-section-btn" data-action="delete-case" data-id="' + e(c.id) + '" style="font-size:.52rem;padding:1px 7px;color:#dd6666;">DELETE</button>'
      + '</div>'
    : '';

  // Vote tally + controls
  var votes = c.votes || {};
  var vk = Object.keys(votes);
  var nFor = vk.filter(function(k){ return votes[k] === 'for'; }).length;
  var nAgainst = vk.filter(function(k){ return votes[k] === 'against'; }).length;
  var nAbstain = vk.filter(function(k){ return votes[k] === 'abstain'; }).length;
  var myVote = currentUser ? votes[currentUser.id] : null;
  var voteCtrls = canVoteCase()
    ? '<button class="vote-btn' + (myVote === 'for' ? ' on-for' : '') + '" data-action="cast-case-vote" data-id="' + e(c.id) + '" data-vote="for">FOR</button>'
      + '<button class="vote-btn' + (myVote === 'against' ? ' on-against' : '') + '" data-action="cast-case-vote" data-id="' + e(c.id) + '" data-vote="against">AGAINST</button>'
      + '<button class="vote-btn' + (myVote === 'abstain' ? ' on-abstain' : '') + '" data-action="cast-case-vote" data-id="' + e(c.id) + '" data-vote="abstain">ABSTAIN</button>'
    : '';
  var voteRow = '<div class="case-vote"><span class="vote-tally">DELIBERATION · For ' + nFor + ' · Against ' + nAgainst + ' · Abstain ' + nAbstain + '</span>' + voteCtrls + '</div>';

  // Linked personnel
  var linked = (c.linked || []).map(function(l){
    return '<span class="case-link"><span class="person-link" data-action="open-case-file" data-pfid="' + e(l.id) + '" data-sys="' + e(l.sys) + '">'
      + e(caseLinkName(l)) + '</span><span class="sys">' + (l.sys === 'ef' ? 'EC' : 'Ω1') + '</span></span>';
  }).join('');

  return '<div class="case-card">'
    + '<div class="case-top"><div><div class="case-ref">' + e(c.ref || '—') + '</div>'
    + '<div class="case-title">' + e(c.title || 'Untitled case') + '</div>'
    + '<div class="case-badges" style="margin-top:4px;">' + statusB + catBadge + '</div></div>' + manage + '</div>'
    + (c.summary ? '<div class="case-block"><span class="lbl">Matter under review</span><span class="txt">' + e(c.summary) + '</span></div>' : '')
    + (c.ruling ? '<div class="case-block case-ruling"><span class="lbl">Ruling</span><span class="txt">' + e(c.ruling) + '</span></div>' : '')
    + (c.rationale ? '<div class="case-block"><span class="lbl">Rationale</span><span class="txt">' + e(c.rationale) + '</span></div>' : '')
    + (linked ? '<div class="case-block"><span class="lbl">Personnel involved</span><div>' + linked + '</div></div>' : '')
    + voteRow
    + '<div style="font-size:.5rem;color:var(--text-faint);letter-spacing:.04em;margin-top:.5rem;">OPENED ' + e(safeDate(c.openedAt)) + ' · EC·' + e(c.openedBy || '—') + (c.ruledBy ? ' · RULED BY EC·' + e(c.ruledBy) : '') + '</div>'
    + '</div>';
}

// ── Modal ──
function openCaseModal(id) {
  if (!id && !canLogCase()) { alert('ACCESS REQUIRED\n\nOnly Ethics Committee members (or Level 5 command) may open cases.'); return; }
  var editing = !!id;
  var c = editing ? allEthicsCases.find(function(x){ return x.id === id; }) : null;
  if (editing && !canManageCase(c)) { alert('You do not have authority to edit this case.'); return; }

  document.getElementById('caseModalTitle').textContent = editing ? 'EDIT CASE' : 'OPEN CASE';
  document.getElementById('caseEditId').value = id || '';
  document.getElementById('caseErr').style.display = 'none';
  document.getElementById('caseCategory').innerHTML = EC_CASE_CATEGORIES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  document.getElementById('caseStatus').innerHTML = EC_CASE_STATUSES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');

  document.getElementById('caseRef').value      = c ? (c.ref || nextCaseRef()) : nextCaseRef();
  document.getElementById('caseTitle').value    = c ? (c.title || '') : '';
  document.getElementById('caseCategory').value = c ? (c.category || EC_CASE_CATEGORIES[0]) : EC_CASE_CATEGORIES[0];
  document.getElementById('caseStatus').value   = c ? (c.status || 'Open') : 'Open';
  document.getElementById('caseSummary').value  = c ? (c.summary || '') : '';
  document.getElementById('caseRuling').value   = c ? (c.ruling || '') : '';
  document.getElementById('caseRationale').value= c ? (c.rationale || '') : '';
  _caseLinked = (c && Array.isArray(c.linked)) ? c.linked.map(function(l){ return { id: l.id, sys: l.sys, name: l.name }; }) : [];

  renderCaseLinkList();
  populateCaseLinkPicker();
  document.getElementById('caseModal').classList.add('open');
}
function closeCaseModal() {
  document.getElementById('caseModal').classList.remove('open');
  _caseLinked = [];
}
function populateCaseLinkPicker() {
  var sel = document.getElementById('caseLinkPicker');
  if (!sel) return;
  var taken = {};
  _caseLinked.forEach(function(l){ taken[l.sys + ':' + l.id] = true; });
  var opts = ['<option value="">+ LINK PERSONNEL...</option>'];
  (allPersonnel || []).slice().sort(function(a,b){ return (a.name||'').localeCompare(b.name||''); }).forEach(function(p){
    if (p.id && !taken['pf:' + p.id]) opts.push('<option value="pf:' + e(p.id) + '">Ω1 · ' + e(p.name || p.id) + '</option>');
  });
  (typeof allEthicsPersonnel !== 'undefined' ? allEthicsPersonnel : []).slice().sort(function(a,b){ return (a.name||'').localeCompare(b.name||''); }).forEach(function(p){
    if (p.id && !taken['ef:' + p.id]) opts.push('<option value="ef:' + e(p.id) + '">EC · ' + e(p.name || p.id) + '</option>');
  });
  sel.innerHTML = opts.join('');
}
function addCaseLink(val) {
  if (!val) return;
  var sys = val.slice(0, 2), id = val.slice(3);
  if (_caseLinked.some(function(l){ return l.sys === sys && l.id === id; })) return;
  var pool = (sys === 'ef') ? (typeof allEthicsPersonnel !== 'undefined' ? allEthicsPersonnel : []) : (allPersonnel || []);
  var p = pool.find(function(x){ return x.id === id; });
  _caseLinked.push({ id: id, sys: sys, name: p ? (p.name || p.nickname || id) : id });
  renderCaseLinkList();
  populateCaseLinkPicker();
}
function removeCaseLink(sys, id) {
  _caseLinked = _caseLinked.filter(function(l){ return !(l.sys === sys && l.id === id); });
  renderCaseLinkList();
  populateCaseLinkPicker();
}
function renderCaseLinkList() {
  var box = document.getElementById('caseLinkList');
  if (!box) return;
  if (!_caseLinked.length) { box.innerHTML = '<span style="font-size:.58rem;color:var(--text-faint);">No personnel linked.</span>'; return; }
  box.innerHTML = _caseLinked.map(function(l){
    return '<span class="case-link">' + e(l.name) + '<span class="sys">' + (l.sys === 'ef' ? 'EC' : 'Ω1') + '</span>'
      + '<span class="x" data-action="remove-case-link" data-sys="' + e(l.sys) + '" data-pfid="' + e(l.id) + '">×</span></span>';
  }).join('');
}
async function saveCase() {
  var title = document.getElementById('caseTitle').value.trim();
  var summary = document.getElementById('caseSummary').value.trim();
  var errEl = document.getElementById('caseErr');
  function fail(m){ errEl.textContent = m; errEl.style.display = 'block'; }
  if (!title)   { fail('A case subject / title is required.'); return; }
  if (!summary) { fail('Describe the matter under review.'); return; }

  var editId = document.getElementById('caseEditId').value;
  var existing = editId ? allEthicsCases.find(function(x){ return x.id === editId; }) : null;
  if (editId && !canManageCase(existing)) { fail('You do not have authority to edit this case.'); return; }
  if (!editId && !canLogCase()) { fail('Only Ethics Committee members (or Level 5 command) may open cases.'); return; }

  var btn = document.getElementById('caseSaveBtn');
  if (btn) { btn.disabled = true; btn.textContent = '[ SAVING... ]'; }

  var status = document.getElementById('caseStatus').value;
  var ruling = document.getElementById('caseRuling').value.trim();
  var rationale = document.getElementById('caseRationale').value.trim();
  var c;
  if (existing) {
    c = existing;
    c.title = title; c.category = document.getElementById('caseCategory').value;
    c.status = status; c.summary = summary; c.ruling = ruling; c.rationale = rationale;
    c.linked = _caseLinked.slice(); c.updatedBy = currentUser.id; c.updatedAt = Date.now();
    if (status === 'Ruled' && !c.ruledAt) { c.ruledBy = currentUser.id; c.ruledAt = Date.now(); }
  } else {
    c = {
      id: 'case_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
      ref: document.getElementById('caseRef').value || nextCaseRef(),
      title: title, category: document.getElementById('caseCategory').value,
      status: status, summary: summary, ruling: ruling, rationale: rationale,
      linked: _caseLinked.slice(), votes: {},
      openedBy: currentUser.id, openedAt: Date.now(), deleted: false
    };
    if (status === 'Ruled') { c.ruledBy = currentUser.id; c.ruledAt = Date.now(); }
  }
  try { await ethicsCaseSet(c.id, c); }
  catch(err) { if (btn){ btn.disabled=false; btn.textContent='[ SAVE CASE ]'; } fail('SAVE ERROR: ' + err.message); return; }
  if (typeof auditRecord === 'function') auditRecord(existing ? 'EDITED CASE' : 'OPENED CASE', c.ref + ' — ' + c.title);

  if (btn) { btn.disabled = false; btn.textContent = '[ SAVE CASE ]'; }
  closeCaseModal();
  if (typeof toast==='function') toast('✓ CASE SAVED');
  await loadEthicsCases();
}
async function castCaseVote(caseId, vote) {
  if (!canVoteCase()) { alert('Only Ethics Committee members (or senior staff) may vote.'); return; }
  var c = allEthicsCases.find(function(x){ return x.id === caseId; });
  if (!c) return;
  if (!c.votes) c.votes = {};
  if (c.votes[currentUser.id] === vote) delete c.votes[currentUser.id]; // toggle off
  else c.votes[currentUser.id] = vote;
  try { await ethicsCaseSet(c.id, c); } catch(e){ alert('ERROR: ' + e.message); return; }
  renderEthicsCases();
}
async function deleteCase(id) {
  var c = allEthicsCases.find(function(x){ return x.id === id; });
  if (!canManageCase(c)) { alert('You do not have authority to delete this case.'); return; }
  if (!await pfConfirm('Move this case to the recycle bin?\n\n' + (c ? (c.ref + ' — ' + c.title) : ''))) return;
  if (c) {
    c.deleted = true; c.deletedBy = currentUser.id; c.deletedAt = Date.now();
    try { await ethicsCaseSet(id, c); } catch(e){ alert('ERROR: ' + e.message); return; }
    if (typeof auditRecord === 'function') auditRecord('DELETED CASE', c.ref + ' → recycle bin');
    allEthicsCases = allEthicsCases.filter(function(x){ return x.id !== id; });
    if (!deletedEthicsCases.some(function(x){ return x.id === id; })) deletedEthicsCases.push(c);
  if (typeof toastUndo==='function') toastUndo('✓ CASE DELETED', function(){ undoSoftDelete('ecase', id); });
  }
  renderEthicsCases();
}
// Jump from a linked case entry to the relevant personnel file.
function openFileFromCase(pfId, sys) {
  if (sys === 'ef') {
    var navE = document.querySelector('#ngt-ethics .nav-tab[onclick*="ethics-files"]');
    if (navE) navE.click();
    setTimeout(function(){
      if (typeof efExpanded !== 'undefined' && efExpanded.add) efExpanded.add(pfId);
      if (typeof renderEthicsFiles === 'function') renderEthicsFiles();
      var card = document.getElementById('efcard_' + pfId);
      if (card && card.scrollIntoView) card.scrollIntoView({ behavior:'smooth', block:'center' });
    }, 120);
  } else {
    openPersonnelFromTraining(pfId); // reuse the Omega-1 open+expand helper
  }
}

// ================================================================
//  TRIBUNAL SYSTEM
//  Any personnel may submit a tribunal request. Ethics Committee
//  personnel (Assistant / Member / Chairman) accept or deny; the
//  acceptor becomes the presiding Judge. Accepted tribunals can be
//  scheduled via a thread, exported as a Foundation document, and
//  concluded with a structured verdict. Verdicts may be appealed
//  within a configurable window, escalating to the next EC tier.
//  Firebase path: /tribunals/{id} ; config: /tribunalConfig
// ================================================================
var TRIBUNAL_STATUSES = ['Submitted','Accepted','Scheduled','Concluded','Appealed','Denied'];
var allTribunals      = [];
var deletedTribunals  = [];
var tribunalConfig    = { appealWindowDays: 5 };
var expandedTribunals = (typeof Set !== 'undefined') ? new Set() : null;
var _tribCharges      = [];
var _tribWitnesses    = [];
var _tribProsecutors  = [];
var _reasonCb         = null; // callback for the shared reason modal

async function tribunalsGetAll() {
  if (firebaseReady) { var all = await fbGetAll('/tribunals'); return all ? Object.values(all) : []; }
  return Object.values(lsAll('tribunals/'));
}
async function tribunalSet(id, data) {
  if (firebaseReady) await fbSet('/tribunals/' + id, data); else lsSet('tribunals/' + id, data);
}
async function tribunalDel(id) { if (firebaseReady) await fbDelete('/tribunals/' + id); else lsDel('tribunals/' + id); }
async function tribunalConfigGet() {
  if (firebaseReady) { var c = await fbGetAll('/tribunalConfig'); return c || null; }
  return lsGet('tribunalConfig/config') || null;
}
async function tribunalConfigSave() {
  if (firebaseReady) await fbSet('/tribunalConfig', tribunalConfig);
  else lsSet('tribunalConfig/config', tribunalConfig);
}

// ── Roles & permissions ──
function ecRoleOf(u) {
  u = u || currentUser;
  if (!u || !u.linkedEfId) return null;
  var ef = (typeof allEthicsPersonnel !== 'undefined' ? allEthicsPersonnel : []).find(function(x){ return x.id === u.linkedEfId; });
  return ef ? (ef.role || 'Assistant') : null;
}
function ecFileName(u) {
  u = u || currentUser;
  if (!u || !u.linkedEfId) return (u ? u.id : '—');
  var ef = (typeof allEthicsPersonnel !== 'undefined' ? allEthicsPersonnel : []).find(function(x){ return x.id === u.linkedEfId; });
  return ef ? (ef.name || ef.nickname || u.id) : u.id;
}
function ecRoleRank(r) { return r === 'Chairman' ? 3 : r === 'Member' ? 2 : r === 'Assistant' ? 1 : 0; }
function nextEcRole(r) { return r === 'Assistant' ? 'Member' : r === 'Member' ? 'Chairman' : null; }
function isEthicsPersonnel() { return !!ecRoleOf(currentUser); }
function canSubmitTribunal() { return !!currentUser; }
function isTribunalJudge(t) { return !!(currentUser && t && t.judgeId === currentUser.id); }

// ── Storage load / render ──
async function loadTribunals() {
  try {
    var raw = await tribunalsGetAll();
    allTribunals = partitionDeleted(raw.filter(function(t){ return t && t.id; }), function(d){ deletedTribunals = d; });
  } catch(e) { allTribunals = []; }
  allTribunals.sort(function(a,b){ return (b.submittedAt || 0) - (a.submittedAt || 0); });
  try { var cfg = await tribunalConfigGet(); if (cfg && cfg.appealWindowDays != null) tribunalConfig.appealWindowDays = cfg.appealWindowDays; } catch(e){}
  var newBtn = document.getElementById('tribNewBtn');
  if (newBtn) newBtn.style.display = canSubmitTribunal() ? 'inline-block' : 'none';
  var notice = document.getElementById('tribAccessNotice');
  if (notice) {
    if (!currentUser) { notice.style.display = 'block'; notice.textContent = 'Observer mode — tribunal docket is read-only.'; }
    else notice.style.display = 'none';
  }
  renderTribunals();
}

function appealWindowDays() { return parseInt(tribunalConfig.appealWindowDays) || 5; }
function appealAllowed(t) {
  if (!t || t.status !== 'Concluded' || !t.outcome || !t.outcome.deliveredAt) return false;
  if (!nextEcRole(t.judgeRole)) return false; // Chairman verdict is final
  return Date.now() < (t.outcome.deliveredAt + appealWindowDays() * 86400000);
}
function tribStatusBadge(s) {
  return s === 'Concluded' ? 'b-green' : s === 'Scheduled' ? 'b-cyan'
    : s === 'Accepted' ? 'b-cyan' : s === 'Denied' ? 'b-retired'
    : s === 'Appealed' ? 'b-red' : 'b-amber';
}

function renderTribunals() {
  var list = document.getElementById('tribList');
  if (!list) return;
  var q = ((document.getElementById('tribSearch') || {}).value || '').trim().toLowerCase();
  var fStatus = (document.getElementById('tribFilterStatus') || {}).value || '';
  var rows = allTribunals.filter(function(t){
    if (fStatus && (t.status || 'Submitted') !== fStatus) return false;
    if (!q) return true;
    var d = t.defendant || {};
    var hay = [t.ref, d.name, d.rank, d.department, t.judgeName, (t.charges||[]).join(' '), (t.leadCounsel&&t.leadCounsel.name)].join(' ').toLowerCase();
    return hay.indexOf(q) !== -1;
  });
  var cnt = document.getElementById('tribCount');
  if (cnt) cnt.textContent = rows.length ? '(' + rows.length + ')' : '';
  if (!rows.length) {
    list.innerHTML = '<div class="trn-empty">NO TRIBUNALS' + (q || fStatus ? ' MATCH THE CURRENT FILTER.' : ' ON THE DOCKET YET.') + '</div>';
    return;
  }
  list.innerHTML = rows.map(buildTribunalCard).join('');
}

function outcomeText(o) {
  if (!o) return '';
  if (o.type === 'not-guilty') return 'NOT GUILTY on all charges — defendant released.';
  if (o.type === 'guilty-all') return 'GUILTY on all counts. Sentence: ' + (o.punishment || '—');
  if (o.type === 'guilty-partial') return 'GUILTY on: ' + (o.partialCharges || '—') + '. Sentence: ' + (o.partialPunishment || '—');
  if (o.type === 'plea') return 'PLEA DEAL — pleaded guilty to: ' + (o.pleaCharges || '—') + '. Disposition: ' + (o.pleaPunishment || '—');
  return '';
}

function buildTribunalCard(t) {
  var d = t.defendant || {};
  var status = t.status || 'Submitted';
  var statusB = '<span class="badge ' + tribStatusBadge(status) + '">' + e(status.toUpperCase()) + '</span>';
  var isEC = isEthicsPersonnel();
  var judge = isTribunalJudge(t);
  var expanded = expandedTribunals && expandedTribunals.has(t.id);

  // Roster blocks
  var charges = (t.charges || []).length ? '<ol style="margin:.2rem 0 0 1.1rem;padding:0;">' + t.charges.map(function(c){ return '<li>' + e(c) + '</li>'; }).join('') + '</ol>' : '<span style="color:var(--text-faint);">none listed</span>';
  var prosec = '<div>Lead Counsel (ISD): <strong>' + e((t.leadCounsel && t.leadCounsel.name) || '—') + '</strong></div>'
    + ((t.prosecutors || []).length ? '<div style="color:var(--text-dim);">Co-counsel: ' + t.prosecutors.map(function(p){ return e(p.name || p); }).join(', ') + '</div>' : '');
  var witnesses = (t.witnesses || []).length ? t.witnesses.map(function(w){ return e(w); }).join(', ') : '<span style="color:var(--text-faint);">none</span>';

  // Action buttons by state
  var actions = [];
  if (status === 'Submitted' && isEC) {
    actions.push('<button class="pf-section-btn" data-action="accept-tribunal" data-id="' + e(t.id) + '" style="color:#5fb87a;">ACCEPT (PRESIDE)</button>');
    actions.push('<button class="pf-section-btn" data-action="deny-tribunal" data-id="' + e(t.id) + '" style="color:#dd6666;">DENY</button>');
  }
  if (status === 'Accepted' || status === 'Scheduled') {
    if (judge) actions.push('<button class="pf-section-btn" data-action="open-outcome" data-id="' + e(t.id) + '">DELIVER VERDICT</button>');
    actions.push('<button class="pf-section-btn" data-action="export-tribunal" data-id="' + e(t.id) + '">⎙ EXPORT</button>');
  }
  if (status === 'Concluded') {
    actions.push('<button class="pf-section-btn" data-action="export-tribunal" data-id="' + e(t.id) + '">⎙ EXPORT</button>');
    if (appealAllowed(t)) actions.push('<button class="pf-section-btn" data-action="file-appeal" data-id="' + e(t.id) + '" style="color:var(--amber);">FILE APPEAL</button>');
  }
  if (status === 'Appealed') {
    actions.push('<button class="pf-section-btn" data-action="export-tribunal" data-id="' + e(t.id) + '">⎙ EXPORT</button>');
    var esc = t.appeal && t.appeal.escalatedToRole;
    if (esc && ecRoleRank(ecRoleOf(currentUser)) >= ecRoleRank(esc)) {
      actions.push('<button class="pf-section-btn" data-action="take-appeal" data-id="' + e(t.id) + '" style="color:#5fb87a;">TAKE APPEAL (PRESIDE)</button>');
    }
  }
  var manageDel = (isTribunalJudge(t) || (currentUser && parseInt(currentUser.clearance) >= 5) || (currentUser && t.submittedBy === currentUser.id && status === 'Submitted'))
    ? '<button class="pf-section-btn" data-action="delete-tribunal" data-id="' + e(t.id) + '" style="color:#dd6666;font-size:.5rem;">DELETE</button>' : '';

  // Judge / schedule / thread (visible once accepted)
  var procBlock = '';
  if (status !== 'Submitted' && status !== 'Denied') {
    var dateLine = t.hearingDate ? safeDateTime(t.hearingDate) + ' UTC' : '<span style="color:var(--amber);">to be scheduled</span>';
    var judgeCtrl = judge
      ? '<div style="display:flex;gap:.35rem;align-items:center;margin-top:.35rem;flex-wrap:wrap;">'
        + '<input type="datetime-local" id="tribDate_' + e(t.id) + '" class="modal-input" style="width:auto;font-size:.6rem;padding:2px 6px;"/>'
        + '<button class="pf-section-btn" data-action="set-hearing-date" data-id="' + e(t.id) + '">SET HEARING DATE</button></div>'
      : '';
    var thread = (t.thread || []);
    var threadHtml = expanded
      ? '<div style="margin-top:.4rem;border-top:1px dashed var(--border);padding-top:.4rem;">'
        + (thread.length ? thread.map(function(m){
            return '<div style="font-size:.6rem;margin-bottom:.3rem;"><span style="color:var(--cyan);">' + e(m.author) + '</span> <span style="color:var(--text-faint);">· ' + e(safeDateTime(m.created)) + '</span><br><span>' + e(m.text) + '</span></div>';
          }).join('') : '<div style="font-size:.58rem;color:var(--text-faint);">[ no scheduling messages yet ]</div>')
        + (currentUser ? '<div style="display:flex;gap:.35rem;margin-top:.3rem;"><input id="tribMsg_' + e(t.id) + '" class="modal-input" placeholder="Propose a date / discuss..." style="flex:1;font-size:.6rem;padding:2px 6px;"/><button class="pf-section-btn" data-action="post-tribunal-msg" data-id="' + e(t.id) + '">POST</button></div>' : '')
        + '</div>'
      : '';
    procBlock = '<div class="case-block"><span class="lbl">Presiding Judge</span><span class="txt">' + e(t.judgeName || '—') + (t.judgeRole ? ' (' + e(t.judgeRole) + ')' : '') + '</span></div>'
      + '<div class="case-block"><span class="lbl">Hearing</span><span class="txt">' + dateLine + '</span>' + judgeCtrl + '</div>'
      + '<div class="case-block"><span class="lbl">Scheduling Thread</span>'
      + '<button class="pf-section-btn" data-action="toggle-tribunal-thread" data-id="' + e(t.id) + '" style="font-size:.5rem;padding:1px 7px;">' + (expanded ? '▾ hide' : '▸ open') + ' (' + (t.thread || []).length + ')</button>'
      + threadHtml + '</div>';
  }

  var outcomeBlock = (status === 'Concluded' || status === 'Appealed') && t.outcome
    ? '<div class="case-block case-ruling"><span class="lbl">Verdict</span><span class="txt">' + e(outcomeText(t.outcome)) + '</span></div>'
    : '';
  var appealBlock = status === 'Appealed' && t.appeal
    ? '<div class="case-block"><span class="lbl">Appeal</span><span class="txt">Escalated to ' + e(t.appeal.escalatedToRole || '—') + '. Grounds: ' + e(t.appeal.reason || '—') + '</span></div>'
    : '';
  var denyBlock = status === 'Denied'
    ? '<div class="case-block"><span class="lbl">Denied</span><span class="txt">' + e(t.denyReason || 'No reason recorded.') + ' (EC·' + e(t.deniedBy || '—') + ')</span></div>'
    : '';

  return '<div class="case-card">'
    + '<div class="case-top"><div><div class="case-ref">' + e(t.ref || '—') + '</div>'
    + '<div class="case-title">TRIBUNAL · ' + e(d.name || 'Unnamed defendant') + '</div>'
    + '<div class="case-badges" style="margin-top:4px;">' + statusB + (d.department ? '<span class="badge b-dim">' + e(d.department) + '</span>' : '') + '</div></div>'
    + '<div style="display:flex;gap:.35rem;flex-wrap:wrap;justify-content:flex-end;">' + actions.join('') + manageDel + '</div></div>'
    + '<div class="case-block"><span class="lbl">Defendant</span><span class="txt">' + e(d.rank || '') + ' ' + e(d.name || '') + (d.department ? ' · ' + e(d.department) : '') + '</span></div>'
    + '<div class="case-block"><span class="lbl">FLC Charges</span><span class="txt">' + charges + '</span></div>'
    + '<div class="case-block"><span class="lbl">Prosecution</span><span class="txt">' + prosec + '</span></div>'
    + '<div class="case-block"><span class="lbl">Witnesses</span><span class="txt">' + witnesses + '</span></div>'
    + procBlock + outcomeBlock + appealBlock + denyBlock
    + '<div style="font-size:.5rem;color:var(--text-faint);letter-spacing:.04em;margin-top:.5rem;">FILED ' + e(safeDate(t.submittedAt)) + ' · ' + e(t.submittedBy || '—') + '</div>'
    + '</div>';
}

// ── Submission modal ──
function openTribunalModal() {
  if (!canSubmitTribunal()) { alert('You must be signed in to submit a tribunal request.'); return; }
  document.getElementById('tribEditId').value = '';
  document.getElementById('tribErr').style.display = 'none';
  ['tribDefDept','tribDefRank','tribDefName','tribLeadCounsel'].forEach(function(idf){ var el=document.getElementById(idf); if(el) el.value=''; });
  document.getElementById('tribIsdConfirm').checked = false;
  _tribCharges = []; _tribWitnesses = []; _tribProsecutors = [];
  renderTribList('tribChargeList', _tribCharges, 'charge');
  renderTribList('tribWitnessList', _tribWitnesses, 'witness');
  renderTribList('tribProsecutorList', _tribProsecutors, 'prosecutor');
  document.getElementById('tribunalModal').classList.add('open');
}
function closeTribunalModal() {
  document.getElementById('tribunalModal').classList.remove('open');
  _tribCharges = []; _tribWitnesses = []; _tribProsecutors = [];
}
function renderTribList(boxId, arr, kind) {
  var box = document.getElementById(boxId);
  if (!box) return;
  if (!arr.length) { box.innerHTML = '<span style="font-size:.58rem;color:var(--text-faint);">none added</span>'; return; }
  box.innerHTML = arr.map(function(v, i){
    return '<span class="trn-attendee">' + e(v) + '<span class="x" data-action="remove-trib-item" data-kind="' + kind + '" data-idx="' + i + '">×</span></span>';
  }).join('');
}
function addTribItem(kind) {
  var map = { charge: ['tribChargeInput', _tribCharges, 'tribChargeList'], witness: ['tribWitnessInput', _tribWitnesses, 'tribWitnessList'], prosecutor: ['tribProsecutorInput', _tribProsecutors, 'tribProsecutorList'] };
  var cfg = map[kind]; if (!cfg) return;
  var inp = document.getElementById(cfg[0]); if (!inp) return;
  var val = inp.value.trim(); if (!val) return;
  cfg[1].push(val); inp.value = '';
  renderTribList(cfg[2], cfg[1], kind);
}
function removeTribItem(kind, idx) {
  var arr = kind === 'charge' ? _tribCharges : kind === 'witness' ? _tribWitnesses : _tribProsecutors;
  arr.splice(parseInt(idx), 1);
  renderTribList(kind === 'charge' ? 'tribChargeList' : kind === 'witness' ? 'tribWitnessList' : 'tribProsecutorList', arr, kind);
}
function nextTribunalRef() {
  var yy = new Date().getFullYear().toString().slice(-2);
  var prefix = 'EC-TRIB-' + yy + '-';
  var maxN = 0;
  allTribunals.concat(deletedTribunals).forEach(function(t){
    if (t.ref && t.ref.indexOf(prefix) === 0) { var n = parseInt(t.ref.slice(prefix.length), 10); if (!isNaN(n) && n > maxN) maxN = n; }
  });
  return prefix + String(maxN + 1).padStart(3, '0');
}
async function saveTribunal() {
  var name = document.getElementById('tribDefName').value.trim();
  var lead = document.getElementById('tribLeadCounsel').value.trim();
  var isd  = document.getElementById('tribIsdConfirm').checked;
  var errEl = document.getElementById('tribErr');
  function fail(m){ errEl.textContent = m; errEl.style.display = 'block'; }
  if (!name) { fail('Defendant name is required.'); return; }
  if (!_tribCharges.length) { fail('At least one FLC charge is required.'); return; }
  if (!lead) { fail('A Lead Counsel is required.'); return; }
  if (!isd)  { fail('Lead Counsel must be confirmed as a member of the Internal Security Department.'); return; }
  if (!canSubmitTribunal()) { fail('You must be signed in to submit.'); return; }

  var btn = document.getElementById('tribSaveBtn');
  if (btn) { btn.disabled = true; btn.textContent = '[ SUBMITTING... ]'; }
  var t = {
    id: 'trib_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    ref: nextTribunalRef(),
    status: 'Submitted',
    defendant: { department: document.getElementById('tribDefDept').value.trim(), rank: document.getElementById('tribDefRank').value.trim(), name: name },
    leadCounsel: { name: lead, isdConfirmed: true },
    prosecutors: _tribProsecutors.map(function(n){ return { name: n }; }),
    charges: _tribCharges.slice(),
    witnesses: _tribWitnesses.slice(),
    thread: [],
    submittedBy: currentUser.id, submittedAt: Date.now(), deleted: false
  };
  try { await tribunalSet(t.id, t); }
  catch(err){ if (btn){ btn.disabled=false; btn.textContent='[ SUBMIT REQUEST ]'; } fail('SUBMIT ERROR: ' + err.message); return; }
  if (typeof auditRecord === 'function') auditRecord('SUBMITTED TRIBUNAL', t.ref + ' — ' + name);
  if (btn) { btn.disabled = false; btn.textContent = '[ SUBMIT REQUEST ]'; }
  closeTribunalModal();
  if (typeof toast==='function') toast('✓ TRIBUNAL SAVED');
  await loadTribunals();
}

// ── Accept / deny ──
async function acceptTribunal(id) {
  if (!isEthicsPersonnel()) { alert('Only Ethics Committee personnel may accept a tribunal.'); return; }
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t || t.status !== 'Submitted') return;
  t.status = 'Accepted';
  t.judgeId = currentUser.id; t.judgeName = ecFileName(currentUser); t.judgeRole = ecRoleOf(currentUser);
  t.acceptedAt = Date.now();
  try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('ACCEPTED TRIBUNAL', t.ref + ' — presiding: ' + t.judgeName);
  renderTribunals();
}
function denyTribunal(id) {
  if (!isEthicsPersonnel()) { alert('Only Ethics Committee personnel may deny a tribunal.'); return; }
  openReasonModal('Reason for denial', async function(reason){
    var t = allTribunals.find(function(x){ return x.id === id; });
    if (!t || t.status !== 'Submitted') return;
    t.status = 'Denied'; t.deniedBy = currentUser.id; t.deniedAt = Date.now(); t.denyReason = reason || 'No reason recorded.';
    try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
    if (typeof auditRecord === 'function') auditRecord('DENIED TRIBUNAL', t.ref);
    renderTribunals();
  });
}

// ── Scheduling thread + hearing date ──
async function setHearingDate(id) {
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t || !isTribunalJudge(t)) { alert('Only the presiding judge may set the hearing date.'); return; }
  var inp = document.getElementById('tribDate_' + id);
  if (!inp || !inp.value) { alert('Select a date and time first.'); return; }
  t.hearingDate = new Date(inp.value).getTime();
  if (t.status === 'Accepted') t.status = 'Scheduled';
  (t.thread = t.thread || []).push({ author: ecFileName(currentUser), text: 'Hearing scheduled for ' + safeDateTime(t.hearingDate) + ' UTC.', created: Date.now() });
  try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('SCHEDULED TRIBUNAL', t.ref + ' — ' + safeDateTime(t.hearingDate));
  renderTribunals();
}
async function postTribunalMsg(id) {
  if (!currentUser) return;
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t) return;
  var inp = document.getElementById('tribMsg_' + id);
  var txt = inp && inp.value.trim(); if (!txt) return;
  (t.thread = t.thread || []).push({ author: (currentUser.linkedEfId ? ecFileName(currentUser) : currentUser.id), text: txt, created: Date.now() });
  try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
  renderTribunals();
}
function toggleTribunalThread(id) {
  if (!expandedTribunals) return;
  if (expandedTribunals.has(id)) expandedTribunals.delete(id); else expandedTribunals.add(id);
  renderTribunals();
}

// ── Verdict / outcome ──
function openOutcomeModal(id) {
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t || !isTribunalJudge(t)) { alert('Only the presiding judge may deliver the verdict.'); return; }
  document.getElementById('outcomeTribId').value = id;
  document.getElementById('outcomeType').value = (t.outcome && t.outcome.type) || 'plea';
  document.getElementById('outcomePleaCharges').value = (t.outcome && t.outcome.pleaCharges) || '';
  document.getElementById('outcomePleaPunish').value = (t.outcome && t.outcome.pleaPunishment) || '';
  document.getElementById('outcomeAllPunish').value = (t.outcome && t.outcome.punishment) || '';
  document.getElementById('outcomePartCharges').value = (t.outcome && t.outcome.partialCharges) || '';
  document.getElementById('outcomePartPunish').value = (t.outcome && t.outcome.partialPunishment) || '';
  document.getElementById('outcomeErr').style.display = 'none';
  syncOutcomeFields();
  document.getElementById('tribunalOutcomeModal').classList.add('open');
}
function closeOutcomeModal() { document.getElementById('tribunalOutcomeModal').classList.remove('open'); }
function syncOutcomeFields() {
  var type = document.getElementById('outcomeType').value;
  var show = { plea: ['outcomePleaRow'], 'guilty-all': ['outcomeAllRow'], 'guilty-partial': ['outcomePartRow'], 'not-guilty': [] };
  ['outcomePleaRow','outcomeAllRow','outcomePartRow'].forEach(function(rid){
    var el = document.getElementById(rid); if (el) el.style.display = (show[type] || []).indexOf(rid) !== -1 ? 'block' : 'none';
  });
  var ng = document.getElementById('outcomeNotGuiltyNote');
  if (ng) ng.style.display = type === 'not-guilty' ? 'block' : 'none';
}
async function saveTribunalOutcome() {
  var id = document.getElementById('outcomeTribId').value;
  var t = allTribunals.find(function(x){ return x.id === id; });
  var errEl = document.getElementById('outcomeErr');
  function fail(m){ errEl.textContent = m; errEl.style.display = 'block'; }
  if (!t || !isTribunalJudge(t)) { fail('Only the presiding judge may deliver the verdict.'); return; }
  var type = document.getElementById('outcomeType').value;
  var o = { type: type, deliveredBy: currentUser.id, deliveredAt: Date.now() };
  if (type === 'plea') {
    o.pleaCharges = document.getElementById('outcomePleaCharges').value.trim();
    o.pleaPunishment = document.getElementById('outcomePleaPunish').value.trim();
    if (!o.pleaCharges || !o.pleaPunishment) { fail('Enter the charges pleaded to and the disposition.'); return; }
  } else if (type === 'guilty-all') {
    o.punishment = document.getElementById('outcomeAllPunish').value.trim();
    if (!o.punishment) { fail('Enter the sentence.'); return; }
  } else if (type === 'guilty-partial') {
    o.partialCharges = document.getElementById('outcomePartCharges').value.trim();
    o.partialPunishment = document.getElementById('outcomePartPunish').value.trim();
    if (!o.partialCharges || !o.partialPunishment) { fail('Enter the charges found guilty and the sentence.'); return; }
  }
  t.outcome = o; t.status = 'Concluded';
  try { await tribunalSet(id, t); } catch(err){ fail('SAVE ERROR: ' + err.message); return; }
  if (typeof auditRecord === 'function') auditRecord('TRIBUNAL VERDICT', t.ref + ' — ' + type);
  closeOutcomeModal();
  renderTribunals();
}

// ── Appeals ──
function fileAppeal(id) {
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t || !appealAllowed(t)) { alert('This verdict is not currently open to appeal.'); return; }
  openReasonModal('Grounds for appeal', async function(reason){
    if (!reason) return;
    t.status = 'Appealed';
    t.appeal = { submittedBy: currentUser.id, submittedAt: Date.now(), reason: reason, escalatedToRole: nextEcRole(t.judgeRole), priorOutcome: t.outcome, priorJudge: { id: t.judgeId, name: t.judgeName, role: t.judgeRole } };
    try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
    if (typeof auditRecord === 'function') auditRecord('TRIBUNAL APPEALED', t.ref + ' → ' + (t.appeal.escalatedToRole || 'review'));
    renderTribunals();
  });
}
async function takeAppeal(id) {
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t || t.status !== 'Appealed' || !t.appeal) return;
  var need = t.appeal.escalatedToRole;
  if (!isEthicsPersonnel() || ecRoleRank(ecRoleOf(currentUser)) < ecRoleRank(need)) {
    alert('This appeal must be presided over by a ' + need + ' or higher.'); return;
  }
  t.status = 'Accepted';
  t.judgeId = currentUser.id; t.judgeName = ecFileName(currentUser); t.judgeRole = ecRoleOf(currentUser);
  t.hearingDate = null; t.outcome = null; t.isAppealHearing = true;
  (t.thread = t.thread || []).push({ author: ecFileName(currentUser), text: 'Appeal accepted. Re-hearing to be scheduled.', created: Date.now() });
  try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('TRIBUNAL APPEAL TAKEN', t.ref + ' — ' + t.judgeName);
  renderTribunals();
}
async function deleteTribunal(id) {
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t) return;
  var allowed = isTribunalJudge(t) || (currentUser && parseInt(currentUser.clearance) >= 5) || (currentUser && t.submittedBy === currentUser.id && t.status === 'Submitted');
  if (!allowed) { alert('You do not have authority to remove this tribunal.'); return; }
  if (!await pfConfirm('Move this tribunal to the recycle bin?\n\n' + (t.ref || ''))) return;
  t.deleted = true; t.deletedBy = currentUser.id; t.deletedAt = Date.now();
  try { await tribunalSet(id, t); } catch(e){ alert('ERROR: ' + e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('DELETED TRIBUNAL', (t.ref || id) + ' → recycle bin');
  allTribunals = allTribunals.filter(function(x){ return x.id !== id; });
  if (!deletedTribunals.some(function(x){ return x.id === id; })) deletedTribunals.push(t);
  if (typeof toastUndo==='function') toastUndo('✓ TRIBUNAL DELETED', function(){ undoSoftDelete('tribunal', id); });
  renderTribunals();
}

// ── Shared reason modal ──
function openReasonModal(title, cb) {
  _reasonCb = cb;
  document.getElementById('tribReasonTitle').textContent = title;
  document.getElementById('tribReasonInput').value = '';
  document.getElementById('tribReasonModal').classList.add('open');
}
function closeReasonModal() { document.getElementById('tribReasonModal').classList.remove('open'); _reasonCb = null; }
function submitReasonModal() {
  var v = document.getElementById('tribReasonInput').value.trim();
  var cb = _reasonCb;
  document.getElementById('tribReasonModal').classList.remove('open'); _reasonCb = null;
  if (cb) cb(v);
}

// ── Export (Foundation document, in the directive style) ──
function exportTribunal(id) {
  var t = allTribunals.find(function(x){ return x.id === id; });
  if (!t) return;
  if (t.status === 'Submitted' || t.status === 'Denied') { alert('A tribunal can be exported once it has been accepted.'); return; }
  var html = buildTribunalDocument(t);
  var safeName = (t.ref + '_' + ((t.defendant && t.defendant.name) || 'tribunal')).replace(/[^A-Za-z0-9_-]/g, '_');
  downloadFile(safeName + '.html', html, 'text/html');
  if (typeof auditRecord === 'function') auditRecord('EXPORTED TRIBUNAL', t.ref);
}
function buildTribunalDocument(t) {
  var d = t.defendant || {};
  var ref = t.ref || 'EC-TRIB';
  var chargesHtml = (t.charges || []).length
    ? '<ol style="margin:0 0 0 1.2rem;padding:0;">' + t.charges.map(function(c){ return '<li>' + escHtml(c) + '</li>'; }).join('') + '</ol>'
    : '<p style="color:#777;font-style:italic;">[ No charges recorded. ]</p>';
  var prosHtml = 'Lead Counsel (Internal Security Department): <strong>' + escHtml((t.leadCounsel && t.leadCounsel.name) || '—') + '</strong>'
    + ((t.prosecutors || []).length ? '<br>Co-counsel: ' + t.prosecutors.map(function(p){ return escHtml(p.name || p); }).join(', ') : '');
  var witHtml = (t.witnesses || []).length ? t.witnesses.map(function(w){ return escHtml(w); }).join('; ') : '[ none ]';
  var verdictHtml = t.outcome
    ? '<div class="secttl">Verdict</div><p>' + escHtml(outcomeText(t.outcome)) + '</p>'
    : '';
  var hearing = t.hearingDate ? safeDateTime(t.hearingDate) + ' UTC' : 'To be scheduled';
  var statusU = (t.status || '').toUpperCase();

  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>'
    + '<meta name="viewport" content="width=device-width, initial-scale=1"/>'
    + '<title>' + escHtml(ref) + ' — TRIBUNAL</title>'
    + '<style>'
    + '@page{size:A4;margin:18mm 16mm;}*{box-sizing:border-box;}'
    + 'body{font-family:"Times New Roman",Georgia,serif;color:#111;background:#525659;margin:0;padding:24px;line-height:1.55;}'
    + '.page{background:#fff;max-width:780px;margin:0 auto 24px;padding:46px 54px 40px;box-shadow:0 2px 18px rgba(0,0,0,.4);position:relative;}'
    + '.runhead{display:flex;justify-content:space-between;font-family:"Courier New",monospace;font-size:8.5px;letter-spacing:.04em;color:#444;border-bottom:1px solid #000;padding-bottom:4px;margin-bottom:2px;text-transform:uppercase;}'
    + '.classbar{background:#1a1a1a;color:#fff;font-family:"Courier New",monospace;font-size:9px;letter-spacing:.14em;text-align:center;padding:5px 4px;margin:0 -54px 4px;font-weight:bold;}'
    + '.scp-tag{text-align:center;font-family:"Courier New",monospace;font-size:9px;letter-spacing:.42em;color:#222;margin:10px 0 18px;font-weight:bold;}'
    + '.lh{text-align:center;border-bottom:2px solid #000;padding-bottom:12px;margin-bottom:16px;}'
    + '.lh .org{font-size:21px;font-weight:bold;letter-spacing:.06em;}.lh .sub{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#333;margin-top:3px;}.lh .div{font-size:10px;letter-spacing:.1em;color:#555;margin-top:6px;font-style:italic;}'
    + '.doctype{text-align:center;font-size:13px;font-weight:bold;letter-spacing:.16em;margin:14px 0 16px;text-transform:uppercase;}'
    + 'table.meta{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:18px;}table.meta td{border:1px solid #999;padding:4px 8px;vertical-align:top;}'
    + 'table.meta td.k{background:#ededed;font-family:"Courier New",monospace;font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:#333;width:34%;font-weight:bold;}table.meta td.v{font-weight:bold;}'
    + '.secttl{font-size:11px;font-weight:bold;letter-spacing:.14em;text-transform:uppercase;border-bottom:1px solid #000;padding-bottom:3px;margin:20px 0 8px;}'
    + '.body p{font-size:12px;margin:0 0 10px;}'
    + '.stampbox{position:absolute;top:120px;right:40px;border:3px double #7a0000;color:#7a0000;font-family:"Courier New",monospace;font-weight:bold;font-size:12px;letter-spacing:.08em;padding:6px 12px;transform:rotate(-9deg);opacity:.82;}'
    + '.stampbox.ok{border-color:#0a5a23;color:#0a5a23;}'
    + '.footer{margin-top:26px;border-top:1px solid #000;padding-top:6px;font-family:"Courier New",monospace;font-size:8px;letter-spacing:.06em;color:#444;text-align:center;text-transform:uppercase;}'
    + '.redact{background:#000;color:#000;padding:0 .5em;}'
    + '@media print{body{background:#fff;padding:0;}.page{box-shadow:none;margin:0;max-width:none;padding:0;}.classbar{margin:0 0 4px;}}'
    + '</style></head><body><div class="page">'
    + '<div class="runhead"><span>SCP FOUNDATION · ETHICS COMMITTEE</span><span>TRIBUNAL ' + escHtml(ref) + ' · LEVEL 4-A</span></div>'
    + '<div class="classbar">LEVEL 4-A // ETHICS COMMITTEE JUDICIAL PROCEEDING // DESIGNATED RECIPIENTS ONLY</div>'
    + '<div class="scp-tag">SECURE · CONTAIN · PROTECT</div>'
    + '<div class="lh"><div class="org">SCP FOUNDATION</div><div class="sub">Ethics Committee &mdash; Judicial Division</div><div class="div">CAIRO.AIC Oversight Terminal · O5 Liaison Division</div></div>'
    + '<div class="doctype">Notice of Tribunal</div>'
    + '<div class="stampbox ' + (t.status === 'Concluded' ? 'ok' : '') + '">' + escHtml(statusU) + '</div>'
    + '<table class="meta">'
    +   '<tr><td class="k">Tribunal Reference</td><td class="v">' + escHtml(ref) + '</td></tr>'
    +   '<tr><td class="k">Defendant</td><td class="v">' + escHtml((d.rank ? d.rank + ' ' : '') + (d.name || '—')) + '</td></tr>'
    +   '<tr><td class="k">Department</td><td class="v">' + escHtml(d.department || '—') + '</td></tr>'
    +   '<tr><td class="k">Presiding Judge</td><td class="v">' + escHtml(t.judgeName || '—') + (t.judgeRole ? ' (' + escHtml(t.judgeRole) + ')' : '') + '</td></tr>'
    +   '<tr><td class="k">Hearing</td><td class="v">' + escHtml(hearing) + '</td></tr>'
    +   '<tr><td class="k">Status</td><td class="v">' + escHtml(statusU) + '</td></tr>'
    + '</table>'
    + '<div class="secttl">FLC Charges</div><div class="body">' + chargesHtml + '</div>'
    + '<div class="secttl">Prosecution</div><div class="body"><p>' + prosHtml + '</p></div>'
    + '<div class="secttl">Witnesses</div><div class="body"><p>' + witHtml + '</p></div>'
    + verdictHtml
    + '<div class="footer">CONFIDENTIAL // LEVEL 4-A // ' + escHtml(ref) + ' // GENERATED ' + escHtml(safeDateTime(Date.now())) + ' UTC // CAIRO.AIC</div>'
    + '</div></body></html>';
}

// ── Admin config (appeal window) ──
function renderTribunalCfgAdmin() {
  var el = document.getElementById('adminTribunalCfg');
  if (!el) return;
  var isCL5 = currentUser && parseInt(currentUser.clearance) >= 5;
  var dis = isCL5 ? '' : 'disabled';
  el.innerHTML = '<label style="display:flex;align-items:center;gap:.4rem;">Appeal window (days) '
    + '<input type="number" min="0" step="1" id="tribAppealDays" value="' + e(appealWindowDays()) + '" ' + dis + ' style="width:60px;background:var(--bg);border:1px solid var(--border2);color:var(--amber);padding:.2rem .4rem;font-family:inherit;"/></label>'
    + (isCL5 ? '<button class="modal-save" data-action="save-tribunal-cfg" style="font-size:.6rem;margin-top:.4rem;">[ SAVE ]</button>' : '<div style="font-size:.52rem;color:var(--text-faint);">CL5 required to edit.</div>');
}
async function saveTribunalCfg() {
  if (!(currentUser && parseInt(currentUser.clearance) >= 5)) return;
  var v = parseInt(document.getElementById('tribAppealDays').value);
  if (isNaN(v) || v < 0) { alert('Enter a valid number of days.'); return; }
  tribunalConfig.appealWindowDays = v;
  try { await tribunalConfigSave(); } catch(e){ alert('ERROR: ' + e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('UPDATED TRIBUNAL CONFIG', 'appeal window = ' + v + ' days');
  renderTribunalCfgAdmin();
}

// ================================================================
//  ETHICS COMMITTEE — CONFIDENTIAL INTELLIGENCE NETWORK (EYES ONLY)
//  The committee's covert apparatus: a registry of codenamed sources
//  embedded across the Foundation, run by EC handlers, and the field
//  reports they file. Reports carry the NATO Admiralty rating (source
//  reliability A–F + information credibility 1–6) and can escalate
//  directly into an Ethics case.
//  Firebase paths: /informants/{id}  ·  /intelReports/{id}
// ================================================================
var SRC_RELIABILITY = ['A','B','C','D','E','F'];
var SRC_RELIABILITY_LABEL = { A:'Completely reliable', B:'Usually reliable', C:'Fairly reliable', D:'Not usually reliable', E:'Unreliable', F:'Cannot be judged' };
var INFO_CREDIBILITY = ['1','2','3','4','5','6'];
var INFO_CREDIBILITY_LABEL = { '1':'Confirmed', '2':'Probably true', '3':'Possibly true', '4':'Doubtful', '5':'Improbable', '6':'Cannot be judged' };
var SRC_STATUSES = ['Active','Dormant','Burned','Terminated'];
var INTEL_CATEGORIES = ['Misconduct','Security Risk','Containment Concern','Disloyalty','Corruption','Insubordination','Other'];
var INTEL_REPORT_STATUSES = ['New','Reviewed','Actioned','Archived'];

var allInformants = [], deletedInformants = [];
var allIntelReports = [], deletedIntelReports = [];
var _intelView = 'sources';

async function informantsGetAll() {
  if (firebaseReady) { var a = await fbGetAll('/informants'); return a ? Object.values(a) : []; }
  return Object.values(lsAll('informants/'));
}
async function informantSet(id, data) { if (firebaseReady) await fbSet('/informants/' + id, data); else lsSet('informants/' + id, data); }
async function informantDel(id) { if (firebaseReady) await fbDelete('/informants/' + id); else lsDel('informants/' + id); }
async function intelReportsGetAll() {
  if (firebaseReady) { var a = await fbGetAll('/intelReports'); return a ? Object.values(a) : []; }
  return Object.values(lsAll('intelReports/'));
}
async function intelReportSet(id, data) { if (firebaseReady) await fbSet('/intelReports/' + id, data); else lsSet('intelReports/' + id, data); }
async function intelReportDel(id) { if (firebaseReady) await fbDelete('/intelReports/' + id); else lsDel('intelReports/' + id); }

// EC personnel (any role) or CL5 command may access the intel network.
function canAccessIntel() {
  if (!currentUser) return false;
  return isEthicsPersonnel() || parseInt(currentUser.clearance) >= 5;
}
// Omega-1 intel is a separate compartment: command tier (CL4+) or Overseer.
function canAccessO1Intel() {
  if (!currentUser) return false;
  return parseInt(currentUser.clearance) >= 4;
}
var _intelOrg = 'ec';
function intelOrgCanAccess() { return _intelOrg === 'o1' ? canAccessO1Intel() : canAccessIntel(); }
function orgMatch(rec) { return rec && (rec.org || 'ec') === _intelOrg; }
// Visible if in this compartment AND the viewer holds any need-to-know grant on the record.
function intelVisible(rec) { return orgMatch(rec) && userHasCompartment(rec && rec.compartment); }
function intelEls() {
  return _intelOrg === 'o1' ? {
    notice:'o1IntelAccessNotice', body:'o1IntelBody', count:'o1IntelCount',
    srcSearch:'o1SrcSearch', srcFilter:'o1SrcFilterStatus', srcList:'o1InformantList',
    repSearch:'o1RepSearch', repFilter:'o1RepFilterStatus', repList:'o1IntelReportList',
    watchList:'o1WatchlistList',
    segS:'o1SegSources', segR:'o1SegReports', segW:'o1SegWatchlist',
    sV:'o1IntelSourcesView', rV:'o1IntelReportsView', wV:'o1IntelWatchlistView'
  } : {
    notice:'intelAccessNotice', body:'intelBody', count:'intelCount',
    srcSearch:'srcSearch', srcFilter:'srcFilterStatus', srcList:'informantList',
    repSearch:'repSearch', repFilter:'repFilterStatus', repList:'intelReportList',
    watchList:'watchlistList',
    segS:'segSources', segR:'segReports', segW:'segWatchlist',
    sV:'intelSourcesView', rV:'intelReportsView', wV:'intelWatchlistView'
  };
}
function canManageIntel(rec) {
  if (!intelOrgCanAccess()) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  return !rec || rec.createdBy === currentUser.id;
}

// Reveal each INTEL nav tab only to those cleared for that compartment.
function refreshIntelNav() {
  var ec = document.getElementById('navIntelTab');
  if (ec) ec.style.display = canAccessIntel() ? '' : 'none';
  var o1 = document.getElementById('navO1IntelTab');
  if (o1) o1.style.display = canAccessO1Intel() ? '' : 'none';
}

function informantName(id) {
  var s = (allInformants || []).find(function(x){ return x.id === id; });
  return s ? s.codename : '[unknown source]';
}

async function loadIntel(org) {
  if (org) _intelOrg = org;
  var els = intelEls();
  var notice = document.getElementById(els.notice);
  var body = document.getElementById(els.body);
  if (!intelOrgCanAccess()) {
    if (notice) { notice.style.display = 'block'; notice.textContent = _intelOrg === 'o1'
      ? 'ACCESS DENIED — Omega-1 intelligence is restricted to command (Level 4+).'
      : 'ACCESS DENIED — This terminal is restricted to Ethics Committee personnel.'; }
    if (body) body.style.display = 'none';
    return;
  }
  if (notice) notice.style.display = 'none';
  if (body) body.style.display = 'block';
  try {
    var rawS = await informantsGetAll();
    allInformants = partitionDeleted(rawS.filter(function(x){ return x && x.id; }), function(d){ deletedInformants = d; });
    var rawR = await intelReportsGetAll();
    allIntelReports = partitionDeleted(rawR.filter(function(x){ return x && x.id; }), function(d){ deletedIntelReports = d; });
  } catch(e) { allInformants = allInformants || []; allIntelReports = allIntelReports || []; }
  allInformants.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
  allIntelReports.sort(function(a,b){ return (b.filedAt||0)-(a.filedAt||0); });
  await loadSurveillance();
  if (_intelView === 'watchlist' && _intelOrg === 'o1') _intelView = 'sources';
  setIntelView(_intelView);
}

function setIntelView(view) {
  _intelView = view;
  var els = intelEls();
  var sv = document.getElementById(els.sV), rv = document.getElementById(els.rV), wv = document.getElementById(els.wV);
  var sb = document.getElementById(els.segS), rb = document.getElementById(els.segR), wb = document.getElementById(els.segW);
  if (sv) sv.style.display = view === 'sources' ? 'block' : 'none';
  if (rv) rv.style.display = view === 'reports' ? 'block' : 'none';
  if (wv) wv.style.display = view === 'watchlist' ? 'block' : 'none';
  if (sb) sb.classList.toggle('on', view === 'sources');
  if (rb) rb.classList.toggle('on', view === 'reports');
  if (wb) wb.classList.toggle('on', view === 'watchlist');
  if (view === 'sources') renderInformants();
  else if (view === 'watchlist') renderWatchlist();
  else renderIntelReports();
}

// Watchlist: every file currently under EC observation, with report counts.
function subjectName(sys, pfId) {
  var pool = (sys === 'ef') ? (typeof allEthicsPersonnel !== 'undefined' ? allEthicsPersonnel : []) : (allPersonnel || []);
  var p = pool.find(function(x){ return x.id === pfId; });
  return p ? (p.name || p.nickname || pfId) : '[file ' + pfId + ']';
}
function renderWatchlist() {
  var els = intelEls();
  var list = document.getElementById(els.watchList);
  if (!list) return;
  var rows = (allSurveillance || []).filter(function(s){ return s && s.active !== false; })
    .sort(function(a,b){ var ord={Priority:0,Elevated:1,Routine:2}; return (ord[a.level]||3)-(ord[b.level]||3); });
  var cnt = document.getElementById(els.count);
  if (cnt && _intelView === 'watchlist') cnt.textContent = rows.length ? '(' + rows.length + ' watched)' : '';
  if (!rows.length) { list.innerHTML = '<div class="trn-empty">NO SUBJECTS UNDER OBSERVATION.</div>'; return; }
  list.innerHTML = rows.map(function(s){
    var reports = reportsForSubject(s.sys, s.pfId).length;
    return '<div class="case-card"><div class="case-top"><div>'
      + '<div class="case-title"><span class="person-link" data-action="open-intel-file" data-pfid="' + e(s.pfId) + '" data-sys="' + e(s.sys||'pf') + '">' + e(subjectName(s.sys, s.pfId)) + '</span></div>'
      + '<div class="case-badges" style="margin-top:4px;"><span class="badge ' + svLevelBadge(s.level) + '">' + e((s.level||'Routine').toUpperCase()) + '</span>'
      + '<span class="badge b-dim">' + (s.sys === 'ef' ? 'EC' : 'Ω1') + '</span>'
      + '<span class="badge b-dim">' + reports + ' report' + (reports===1?'':'s') + '</span></div></div>'
      + '<div style="display:flex;gap:.35rem;"><button class="pf-section-btn" data-action="adjust-surveillance" data-sys="' + e(s.sys||'pf') + '" data-pfid="' + e(s.pfId) + '" style="font-size:.52rem;padding:1px 7px;">ADJUST</button>'
      + '<button class="pf-section-btn" data-action="lift-surveillance" data-sys="' + e(s.sys||'pf') + '" data-pfid="' + e(s.pfId) + '" style="font-size:.52rem;padding:1px 7px;color:#dd6666;">LIFT</button></div></div>'
      + (s.reason ? '<div class="case-block"><span class="lbl">Grounds</span><span class="txt">' + e(s.reason) + '</span></div>' : '')
      + '</div>';
  }).join('');
}

// ── Sources ──
function srcStatusBadge(s) { return s === 'Active' ? 'b-green' : s === 'Dormant' ? 'b-amber' : s === 'Burned' ? 'b-red' : 'b-retired'; }

function renderInformants() {
  var els = intelEls();
  var list = document.getElementById(els.srcList);
  if (!list) return;
  var q = ((document.getElementById(els.srcSearch)||{}).value||'').trim().toLowerCase();
  var f = (document.getElementById(els.srcFilter)||{}).value||'';
  var rows = allInformants.filter(function(s){
    if (!intelVisible(s)) return false;
    if (f && (s.status||'Active') !== f) return false;
    if (!q) return true;
    return [s.codename, s.department, s.coverRole, s.handlerName, s.notes].join(' ').toLowerCase().indexOf(q) !== -1;
  });
  var cnt = document.getElementById(els.count);
  if (cnt && _intelView === 'sources') cnt.textContent = rows.length ? '(' + rows.length + ' sources)' : '';
  if (!rows.length) { list.innerHTML = '<div class="trn-empty">NO SOURCES' + (q||f?' MATCH THE FILTER.':' ON THE NETWORK YET.') + '</div>'; return; }
  list.innerHTML = rows.map(buildInformantCard).join('');
}

function buildInformantCard(s) {
  var status = s.status || 'Active';
  var rel = s.reliability || 'F';
  var reports = allIntelReports.filter(function(r){ return r.sourceId === s.id; }).length;
  var manage = canManageIntel(s)
    ? '<div style="display:flex;gap:.35rem;">'
      + '<button class="pf-section-btn" data-action="edit-informant" data-id="' + e(s.id) + '" style="font-size:.52rem;padding:1px 7px;">EDIT</button>'
      + '<button class="pf-section-btn" data-action="delete-informant" data-id="' + e(s.id) + '" style="font-size:.52rem;padding:1px 7px;color:#dd6666;">DELETE</button></div>'
    : '';
  var realLink = s.realPfId
    ? '<div class="case-block"><span class="lbl">True identity</span><span class="txt"><span class="person-link" data-action="open-intel-file" data-pfid="' + e(s.realPfId) + '" data-sys="' + e(s.realSys||'pf') + '">' + e(s.realName || '[linked file]') + '</span></span></div>'
    : '';
  return '<div class="case-card">'
    + '<div class="case-top"><div><div class="src-codename">' + e(s.codename || 'UNNAMED') + '</div>'
    + '<div class="case-badges" style="margin-top:5px;"><span class="badge ' + srcStatusBadge(status) + '">' + e(status.toUpperCase()) + '</span>'
    + '<span class="rel-badge rel-' + e(rel) + '">REL ' + e(rel) + '</span>'
    + (s.department ? '<span class="badge b-dim">' + e(s.department) + '</span>' : '') + '</div></div>' + manage + '</div>'
    + (s.coverRole ? '<div class="case-block"><span class="lbl">Cover</span><span class="txt">' + e(s.coverRole) + '</span></div>' : '')
    + '<div class="case-block"><span class="lbl">Handler</span><span class="txt">' + e(s.handlerName || '—') + '</span></div>'
    + realLink
    + (s.notes ? '<div class="case-block"><span class="lbl">Handler notes</span><span class="txt">' + e(s.notes) + '</span></div>' : '')
    + '<div class="case-vote"><span class="vote-tally">' + reports + ' report' + (reports===1?'':'s') + ' on file'
    + (s.lastContact ? ' · last contact ' + e(safeDate(s.lastContact)) : '') + '</span>'
    + '<button class="vote-btn" data-action="file-from-source" data-id="' + e(s.id) + '">+ FILE REPORT</button></div>'
    + '</div>';
}

function openInformantModal(id) {
  if (!intelOrgCanAccess()) { alert('Compartment access required.'); return; }
  var editing = !!id;
  var s = editing ? allInformants.find(function(x){ return x.id === id; }) : null;
  if (editing && !canManageIntel(s)) { alert('Only the handler or command may edit this source.'); return; }
  document.getElementById('informantModalTitle').textContent = editing ? 'EDIT SOURCE' : 'RECRUIT CONFIDENTIAL SOURCE';
  document.getElementById('informantEditId').value = id || '';
  document.getElementById('srcErr').style.display = 'none';
  document.getElementById('srcReliability').innerHTML = SRC_RELIABILITY.map(function(r){ return '<option value="' + r + '">' + r + ' — ' + e(SRC_RELIABILITY_LABEL[r]) + '</option>'; }).join('');
  document.getElementById('srcStatus').innerHTML = SRC_STATUSES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  // Handler picker = personnel of the active compartment's organisation
  var handlerPool = _intelOrg === 'o1' ? (allPersonnel||[]) : (typeof allEthicsPersonnel!=='undefined'?allEthicsPersonnel:[]);
  var handlerOpts = '<option value="">— select handler —</option>' + handlerPool.map(function(p){ return '<option value="' + e(p.id) + '">' + e(p.name||p.id) + (p.role?' ('+e(p.role)+')':'') + (p.rank?' ('+e(p.rank)+')':'') + '</option>'; }).join('');
  document.getElementById('srcHandler').innerHTML = handlerOpts;
  // True-identity picker = all personnel (both pools)
  var idOpts = '<option value="">— unlinked —</option>'
    + (allPersonnel||[]).map(function(p){ return '<option value="pf:' + e(p.id) + '">Ω1 · ' + e(p.name||p.id) + '</option>'; }).join('')
    + (typeof allEthicsPersonnel!=='undefined'?allEthicsPersonnel:[]).map(function(p){ return '<option value="ef:' + e(p.id) + '">EC · ' + e(p.name||p.id) + '</option>'; }).join('');
  document.getElementById('srcRealId').innerHTML = idOpts;
  if (typeof populateCompartmentSelect === 'function') populateCompartmentSelect('srcCompartment', s ? (s.compartment||'') : '');

  document.getElementById('srcCodename').value = s ? (s.codename||'') : '';
  document.getElementById('srcReliability').value = s ? (s.reliability||'C') : 'C';
  document.getElementById('srcDept').value = s ? (s.department||'') : '';
  document.getElementById('srcStatus').value = s ? (s.status||'Active') : 'Active';
  document.getElementById('srcCover').value = s ? (s.coverRole||'') : '';
  document.getElementById('srcHandler').value = s ? (s.handlerId||'') : (_intelOrg === 'o1' ? (currentUser.linkedPfId||'') : (currentUser.linkedEfId||''));
  document.getElementById('srcLastContact').value = s ? (s.lastContact||'') : '';
  document.getElementById('srcRealId').value = s && s.realPfId ? ((s.realSys||'pf')+':'+s.realPfId) : '';
  document.getElementById('srcNotes').value = s ? (s.notes||'') : '';
  document.getElementById('informantModal').classList.add('open');
}
function closeInformantModal() { document.getElementById('informantModal').classList.remove('open'); }

async function saveInformant() {
  var codename = document.getElementById('srcCodename').value.trim();
  var errEl = document.getElementById('srcErr');
  function fail(m){ errEl.textContent = m; errEl.style.display = 'block'; }
  if (!codename) { fail('A codename is required.'); return; }
  var editId = document.getElementById('informantEditId').value;
  var existing = editId ? allInformants.find(function(x){ return x.id === editId; }) : null;
  if (editId && !canManageIntel(existing)) { fail('You may not edit this source.'); return; }

  var handlerId = document.getElementById('srcHandler').value;
  var handlerPool = (existing ? (existing.org==='o1') : (_intelOrg==='o1')) ? (allPersonnel||[]) : (typeof allEthicsPersonnel!=='undefined'?allEthicsPersonnel:[]);
  var handlerName = handlerId ? ((handlerPool.find(function(p){return p.id===handlerId;})||{}).name || handlerId) : '';
  var realVal = document.getElementById('srcRealId').value;
  var realSys = realVal ? realVal.slice(0,2) : '';
  var realId = realVal ? realVal.slice(3) : '';
  var realName = '';
  if (realId) {
    var pool = realSys==='ef' ? (typeof allEthicsPersonnel!=='undefined'?allEthicsPersonnel:[]) : (allPersonnel||[]);
    var pr = pool.find(function(p){ return p.id===realId; });
    realName = pr ? (pr.name||realId) : realId;
  }
  var btn = document.getElementById('srcSaveBtn'); if (btn){ btn.disabled=true; btn.textContent='[ SAVING... ]'; }
  var s;
  if (existing) {
    s = existing;
  } else {
    s = { id: 'src_' + Date.now() + '_' + Math.random().toString(36).slice(2,5), org: _intelOrg, createdBy: currentUser.id, createdAt: Date.now(), deleted: false };
  }
  if (!s.org) s.org = _intelOrg;
  s.compartment = (document.getElementById('srcCompartment')||{}).value || null;
  s.codename = codename;
  s.reliability = document.getElementById('srcReliability').value;
  s.department = document.getElementById('srcDept').value.trim();
  s.status = document.getElementById('srcStatus').value;
  s.coverRole = document.getElementById('srcCover').value.trim();
  s.handlerId = handlerId; s.handlerName = handlerName;
  s.lastContact = document.getElementById('srcLastContact').value || '';
  s.realPfId = realId || null; s.realSys = realId ? realSys : null; s.realName = realId ? realName : null;
  s.notes = document.getElementById('srcNotes').value.trim();
  s.updatedAt = Date.now();
  try { await informantSet(s.id, s); }
  catch(err){ if(btn){btn.disabled=false;btn.textContent='[ SAVE SOURCE ]';} fail('SAVE ERROR: '+err.message); return; }
  if (typeof auditRecord === 'function') auditRecord(existing?'EDITED SOURCE':'RECRUITED SOURCE', 'codename ' + codename);
  if (btn){ btn.disabled=false; btn.textContent='[ SAVE SOURCE ]'; }
  closeInformantModal();
  if (typeof toast==='function') toast('✓ SOURCE SAVED');
  await loadIntel();
}
async function deleteInformant(id) {
  var s = allInformants.find(function(x){ return x.id === id; });
  if (!canManageIntel(s)) { alert('You may not remove this source.'); return; }
  if (!await pfConfirm('Move source ' + (s?s.codename:'') + ' to the recycle bin?')) return;
  s.deleted = true; s.deletedBy = currentUser.id; s.deletedAt = Date.now();
  try { await informantSet(id, s); } catch(e){ alert('ERROR: '+e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('DELETED SOURCE', (s.codename||id) + ' → recycle bin');
  allInformants = allInformants.filter(function(x){ return x.id !== id; });
  if (!deletedInformants.some(function(x){ return x.id===id; })) deletedInformants.push(s);
  if (typeof toastUndo==='function') toastUndo('✓ SOURCE DELETED', function(){ undoSoftDelete('informant', id); });
  renderInformants();
}

// ── Field reports ──
function repStatusBadge(s) { return s === 'Actioned' ? 'b-green' : s === 'Reviewed' ? 'b-cyan' : s === 'Archived' ? 'b-retired' : 'b-amber'; }

function nextIntelRef() {
  var yy = new Date().getFullYear().toString().slice(-2);
  var prefix = 'INTEL-' + yy + '-';
  var maxN = 0;
  allIntelReports.concat(deletedIntelReports).forEach(function(r){
    if (r.ref && r.ref.indexOf(prefix)===0){ var n=parseInt(r.ref.slice(prefix.length),10); if(!isNaN(n)&&n>maxN) maxN=n; }
  });
  return prefix + String(maxN+1).padStart(3,'0');
}

function renderIntelReports() {
  var els = intelEls();
  var list = document.getElementById(els.repList);
  if (!list) return;
  var q = ((document.getElementById(els.repSearch)||{}).value||'').trim().toLowerCase();
  var f = (document.getElementById(els.repFilter)||{}).value||'';
  var rows = allIntelReports.filter(function(r){
    if (!intelVisible(r)) return false;
    if (f && (r.status||'New') !== f) return false;
    if (!q) return true;
    return [r.ref, r.content, r.category, informantName(r.sourceId), r.subjectName].join(' ').toLowerCase().indexOf(q) !== -1;
  });
  var cnt = document.getElementById(els.count);
  if (cnt && _intelView === 'reports') cnt.textContent = rows.length ? '(' + rows.length + ' reports)' : '';
  if (!rows.length) { list.innerHTML = '<div class="trn-empty">NO REPORTS' + (q||f?' MATCH THE FILTER.':' FILED YET.') + '</div>'; return; }
  list.innerHTML = rows.map(buildIntelReportCard).join('');
}

function buildIntelReportCard(r) {
  var status = r.status || 'New';
  var rel = r.reliability || 'F', cred = r.credibility || '6';
  var manage = canManageIntel(r)
    ? '<div style="display:flex;gap:.35rem;">'
      + '<button class="pf-section-btn" data-action="edit-intel-report" data-id="' + e(r.id) + '" style="font-size:.52rem;padding:1px 7px;">EDIT</button>'
      + '<button class="pf-section-btn" data-action="delete-intel-report" data-id="' + e(r.id) + '" style="font-size:.52rem;padding:1px 7px;color:#dd6666;">DELETE</button></div>'
    : '';
  var subject = r.subjectId
    ? '<div class="case-block"><span class="lbl">Subject</span><span class="txt"><span class="person-link" data-action="open-intel-file" data-pfid="' + e(r.subjectId) + '" data-sys="' + e(r.subjectSys||'pf') + '">' + e(r.subjectName||'[linked file]') + '</span></span></div>'
    : '';
  var escalate = canManageIntel(r)
    ? '<button class="vote-btn" data-action="escalate-report" data-id="' + e(r.id) + '" style="border-color:var(--amber);color:var(--amber);">⮞ ESCALATE TO CASE</button>'
    : '';
  return '<div class="case-card">'
    + '<div class="case-top"><div><div class="case-ref">' + e(r.ref||'—') + ' · ' + e((r.category||'').toUpperCase()) + '</div>'
    + '<div class="case-title" style="font-size:.72rem;">SOURCE <span class="src-codename" style="font-size:.72rem;">' + e(informantName(r.sourceId)) + '</span></div>'
    + '<div class="case-badges" style="margin-top:5px;"><span class="badge ' + repStatusBadge(status) + '">' + e(status.toUpperCase()) + '</span>'
    + '<span class="rel-badge rel-' + e(rel) + '" title="Admiralty rating">' + e(rel) + e(cred) + '</span></div></div>' + manage + '</div>'
    + subject
    + '<div class="case-block"><span class="lbl">Intelligence</span><span class="txt">' + e(r.content||'') + '</span></div>'
    + '<div class="case-vote"><span class="vote-tally">FILED ' + e(safeDate(r.filedAt)) + ' · ' + (r.org==='o1'?'Ω1·':'EC·') + e(r.filedBy||'—')
    + ' · rating ' + e(rel) + e(cred) + ' (' + e(SRC_RELIABILITY_LABEL[rel]||'?') + ' / ' + e(INFO_CREDIBILITY_LABEL[cred]||'?') + ')</span>' + escalate + '</div>'
    + '</div>';
}

function syncReportReliability() {
  var srcId = document.getElementById('repSource').value;
  var s = allInformants.find(function(x){ return x.id === srcId; });
  if (s && s.reliability) document.getElementById('repReliability').value = s.reliability;
}

function openIntelReportModal(id, presetSourceId) {
  if (!intelOrgCanAccess()) { alert('Compartment access required.'); return; }
  var editing = !!id;
  var r = editing ? allIntelReports.find(function(x){ return x.id === id; }) : null;
  if (editing && !canManageIntel(r)) { alert('You may not edit this report.'); return; }
  document.getElementById('intelReportModalTitle').textContent = editing ? 'EDIT FIELD REPORT' : 'FILE FIELD REPORT';
  document.getElementById('intelReportEditId').value = id || '';
  document.getElementById('repErr').style.display = 'none';
  document.getElementById('repRef').value = r ? (r.ref || nextIntelRef()) : nextIntelRef();
  document.getElementById('repSource').innerHTML = '<option value="">— select source —</option>' + allInformants.filter(orgMatch).map(function(s){ return '<option value="' + e(s.id) + '">' + e(s.codename) + ' (REL ' + e(s.reliability||'F') + ')</option>'; }).join('');
  document.getElementById('repCategory').innerHTML = INTEL_CATEGORIES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  document.getElementById('repReliability').innerHTML = SRC_RELIABILITY.map(function(x){ return '<option value="' + x + '">' + x + ' — ' + e(SRC_RELIABILITY_LABEL[x]) + '</option>'; }).join('');
  document.getElementById('repCredibility').innerHTML = INFO_CREDIBILITY.map(function(x){ return '<option value="' + x + '">' + x + ' — ' + e(INFO_CREDIBILITY_LABEL[x]) + '</option>'; }).join('');
  document.getElementById('repStatus').innerHTML = INTEL_REPORT_STATUSES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  var subjOpts = '<option value="">— no linked subject —</option>'
    + (allPersonnel||[]).map(function(p){ return '<option value="pf:' + e(p.id) + '">Ω1 · ' + e(p.name||p.id) + '</option>'; }).join('')
    + (typeof allEthicsPersonnel!=='undefined'?allEthicsPersonnel:[]).map(function(p){ return '<option value="ef:' + e(p.id) + '">EC · ' + e(p.name||p.id) + '</option>'; }).join('');
  document.getElementById('repSubject').innerHTML = subjOpts;
  if (typeof populateCompartmentSelect === 'function') populateCompartmentSelect('repCompartment', r ? (r.compartment||'') : '');

  document.getElementById('repSource').value = r ? (r.sourceId||'') : (presetSourceId||'');
  document.getElementById('repCategory').value = r ? (r.category||INTEL_CATEGORIES[0]) : INTEL_CATEGORIES[0];
  document.getElementById('repReliability').value = r ? (r.reliability||'C') : 'C';
  document.getElementById('repCredibility').value = r ? (r.credibility||'3') : '3';
  document.getElementById('repStatus').value = r ? (r.status||'New') : 'New';
  document.getElementById('repSubject').value = r && r.subjectId ? ((r.subjectSys||'pf')+':'+r.subjectId) : '';
  document.getElementById('repContent').value = r ? (r.content||'') : '';
  if (!editing && presetSourceId) syncReportReliability();
  document.getElementById('intelReportModal').classList.add('open');
}
function closeIntelReportModal() { document.getElementById('intelReportModal').classList.remove('open'); }

async function saveIntelReport() {
  var content = document.getElementById('repContent').value.trim();
  var sourceId = document.getElementById('repSource').value;
  var errEl = document.getElementById('repErr');
  function fail(m){ errEl.textContent = m; errEl.style.display = 'block'; }
  if (!sourceId) { fail('Select the reporting source.'); return; }
  if (!content) { fail('Enter the intelligence.'); return; }
  var editId = document.getElementById('intelReportEditId').value;
  var existing = editId ? allIntelReports.find(function(x){ return x.id === editId; }) : null;
  if (editId && !canManageIntel(existing)) { fail('You may not edit this report.'); return; }

  var subjVal = document.getElementById('repSubject').value;
  var subjSys = subjVal ? subjVal.slice(0,2) : '';
  var subjId = subjVal ? subjVal.slice(3) : '';
  var subjName = '';
  if (subjId) {
    var pool = subjSys==='ef' ? (typeof allEthicsPersonnel!=='undefined'?allEthicsPersonnel:[]) : (allPersonnel||[]);
    var sp = pool.find(function(p){ return p.id===subjId; });
    subjName = sp ? (sp.name||subjId) : subjId;
  }
  var btn = document.getElementById('repSaveBtn'); if (btn){ btn.disabled=true; btn.textContent='[ FILING... ]'; }
  var r;
  if (existing) { r = existing; }
  else { r = { id:'intel_'+Date.now()+'_'+Math.random().toString(36).slice(2,5), ref:document.getElementById('repRef').value||nextIntelRef(), org:_intelOrg, filedBy:currentUser.id, filedAt:Date.now(), deleted:false }; }
  if (!r.org) r.org = _intelOrg;
  r.compartment = (document.getElementById('repCompartment')||{}).value || null;
  r.sourceId = sourceId;
  r.category = document.getElementById('repCategory').value;
  r.reliability = document.getElementById('repReliability').value;
  r.credibility = document.getElementById('repCredibility').value;
  r.status = document.getElementById('repStatus').value;
  r.subjectId = subjId || null; r.subjectSys = subjId ? subjSys : null; r.subjectName = subjId ? subjName : null;
  r.content = content; r.updatedAt = Date.now();
  try { await intelReportSet(r.id, r); }
  catch(err){ if(btn){btn.disabled=false;btn.textContent='[ FILE REPORT ]';} fail('SAVE ERROR: '+err.message); return; }
  if (typeof auditRecord === 'function') auditRecord(existing?'EDITED INTEL REPORT':'FILED INTEL REPORT', r.ref);
  if (btn){ btn.disabled=false; btn.textContent='[ FILE REPORT ]'; }
  closeIntelReportModal();
  if (typeof toast==='function') toast('✓ REPORT FILED');
  await loadIntel();
}
async function deleteIntelReport(id) {
  var r = allIntelReports.find(function(x){ return x.id === id; });
  if (!canManageIntel(r)) { alert('You may not remove this report.'); return; }
  if (!await pfConfirm('Move report ' + (r?r.ref:'') + ' to the recycle bin?')) return;
  r.deleted = true; r.deletedBy = currentUser.id; r.deletedAt = Date.now();
  try { await intelReportSet(id, r); } catch(e){ alert('ERROR: '+e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('DELETED INTEL REPORT', (r.ref||id) + ' → recycle bin');
  allIntelReports = allIntelReports.filter(function(x){ return x.id !== id; });
  if (!deletedIntelReports.some(function(x){ return x.id===id; })) deletedIntelReports.push(r);
  if (typeof toastUndo==='function') toastUndo('✓ REPORT DELETED', function(){ undoSoftDelete('intelrep', id); });
  renderIntelReports();
}

// ── Connective tissue: escalate a report into an Ethics case ──
function escalateReportToCase(id) {
  var r = allIntelReports.find(function(x){ return x.id === id; });
  if (!r) return;
  if (typeof openCaseModal !== 'function') { alert('Case docket unavailable.'); return; }
  if (typeof canLogCase === 'function' && !canLogCase()) { alert('You need case-docket authority (EC member or CL5) to escalate.'); return; }
  openCaseModal(null);
  // Pre-fill from the intelligence
  var src = informantName(r.sourceId);
  document.getElementById('caseTitle').value = 'Intelligence review — ' + (r.subjectName || r.category || r.ref);
  document.getElementById('caseCategory').value = 'Personnel Conduct';
  document.getElementById('caseSummary').value = 'Escalated from field report ' + r.ref + ' (source ' + src + ', rating ' + (r.reliability||'') + (r.credibility||'') + ').\n\n' + (r.content||'');
  if (r.subjectId && typeof _caseLinked !== 'undefined') {
    _caseLinked = [{ id: r.subjectId, sys: r.subjectSys||'pf', name: r.subjectName||r.subjectId }];
    if (typeof renderCaseLinkList === 'function') renderCaseLinkList();
    if (typeof populateCaseLinkPicker === 'function') populateCaseLinkPicker();
  }
  // Mark the report actioned
  r.status = 'Actioned';
  intelReportSet(r.id, r);
}
function openIntelFile(pfId, sys) {
  if (typeof openFileFromCase === 'function') openFileFromCase(pfId, sys);
}

// ================================================================
//  OMEGA-1 — OPERATIONS / DEPLOYMENT LOG
//  The task force's operational record: deployments with objectives,
//  assigned operators, and after-action reports. Operations a member
//  led or served on surface on their personnel file's service record.
//  Firebase path: /operations/{id}
// ================================================================
var OP_TYPES      = ['Containment','Recovery','Escort','Investigation','Security Detail','Reconnaissance','Extraction','Suppression','Other'];
var OP_STATUSES   = ['Planned','Active','On Hold','Completed','Aborted'];
var OP_PRIORITIES = ['Routine','Elevated','Critical'];
var OP_OUTCOMES   = ['Success','Partial Success','Failure','N/A'];
var allOperations = [], deletedOperations = [];
var _opOperators  = [];

async function operationsGetAll() {
  if (firebaseReady) { var a = await fbGetAll('/operations'); return a ? Object.values(a) : []; }
  return Object.values(lsAll('operations/'));
}
async function operationSet(id, data) { if (firebaseReady) await fbSet('/operations/' + id, data); else lsSet('operations/' + id, data); }
async function operationDel(id) { if (firebaseReady) await fbDelete('/operations/' + id); else lsDel('operations/' + id); }

// Operations are a command function: CL4+ may log and manage them.
function canManageOp() { return currentUser && parseInt(currentUser.clearance) >= 4; }

function opName(id) {
  var p = (allPersonnel || []).find(function(x){ return x.id === id; });
  return p ? (p.name || p.nickname || id) : null;
}
function opStatusBadge(s) {
  return s === 'Active' ? 'b-green' : s === 'Completed' ? 'b-cyan'
    : s === 'Aborted' ? 'b-red' : s === 'On Hold' ? 'b-retired' : 'b-amber';
}
function opOutcomeBadge(o) {
  return o === 'Success' ? 'b-green' : o === 'Failure' ? 'b-red' : o === 'Partial Success' ? 'b-amber' : 'b-dim';
}
function opPriorityBadge(p) { return p === 'Critical' ? 'b-red' : p === 'Elevated' ? 'b-amber' : 'b-dim'; }

function nextOpRef() {
  var yy = new Date().getFullYear().toString().slice(-2);
  var prefix = 'OP-' + yy + '-';
  var maxN = 0;
  allOperations.concat(deletedOperations).forEach(function(o){
    if (o.ref && o.ref.indexOf(prefix) === 0) { var n = parseInt(o.ref.slice(prefix.length), 10); if (!isNaN(n) && n > maxN) maxN = n; }
  });
  return prefix + String(maxN + 1).padStart(3, '0');
}

async function loadOperations() {
  try {
    var raw = await operationsGetAll();
    allOperations = partitionDeleted(raw.filter(function(o){ return o && o.id; }), function(d){ deletedOperations = d; });
  } catch(e) { allOperations = []; }
  allOperations.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
  var btn = document.getElementById('opNewBtn');
  if (btn) btn.style.display = canManageOp() ? 'inline-block' : 'none';
  if (typeof updateOperationBadge === 'function') updateOperationBadge();
  var notice = document.getElementById('opAccessNotice');
  if (notice) {
    if (!canManageOp()) { notice.style.display = 'block'; notice.textContent = currentUser ? 'Operations are logged by command (Level 4+). You may review the deployment log below.' : 'Observer mode — deployment log is read-only.'; }
    else notice.style.display = 'none';
  }
  renderOperations();
}

function renderOperations() {
  var list = document.getElementById('operationList');
  if (!list) return;
  var q = ((document.getElementById('opSearch')||{}).value||'').trim().toLowerCase();
  var f = (document.getElementById('opFilterStatus')||{}).value||'';
  var rows = allOperations.filter(function(o){
    if (f && (o.status||'Planned') !== f) return false;
    if (!q) return true;
    var hay = [o.ref, o.codename, o.objective, o.opType, o.location, o.leadName].concat((o.operators||[]).map(function(x){ return x.name; })).join(' ').toLowerCase();
    return hay.indexOf(q) !== -1;
  });
  var cnt = document.getElementById('opCount');
  if (cnt) cnt.textContent = rows.length ? '(' + rows.length + ')' : '';
  if (!rows.length) { list.innerHTML = '<div class="trn-empty">NO OPERATIONS' + (q||f?' MATCH THE FILTER.':' LOGGED YET.') + '</div>'; return; }
  list.innerHTML = rows.map(buildOperationCard).join('');
}

function buildOperationCard(o) {
  var status = o.status || 'Planned';
  var manage = canManageOp()
    ? '<div style="display:flex;gap:.35rem;">'
      + '<button class="pf-section-btn" data-action="edit-operation" data-id="' + e(o.id) + '" style="font-size:.52rem;padding:1px 7px;">EDIT</button>'
      + '<button class="pf-section-btn" data-action="delete-operation" data-id="' + e(o.id) + '" style="font-size:.52rem;padding:1px 7px;color:#dd6666;">DELETE</button></div>'
    : '';
  var dates = (o.startDate || o.endDate)
    ? (o.startDate ? safeDate(o.startDate) : '?') + (o.endDate ? ' → ' + safeDate(o.endDate) : '')
    : '';
  var operators = (o.operators || []).map(function(op){
    return '<span class="case-link"><span class="person-link" data-action="open-op-file" data-pfid="' + e(op.id) + '">' + e(opName(op.id) || op.name || op.id) + '</span></span>';
  }).join('');
  var sqd = o.squadName ? '<span class="badge b-dim">SQUAD: ' + e(o.squadName) + '</span>' : '';
  var outcomeBlock = (status === 'Completed' || status === 'Aborted')
    ? '<div class="case-block case-ruling"><span class="lbl">Outcome</span><span class="txt">'
      + (o.outcome ? '<span class="badge ' + opOutcomeBadge(o.outcome) + '">' + e(o.outcome.toUpperCase()) + '</span> ' : '')
      + (o.afterAction ? e(o.afterAction) : '<span style="color:var(--text-faint);">No after-action report filed.</span>') + '</span></div>'
    : '';
  return '<div class="case-card">'
    + '<div class="case-top"><div><div class="case-ref">' + e(o.ref||'—') + (o.opType ? ' · ' + e(o.opType.toUpperCase()) : '') + '</div>'
    + '<div class="case-title" style="letter-spacing:.06em;">OPERATION ' + e((o.codename||'UNNAMED').toUpperCase()) + '</div>'
    + '<div class="case-badges" style="margin-top:4px;"><span class="badge ' + opStatusBadge(status) + '">' + e(status.toUpperCase()) + '</span>'
    + (o.priority ? '<span class="badge ' + opPriorityBadge(o.priority) + '">' + e(o.priority.toUpperCase()) + '</span>' : '') + sqd + '</div></div>' + manage + '</div>'
    + (o.objective ? '<div class="case-block"><span class="lbl">Objective</span><span class="txt">' + e(o.objective) + '</span></div>' : '')
    + ((o.location || dates) ? '<div class="case-block"><span class="lbl">Deployment</span><span class="txt">' + (o.location ? e(o.location) : '') + (o.location && dates ? ' · ' : '') + e(dates) + '</span></div>' : '')
    + '<div class="case-block"><span class="lbl">Lead</span><span class="txt">' + e(o.leadName || '—') + '</span></div>'
    + (operators ? '<div class="case-block"><span class="lbl">Operators (' + (o.operators||[]).length + ')</span><div>' + operators + '</div></div>' : '')
    + outcomeBlock
    + '<div style="font-size:.5rem;color:var(--text-faint);letter-spacing:.04em;margin-top:.5rem;">LOGGED ' + e(safeDate(o.createdAt)) + ' · ' + e(o.createdBy||'—') + '</div>'
    + '</div>';
}

// ── Modal ──
function openOperationModal(id) {
  if (!id && !canManageOp()) { alert('Operations are logged by command (Level 4+).'); return; }
  var editing = !!id;
  var o = editing ? allOperations.find(function(x){ return x.id === id; }) : null;
  if (editing && !canManageOp()) { alert('Command authority required to edit operations.'); return; }
  document.getElementById('operationModalTitle').textContent = editing ? 'EDIT OPERATION' : 'LOG OPERATION';
  document.getElementById('operationEditId').value = id || '';
  document.getElementById('opErr').style.display = 'none';
  document.getElementById('opType').innerHTML = OP_TYPES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  document.getElementById('opStatus').innerHTML = OP_STATUSES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  document.getElementById('opPriority').innerHTML = OP_PRIORITIES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  document.getElementById('opOutcome').innerHTML = OP_OUTCOMES.map(function(x){ return '<option>' + e(x) + '</option>'; }).join('');
  var leadOpts = '<option value="">— select lead —</option>' + (allPersonnel||[]).slice().sort(function(a,b){ return (a.name||'').localeCompare(b.name||''); }).map(function(p){ return '<option value="' + e(p.id) + '">' + e(p.name||p.id) + (p.rank?' ('+e(p.rank)+')':'') + '</option>'; }).join('');
  document.getElementById('opLead').innerHTML = leadOpts;
  var sqdOpts = '<option value="">— none —</option>' + (typeof allSquadrons!=='undefined'?allSquadrons:[]).map(function(s){ return '<option value="' + e(s.id) + '">' + e(s.name||s.id) + '</option>'; }).join('');
  document.getElementById('opSquad').innerHTML = sqdOpts;

  document.getElementById('opCodename').value = o ? (o.codename||'') : '';
  document.getElementById('opObjective').value = o ? (o.objective||'') : '';
  document.getElementById('opType').value = o ? (o.opType||OP_TYPES[0]) : OP_TYPES[0];
  document.getElementById('opStatus').value = o ? (o.status||'Planned') : 'Planned';
  document.getElementById('opPriority').value = o ? (o.priority||'Routine') : 'Routine';
  document.getElementById('opLocation').value = o ? (o.location||'') : '';
  document.getElementById('opStart').value = o ? (o.startDate||'') : '';
  document.getElementById('opEnd').value = o ? (o.endDate||'') : '';
  document.getElementById('opLead').value = o ? (o.leadId||'') : '';
  document.getElementById('opSquad').value = o ? (o.squadId||'') : '';
  document.getElementById('opOutcome').value = o ? (o.outcome||'N/A') : 'N/A';
  document.getElementById('opAfterAction').value = o ? (o.afterAction||'') : '';
  _opOperators = (o && Array.isArray(o.operators)) ? o.operators.map(function(x){ return { id:x.id, name:x.name }; }) : [];
  renderOpOperators(); populateOpOperatorPicker();
  document.getElementById('operationModal').classList.add('open');
}
function closeOperationModal() { document.getElementById('operationModal').classList.remove('open'); _opOperators = []; }

function populateOpOperatorPicker() {
  var sel = document.getElementById('opOperatorPicker'); if (!sel) return;
  var taken = {}; _opOperators.forEach(function(x){ taken[x.id] = true; });
  var opts = ['<option value="">+ ADD OPERATOR...</option>'];
  (allPersonnel||[]).slice().sort(function(a,b){ return (a.name||'').localeCompare(b.name||''); }).forEach(function(p){
    if (p.id && !taken[p.id]) opts.push('<option value="' + e(p.id) + '">' + e(p.name||p.id) + '</option>');
  });
  sel.innerHTML = opts.join('');
}
function addOpOperator(id) {
  if (!id) return;
  if (_opOperators.some(function(x){ return x.id === id; })) return;
  var p = (allPersonnel||[]).find(function(x){ return x.id === id; });
  _opOperators.push({ id:id, name: p ? (p.name||id) : id });
  renderOpOperators(); populateOpOperatorPicker();
}
function removeOpOperator(id) {
  _opOperators = _opOperators.filter(function(x){ return x.id !== id; });
  renderOpOperators(); populateOpOperatorPicker();
}
function renderOpOperators() {
  var box = document.getElementById('opOperatorList'); if (!box) return;
  if (!_opOperators.length) { box.innerHTML = '<span style="font-size:.58rem;color:var(--text-faint);">No operators assigned.</span>'; return; }
  box.innerHTML = _opOperators.map(function(x){
    return '<span class="case-link">' + e(opName(x.id) || x.name) + '<span class="x" data-action="remove-op-operator" data-pfid="' + e(x.id) + '">×</span></span>';
  }).join('');
}

async function saveOperation() {
  var codename = document.getElementById('opCodename').value.trim();
  var objective = document.getElementById('opObjective').value.trim();
  var errEl = document.getElementById('opErr');
  function fail(m){ errEl.textContent = m; errEl.style.display = 'block'; }
  if (!codename) { fail('An operation codename is required.'); return; }
  if (!objective) { fail('State the operation objective.'); return; }
  if (!canManageOp()) { fail('Command authority required.'); return; }
  var editId = document.getElementById('operationEditId').value;
  var existing = editId ? allOperations.find(function(x){ return x.id === editId; }) : null;

  var leadId = document.getElementById('opLead').value;
  var leadName = leadId ? (opName(leadId) || leadId) : '';
  var squadId = document.getElementById('opSquad').value;
  var squadName = squadId ? (((typeof allSquadrons!=='undefined'?allSquadrons:[]).find(function(s){ return s.id===squadId; })||{}).name || '') : '';

  var btn = document.getElementById('opSaveBtn'); if (btn){ btn.disabled=true; btn.textContent='[ SAVING... ]'; }
  var o;
  if (existing) { o = existing; }
  else { o = { id:'op_'+Date.now()+'_'+Math.random().toString(36).slice(2,5), ref:nextOpRef(), createdBy:currentUser.id, createdAt:Date.now(), deleted:false }; }
  o.codename = codename; o.objective = objective;
  o.opType = document.getElementById('opType').value;
  o.status = document.getElementById('opStatus').value;
  o.priority = document.getElementById('opPriority').value;
  o.location = document.getElementById('opLocation').value.trim();
  o.startDate = document.getElementById('opStart').value || '';
  o.endDate = document.getElementById('opEnd').value || '';
  o.leadId = leadId; o.leadName = leadName;
  o.squadId = squadId || null; o.squadName = squadName || null;
  o.operators = _opOperators.slice();
  o.outcome = document.getElementById('opOutcome').value;
  o.afterAction = document.getElementById('opAfterAction').value.trim();
  o.updatedAt = Date.now();
  try { await operationSet(o.id, o); }
  catch(err){ if(btn){btn.disabled=false;btn.textContent='[ SAVE OPERATION ]';} fail('SAVE ERROR: '+err.message); return; }
  if (typeof auditRecord === 'function') auditRecord(existing?'EDITED OPERATION':'LOGGED OPERATION', (o.ref||'') + ' — ' + codename);
  if (btn){ btn.disabled=false; btn.textContent='[ SAVE OPERATION ]'; }
  closeOperationModal();
  if (typeof toast==='function') toast('✓ OPERATION SAVED');
  await loadOperations();
}
async function deleteOperation(id) {
  if (!canManageOp()) { alert('Command authority required.'); return; }
  var o = allOperations.find(function(x){ return x.id === id; });
  if (!await pfConfirm('Move operation ' + (o?('"'+o.codename+'"'):'') + ' to the recycle bin?')) return;
  o.deleted = true; o.deletedBy = currentUser.id; o.deletedAt = Date.now();
  try { await operationSet(id, o); } catch(e){ alert('ERROR: '+e.message); return; }
  if (typeof auditRecord === 'function') auditRecord('DELETED OPERATION', (o.ref||id) + ' → recycle bin');
  allOperations = allOperations.filter(function(x){ return x.id !== id; });
  if (!deletedOperations.some(function(x){ return x.id===id; })) deletedOperations.push(o);
  if (typeof toastUndo==='function') toastUndo('✓ OPERATION DELETED', function(){ undoSoftDelete('operation', id); });
  renderOperations();
}
function openOpFile(pfId) { if (typeof openPersonnelFromTraining === 'function') openPersonnelFromTraining(pfId); }

// ================================================================
//  OMEGA-1 — PERSONNEL READINESS BOARD
//  Read-only aggregation: derives each operative's deployability from
//  existing data (status, active leave, active strikes, current
//  operation assignment, training currency). No new data model.
// ================================================================
var STRIKE_DEPLOY_LIMIT = 3;       // active strikes at/above this -> non-deployable
var TRAINING_CURRENCY_DAYS = 90;   // last training within this many days -> current

function canViewReadiness() { return currentUser && parseInt(currentUser.clearance) >= 4; }

function pfActiveStrikes(p) {
  return (typeof objArr === 'function' ? objArr(p.strikes) : (p.strikes || [])).filter(isStrikeActive).length;
}
// Operations the person is committed to that are still ongoing (not Completed/Aborted).
function pfCurrentOps(p) {
  return (typeof allOperations !== 'undefined' ? allOperations : []).filter(function(o){
    if (!o || o.status === 'Completed' || o.status === 'Aborted') return false;
    return o.leadId === p.id || (Array.isArray(o.operators) && o.operators.some(function(x){ return x && x.id === p.id; }));
  });
}
function pfLastTrainingDate(p) {
  var ds = (typeof allTrainings !== 'undefined' ? allTrainings : [])
    .filter(function(t){ return t && Array.isArray(t.attendees) && t.attendees.some(function(a){ return a && a.pfId === p.id; }); })
    .map(function(t){ return t.date; }).filter(Boolean).sort();
  return ds.length ? ds[ds.length - 1] : null;
}
function pfTrainingCurrency(p) {
  var last = pfLastTrainingDate(p);
  if (!last) return { state: 'none', last: null };
  var age = (Date.now() - new Date(last + 'T00:00:00').getTime()) / 86400000;
  return { state: age <= TRAINING_CURRENCY_DAYS ? 'current' : 'lapsed', last: last, ageDays: Math.floor(age) };
}
// Composite readiness verdict.
function pfReadiness(p) {
  var status  = p.status || 'Active';
  var leave   = (typeof getActiveLeave === 'function') ? getActiveLeave(p) : null;
  var strikes = pfActiveStrikes(p);
  var ops     = pfCurrentOps(p);
  var deployed = ops.some(function(o){ return o.status === 'Active'; });
  var training = pfTrainingCurrency(p);
  var reasons = [];
  if (status !== 'Active')          reasons.push(status.toUpperCase());
  if (leave)                        reasons.push((leave.type || 'LEAVE').toUpperCase());
  if (strikes >= STRIKE_DEPLOY_LIMIT) reasons.push(strikes + ' STRIKES');
  var verdict = reasons.length ? 'NON-DEPLOYABLE' : (deployed ? 'DEPLOYED' : 'DEPLOYABLE');
  return { verdict: verdict, reasons: reasons, strikes: strikes, ops: ops, deployed: deployed, leave: leave, status: status, training: training };
}
function pfBoardStatus(p, r) {
  if (p.status && p.status !== 'Active') return p.status.toUpperCase();
  if (r.leave) return (r.leave.type || 'LEAVE').toUpperCase();
  if (r.deployed) return 'DEPLOYED';
  if (typeof activityStatus === 'function') { var a = activityStatus(p, 'pf'); return (a && a.label) || 'ACTIVE'; }
  return 'ACTIVE';
}
function rdyClass(v) { return v === 'DEPLOYABLE' ? 'rdy-ok' : v === 'DEPLOYED' ? 'rdy-dep' : 'rdy-no'; }

async function loadReadiness() {
  var notice = document.getElementById('rdyAccessNotice');
  var body = document.getElementById('rdyBody');
  if (!canViewReadiness()) {
    if (notice) { notice.style.display = 'block'; notice.textContent = 'Readiness board is restricted to Omega-1 command (Level 4+).'; }
    if (body) body.style.display = 'none';
    return;
  }
  if (notice) notice.style.display = 'none';
  if (body) body.style.display = 'block';
  // Ensure the aggregated data sources are loaded.
  try {
    if (typeof loadPersonnel === 'function' && (!allPersonnel || !allPersonnel.length)) await loadPersonnel();
    if (typeof loadOperations === 'function') await loadOperations();
    if (typeof loadTrainings === 'function') await loadTrainings();
  } catch (e) {}
  renderReadiness();
}

function renderReadiness() {
  var list = document.getElementById('readinessList');
  if (!list) return;
  var q = (g('rdySearch') || '').trim().toLowerCase();
  var f = g('rdyFilter') || '';
  var rows = (allPersonnel || []).map(function(p){ return { p: p, r: pfReadiness(p) }; });
  // Summary tallies (whole roster, independent of filter)
  function tally(v){ return rows.filter(function(x){ return x.r.verdict === v; }).length; }
  var sd = document.getElementById('rdyDeployable'); if (sd) sd.textContent = tally('DEPLOYABLE');
  var sp = document.getElementById('rdyDeployed');   if (sp) sp.textContent = tally('DEPLOYED');
  var sn = document.getElementById('rdyNon');        if (sn) sn.textContent = tally('NON-DEPLOYABLE');

  var filtered = rows.filter(function(x){
    if (f && x.r.verdict !== f) return false;
    if (!q) return true;
    return (x.p.name || '').toLowerCase().indexOf(q) !== -1 || (x.p.rank || '').toLowerCase().indexOf(q) !== -1;
  });
  var ord = { DEPLOYABLE: 0, DEPLOYED: 1, 'NON-DEPLOYABLE': 2 };
  filtered.sort(function(a, b){ return (ord[a.r.verdict] - ord[b.r.verdict]) || (a.p.name || '').localeCompare(b.p.name || ''); });

  var cnt = document.getElementById('rdyCount');
  if (cnt) cnt.textContent = filtered.length ? '(' + filtered.length + ')' : '';
  if (!filtered.length) { list.innerHTML = '<div class="trn-empty">NO PERSONNEL' + (q || f ? ' MATCH THE FILTER.' : ' ON THE ROSTER YET.') + '</div>'; return; }
  list.innerHTML = filtered.map(function(x){ return buildReadinessRow(x.p, x.r); }).join('');
  applyPagination(list, 'readiness', q + '|' + f);
}

function buildReadinessRow(p, r) {
  var vc = rdyClass(r.verdict);
  var opTxt = r.ops.length
    ? r.ops.map(function(o){ return e(o.codename || o.ref || 'OP') + (o.status !== 'Active' ? ' (' + e(o.status) + ')' : ''); }).join(', ')
    : '<span class="muted">—</span>';
  var trn = r.training.state === 'current' ? '<span class="rdy-pill rdy-pill-ok">CURRENT</span>'
          : r.training.state === 'lapsed'  ? '<span class="rdy-pill rdy-pill-warn">LAPSED</span>'
          : '<span class="rdy-pill rdy-pill-dim">NONE</span>';
  var strikeCell = r.strikes > 0 ? '<span class="rdy-strikecount">' + r.strikes + '</span>' : '<span class="muted">0</span>';
  return '<div class="rdy-row ' + vc + '" data-action="open-pf-from-training" data-pfid="' + e(p.id) + '" title="Open file">'
    + '<span class="rdy-c rdy-name">' + e(p.name || p.id) + (p.rank ? ' <span class="rdy-rank">' + e(p.rank) + '</span>' : '') + '</span>'
    + '<span class="rdy-c" data-label="STATUS">' + e(pfBoardStatus(p, r)) + '</span>'
    + '<span class="rdy-c" data-label="STRIKES">' + strikeCell + '</span>'
    + '<span class="rdy-c" data-label="OP">' + opTxt + '</span>'
    + '<span class="rdy-c" data-label="TRAINING">' + trn + '</span>'
    + '<span class="rdy-c" data-label="READINESS"><span class="rdy-verdict ' + vc + '">' + r.verdict + '</span>'
      + (r.reasons.length ? '<span class="rdy-reason"> · ' + e(r.reasons.join(', ')) + '</span>' : '') + '</span>'
    + '</div>';
}

function refreshReadinessNav() {
  var tab = document.getElementById('navReadinessTab');
  if (tab) tab.style.display = canViewReadiness() ? '' : 'none';
}



// ================================================================
//  EC SURVEILLANCE — quiet observation flags on personnel files
//  Visible ONLY to Ethics Committee personnel. Places a file under
//  observation at a chosen level, and surfaces all field-intelligence
//  filed against that subject directly inside the dossier — so the
//  intel network "lands" on the files themselves.
//  Firebase path: /surveillance/{sys_pfId}
// ================================================================
var allSurveillance = [];
var _svTarget = null;
var SV_LEVELS = ['Routine','Elevated','Priority'];

async function surveillanceGetAll() {
  if (firebaseReady) { var a = await fbGetAll('/surveillance'); return a ? Object.values(a) : []; }
  return Object.values(lsAll('surveillance/'));
}
async function surveillanceSet(key, data) { if (firebaseReady) await fbSet('/surveillance/' + key, data); else lsSet('surveillance/' + key, data); }
async function surveillanceDel(key) { if (firebaseReady) await fbDelete('/surveillance/' + key); else lsDel('surveillance/' + key); }

async function loadSurveillance() {
  if (!canAccessIntel()) { allSurveillance = []; return; }
  try { allSurveillance = (await surveillanceGetAll()).filter(function(x){ return x && x.key; }); }
  catch(e) { allSurveillance = []; }
}

function surveillanceFor(sys, pfId) {
  var k = (sys||'pf') + '_' + pfId;
  return (allSurveillance || []).find(function(x){ return x.key === k; }) || null;
}
function isUnderSurveillance(sys, pfId) {
  var sv = surveillanceFor(sys, pfId);
  return !!(sv && sv.active !== false);
}
function reportsForSubject(sys, pfId) {
  sys = sys || 'pf';
  return (allIntelReports || []).filter(function(r){ return r.subjectId === pfId && (r.subjectSys||'pf') === sys; });
}
function svLevelBadge(l) { return l === 'Priority' ? 'b-red' : l === 'Elevated' ? 'b-amber' : 'b-dim'; }

// Section body injected into both card builders (EC viewers only).
function buildSurveillanceSection(p, sys) {
  if (!canAccessIntel()) return '';
  sys = sys || 'pf';
  var sv = surveillanceFor(sys, p.id);
  var active = !!(sv && sv.active !== false);
  var reports = reportsForSubject(sys, p.id);
  var html = '';
  if (active) {
    html += '<div class="sv-banner sv-' + e((sv.level||'Routine').toLowerCase()) + '">◉ UNDER EC OBSERVATION &middot; ' + e((sv.level||'Routine').toUpperCase()) + '</div>'
      + (sv.reason ? '<div class="case-block"><span class="lbl">Grounds</span><span class="txt">' + e(sv.reason) + '</span></div>' : '')
      + '<div style="font-size:.5rem;color:var(--text-faint);margin:.2rem 0 .45rem;">flagged ' + e(safeDate(sv.flaggedAt)) + ' &middot; EC&middot;' + e(sv.flaggedBy||'—') + '</div>'
      + '<div style="display:flex;gap:.35rem;margin-bottom:.55rem;">'
      + '<button class="pf-section-btn" data-action="adjust-surveillance" data-sys="' + e(sys) + '" data-pfid="' + e(p.id) + '">ADJUST</button>'
      + '<button class="pf-section-btn" data-action="lift-surveillance" data-sys="' + e(sys) + '" data-pfid="' + e(p.id) + '" style="color:#dd6666;">LIFT</button></div>';
  } else {
    html += '<div style="font-size:.62rem;color:var(--text-faint);margin-bottom:.4rem;">Not under active observation.</div>'
      + '<button class="pf-section-btn" data-action="place-surveillance" data-sys="' + e(sys) + '" data-pfid="' + e(p.id) + '" style="margin-bottom:.55rem;">+ PLACE UNDER SURVEILLANCE</button>';
  }
  if (reports.length) {
    html += '<div style="font-size:.55rem;letter-spacing:.08em;color:var(--text-faint);text-transform:uppercase;margin:.35rem 0 .3rem;">Field intelligence (' + reports.length + ')</div>'
      + reports.map(function(r){
          var rel = r.reliability||'F', cred = r.credibility||'6';
          var snip = (r.content||'').slice(0,130) + ((r.content||'').length>130 ? '…' : '');
          return '<div class="sv-report" data-action="open-intel-ref" data-ref="' + e(r.ref||'') + '">'
            + '<span class="rel-badge rel-' + e(rel) + '">' + e(rel) + e(cred) + '</span> '
            + '<span class="src-codename" style="font-size:.6rem;">' + e(informantName(r.sourceId)) + '</span> '
            + '<span style="color:var(--text-faint);font-size:.52rem;">' + e(r.ref||'') + ' &middot; ' + e(r.category||'') + ' &middot; ' + e(r.status||'New') + '</span>'
            + '<div style="font-size:.6rem;color:var(--text);margin-top:1px;">' + e(snip) + '</div></div>';
        }).join('');
  } else {
    html += '<div style="font-size:.58rem;color:var(--text-faint);">No field intelligence on file.</div>';
  }
  return html;
}

// Label/count for the collapsible section header.
function surveillanceSectionMeta(p, sys) {
  var sv = surveillanceFor(sys, p.id);
  var active = !!(sv && sv.active !== false);
  var reports = reportsForSubject(sys, p.id);
  return {
    label: active ? '◉ EC OBSERVATION' : '◉ EC INTEL',
    count: active ? ' · ' + (sv.level||'Routine').toUpperCase() : (reports.length ? ' (' + reports.length + ')' : '')
  };
}

function openSurveillanceModal(sys, pfId) {
  if (!canAccessIntel()) { alert('Ethics Committee access required.'); return; }
  _svTarget = { sys: sys, pfId: pfId };
  var sv = surveillanceFor(sys, pfId);
  document.getElementById('svLevel').innerHTML = SV_LEVELS.map(function(x){ return '<option>' + x + '</option>'; }).join('');
  document.getElementById('svLevel').value = sv ? (sv.level||'Routine') : 'Routine';
  document.getElementById('svReason').value = sv ? (sv.reason||'') : '';
  document.getElementById('svModalTitle').textContent = (sv && sv.active !== false) ? 'ADJUST SURVEILLANCE' : 'PLACE UNDER SURVEILLANCE';
  document.getElementById('svErr').style.display = 'none';
  document.getElementById('surveillanceModal').classList.add('open');
}
function closeSurveillanceModal() { document.getElementById('surveillanceModal').classList.remove('open'); _svTarget = null; }

async function saveSurveillance() {
  if (!_svTarget) return;
  var sys = _svTarget.sys, pfId = _svTarget.pfId, key = sys + '_' + pfId;
  var reason = document.getElementById('svReason').value.trim();
  if (!reason) { var er = document.getElementById('svErr'); er.textContent = 'State the grounds for observation.'; er.style.display = 'block'; return; }
  var existing = surveillanceFor(sys, pfId);
  var rec = existing || { key: key, sys: sys, pfId: pfId, flaggedBy: currentUser.id, flaggedAt: Date.now() };
  rec.level = document.getElementById('svLevel').value;
  rec.reason = reason; rec.active = true; rec.updatedAt = Date.now();
  try { await surveillanceSet(key, rec); } catch(e){ alert('ERROR: ' + e.message); return; }
  if (!allSurveillance.some(function(x){ return x.key === key; })) allSurveillance.push(rec);
  if (typeof auditRecord === 'function') auditRecord(existing ? 'ADJUSTED SURVEILLANCE' : 'PLACED SURVEILLANCE', key + ' · ' + rec.level);
  closeSurveillanceModal();
  if (typeof toast==='function') toast('✓ SURVEILLANCE UPDATED');
  refreshFileViews(sys);
}
async function liftSurveillance(sys, pfId) {
  if (!canAccessIntel()) return;
  if (!await pfConfirm('Lift surveillance on this file?')) return;
  var key = sys + '_' + pfId;
  try { await surveillanceDel(key); } catch(e){ alert('ERROR: ' + e.message); return; }
  allSurveillance = allSurveillance.filter(function(x){ return x.key !== key; });
  if (typeof auditRecord === 'function') auditRecord('LIFTED SURVEILLANCE', key);
  refreshFileViews(sys);
}
function refreshFileViews(sys) {
  if (sys === 'ef') { if (typeof renderEthicsFiles === 'function') renderEthicsFiles(); }
  else { if (typeof renderPersonnelFiles === 'function') renderPersonnelFiles(); }
}
function openIntelRef(ref) {
  var nav = document.getElementById('navIntelTab');
  if (nav) nav.click();
  setTimeout(function(){
    if (typeof setIntelView === 'function') setIntelView('reports');
    var s = document.getElementById('repSearch'); if (s) s.value = ref;
    if (typeof renderIntelReports === 'function') renderIntelReports();
  }, 130);
}




// ── Re-derive clearance once personnel data is in memory ──
// Called at the end of loadPersonnel / loadEthicsPersonnel so any
// stored-vs-file-rank discrepancy (e.g. from a promotion/demotion) is
// corrected without requiring a full re-login.
async function refreshClearance() {
  if (!currentUser) return;
  try {
    var rec = await userGet(currentUser.id);
    if (!rec) return;
    var newCl = deriveClearance(rec);
    if (newCl === currentUser.clearance) return; // nothing changed

    currentUser.clearance = newCl;

    // Update pill text
    var pill = document.getElementById('userPill');
    if (pill && pill.style.display !== 'none') {
      var unitTag = rec.unit ? ' · ' + (rec.unit === 'omega1' ? 'Ω-1' : 'EC') : '';
      pill.textContent = 'EC·' + currentUser.id + ' [L' + newCl + ']' + unitTag + '  ▾';
    }
    // Update admin button visibility
    var adminBtn = document.getElementById('adminBtn');
    if (adminBtn) adminBtn.style.display = parseInt(newCl) >= 5 ? 'inline-block' : 'none';
    // Update CL3 read-only banner
    var cl3Banner = document.getElementById('cl3Banner');
    if (cl3Banner) cl3Banner.style.display = (currentUser && parseInt(newCl) <= 3) ? 'block' : 'none';
    // Re-render active tab so access filters reflect the corrected clearance
    var active = document.querySelector('.tab-content.active');
    if (active) {
      var tid = active.id;
      if (tid === 'tab-personnel-files') renderPersonnelFiles();
      else if (tid === 'tab-roster')     renderRoster();
      else if (tid === 'tab-ethics-files') renderEthicsFiles();
      else if (tid === 'tab-ethics-roster') renderEthicsRoster();
    }
  } catch(_) {}
}

async function loadPersonnel() {
  try {
    var raw = await personnelGetAll();
    allPersonnel = partitionDeleted(raw.filter(function(p){ return p && p.id; }), function(d){ deletedPersonnel = d; });
  } catch(e) { allPersonnel = []; }
  await loadSquadrons();
  renderPersonnelFiles();
  renderRoster();
  refreshClearance(); // silently correct clearance now that allPersonnel is populated
}

// ── Render Personnel Files ──
// ── Personnel file read-access level helpers ──
// Access levels: 3=CL3, 4=CL4-Junior, 5=CL4-Senior/EC-Assistant, 6=CL5
var CL4_SENIOR_RANKS  = ['Commander','Lieutenant Commander','Major'];
var CL4_JUNIOR_RANKS  = ['Captain','Lieutenant'];

function getPfReadLevel(p) {
  if (!p) return 3;
  if (CL4_SENIOR_RANKS.includes(p.rank)) return 5;
  if (CL4_JUNIOR_RANKS.includes(p.rank)) return 4;
  return 3;
}
// ── File ↔ account bridge: integrity status & compartments shown ON personnel files ──
// Find the user account linked to a given personnel file (by linkedPfId / linkedEfId).
function userForFile(fileId, unit) {
  if (!fileId || !allUsers) return null;
  var key = unit === 'ef' ? 'linkedEfId' : 'linkedPfId';
  var found = Object.values(allUsers).find(function(u){ return u && u[key] === fileId; });
  return found || null;
}
// Can the current viewer see integrity status on files? Senior CL4 + CL5 only (counterintel).
function canViewFileIntegrity() {
  if (!currentUser) return false;
  if (parseInt(currentUser.clearance) >= 5) return true;
  if (currentUser.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
    if (pf && CL4_SENIOR_RANKS.includes(pf.rank)) return true;
  }
  if (currentUser.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === currentUser.linkedEfId; });
    if (ef && (ef.role === 'Chairman' || ef.role === 'Member')) return true; // CL5-equiv EC
  }
  return false;
}
// Build the integrity badge for a file (only if viewer is authorised and a status is set).
function fileIntegrityBadge(fileId, unit) {
  if (!canViewFileIntegrity()) return '';
  var u = userForFile(fileId, unit);
  if (!u || !u.integrityStatus) return '';
  return '<span class="badge ' + integrityClass(u.integrityStatus) + '" style="margin-left:4px;font-size:.5rem;" title="Integrity status (CL4-senior/CL5 only)">⚕ ' + e(integrityLabel(u.integrityStatus)) + '</span>';
}
// Build compartment-grant badges for a file (visible per normal file read access).
function fileCompartmentBadges(fileId, unit) {
  var u = userForFile(fileId, unit);
  if (!u || !Array.isArray(u.compartments) || !u.compartments.length) return '';
  return u.compartments.map(function(id){
    var nm = compartmentName(id);
    if (!nm) return '';
    return '<span class="badge b-dim" style="margin-left:4px;font-size:.5rem;" title="Need-to-know program">▢ ' + e(nm) + '</span>';
  }).join('');
}
// Editable integrity-status control shown on a personnel file (senior CL4 + CL5 only).
// Reads/writes the same integrityStatus field on the linked account as the admin panel.
function fileIntegrityControl(fileId, unit) {
  if (!canViewFileIntegrity()) return '';
  var u = userForFile(fileId, unit);
  if (!u) return '<div style="font-size:.56rem;color:var(--text-faint);">No linked account — integrity status is tracked on the member\'s account.</div>';
  var cur = u.integrityStatus || '';
  var opts = [
    ['',                'CLEAR — no concerns'],
    ['psych-eval',      'PSYCH EVAL PENDING'],
    ['monitoring',      'MONITORING — anomaly exposure'],
    ['memetic',         'MEMETIC HAZARD — exposure suspected'],
    ['amnestic-pending','AMNESTIC TREATMENT PENDING'],
    ['impostor-review', 'POSSIBLE IMPOSTER — identity unverified'],
    ['compromised',     'COMPROMISED — access suspended']
  ].map(function(o){
    return '<option value="' + o[0] + '"' + (o[0]===cur?' selected':'') + '>' + o[1] + '</option>';
  }).join('');
  return '<div style="font-size:.56rem;color:var(--text-faint);margin-bottom:.4rem;line-height:1.5;">Visible to senior command (CL4+) only. COMPROMISED and POSSIBLE IMPOSTER suspend the member\'s access.</div>'
    + '<select class="order-select" style="width:100%;" '
    + 'onchange="setFileIntegrity(\'' + e(u.displayId) + '\', this.value)">' + opts + '</select>';
}
// Persist an integrity-status change made from a personnel file.
async function setFileIntegrity(uid, status) {
  if (!canViewFileIntegrity()) return;
  var rec = allUsers[uid];
  if (!rec) { alert('Linked account not found.'); return; }
  if ((rec.integrityStatus || '') === (status || '')) return;
  rec.integrityStatus = status || null;
  try {
    await userPatch(uid, { integrityStatus: status || null });
    auditRecord('SET INTEGRITY STATUS', 'EC·'+uid+' → '+(status ? integrityLabel(status) : 'CLEAR') + ' (via file)');
    // Refresh whichever views are open
    if (typeof renderPersonnelFiles === 'function') renderPersonnelFiles();
    if (typeof renderAdminPanel === 'function' && document.getElementById('adminModal') && document.getElementById('adminModal').classList.contains('open')) renderAdminPanel();
  } catch(err) { alert('ERROR: ' + err.message); }
}

// ── Promotion requirements section (Omega-1 personnel files) ──
// Who may tick off PROMOTION REQUIREMENTS on an Omega-1 file. CL5 and senior
// staff (Sr CL4 / senior EC) may mark any file. Junior CL4 (Captain / Lieutenant)
// may mark OTHERS' requirements but NOT their own (no self-certification). CL3 is
// read-only.
function canMarkPromoReq(rec) {
  if (!currentUser || !rec) return false;
  var cl = parseInt(currentUser.clearance || '0');
  if (cl >= 5) return true;                                       // CL5 — any
  if (cl < 4) return false;                                       // CL3 read-only
  var role = currentEfRole();
  if (role === 'Chairman' || role === 'Member') return true;      // senior EC — any
  if (currentUser.linkedPfId) {
    var me = allPersonnel.find(function(x){ return x.id === currentUser.linkedPfId; });
    if (me && CL4_SENIOR_RANKS.includes(me.rank)) return true;    // Sr CL4 — any (incl. own)
    if (me && CL4_JUNIOR_RANKS.includes(me.rank)) {
      return currentUser.linkedPfId !== rec.id;                   // Jr CL4 — others only, not own
    }
  }
  return false;
}
function buildPromoSection(p, canEdit) {
  if (!allPromoReqs) { return '<div style="font-size:.56rem;color:var(--text-faint);">Loading requirements…</div>'; }
  var meta  = getPromoMeta();
  var cbIdx = rankIndex(meta.caseByCaseFrom);
  var myIdx = rankIndex(p.rank);
  // Ranks at or above the configured threshold are command-discretion (no checklist).
  if (cbIdx >= 0 && myIdx >= 0 && myIdx <= cbIdx) {
    return '<div style="font-size:.58rem;color:var(--text-faint);line-height:1.5;">' + e(meta.caseByCaseNote) + '</div>';
  }
  var info = promoReqsFor(p.rank);
  if (!info) {
    return '<div style="font-size:.58rem;color:var(--text-faint);line-height:1.5;">' + e(meta.caseByCaseNote) + '</div>';
  }
  var items = info.items || [];
  var progress = (p.promoProgress && typeof p.promoProgress === 'object') ? p.promoProgress : {};
  if (!items.length) {
    return '<div style="font-size:.58rem;color:var(--text-dim);line-height:1.6;">Advancement to <strong style="color:var(--green);">' + e(info.next) + '</strong> — <span style="color:var(--text-faint);">no specific requirements.</span></div>';
  }
  var metCount = items.filter(function(it){ return progress[it.id] && progress[it.id].met; }).length;
  var head = '<div style="font-size:.58rem;color:var(--text-dim);margin-bottom:.5rem;line-height:1.5;">Advancement to <strong style="color:var(--green);">' + e(info.next) + '</strong> · <span style="color:' + (metCount===items.length?'var(--green)':'var(--amber)') + ';">' + metCount + '/' + items.length + ' complete</span></div>';
  var rows = items.map(function(it){
    var st = progress[it.id] || {};
    var done = !!st.met;
    var box = canEdit
      ? '<input type="checkbox" ' + (done?'checked':'') + ' onchange="togglePromoReq(\'' + e(p.id) + '\',\'' + e(it.id) + '\',this.checked)" style="margin-top:2px;cursor:pointer;flex-shrink:0;"/>'
      : '<span style="flex-shrink:0;color:' + (done?'var(--green)':'var(--text-faint)') + ';">' + (done?'☑':'☐') + '</span>';
    var meta = done && st.metBy ? '<div style="font-size:.5rem;color:var(--text-faint);margin-top:1px;">✓ EC·' + e(st.metBy) + (st.metAt?' · '+safeDate(st.metAt):'') + '</div>' : '';
    return '<label style="display:flex;gap:.45rem;align-items:flex-start;padding:.25rem 0;font-size:.58rem;line-height:1.5;' + (canEdit?'cursor:pointer;':'') + (done?'color:var(--text);':'color:var(--text-dim);') + '">'
      + box + '<span>' + e(it.text) + meta + '</span></label>';
  }).join('');
  return head + rows;
}
async function togglePromoReq(pfId, reqId, met) {
  var rec = allPersonnel.find(function(x){ return x.id === pfId; });
  if (!rec) return;
  if (!canMarkPromoReq(rec)) { alert('You do not have authority to mark this file\'s promotion requirements.'); renderPersonnelFiles(); return; }
  if (!rec.promoProgress || typeof rec.promoProgress !== 'object') rec.promoProgress = {};
  if (met) rec.promoProgress[reqId] = { met: true, metBy: currentUser.id, metAt: Date.now() };
  else delete rec.promoProgress[reqId];
  try {
    await personnelSet(pfId, rec);
    auditRecord('PROMOTION REQ ' + (met?'MET':'CLEARED'), 'Ω-1 ' + (rec.name||pfId) + ' · ' + reqId);
    renderPersonnelFiles();
  } catch(err) { alert('ERROR: ' + err.message); }
}
function getEfReadLevel(p) {
  if (!p) return 3;
  if (p.role === 'Chairman' || p.role === 'Member') return 6;
  if (p.role === 'Assistant') return 5;
  return 3;
}

// Graduated access to an Ethics file's details for the current viewer.
// Returns one of:
//   'full'      — own file, CL5, or viewer's level meets the file's level
//   'partial'   — Ethics Assistant viewing Member/Chairman: all info EXCEPT strikes & notes
//   'name-only' — lower viewers: name + role visible; DoB/strikes/squadrons/ranks/notes Restricted
function getEfFileAccess(p) {
  if (!currentUser) return 'name-only';
  if (parseInt(currentUser.clearance) >= 5) return 'full';
  // Own file always full
  if (currentUser.linkedEfId === p.id) return 'full';

  var fileLevel = getEfReadLevel(p);
  var viewer = getUserReadLevel();
  if (viewer >= fileLevel) return 'full';

  // Ethics Assistant viewing a more senior EC file → partial (no strikes/notes)
  var viewerEf = currentUser.linkedEfId
    ? allEthicsPersonnel.find(function(x){ return x.id === currentUser.linkedEfId; })
    : null;
  if (viewerEf && viewerEf.role === 'Assistant' &&
      (p.role === 'Member' || p.role === 'Chairman')) {
    return 'partial';
  }

  return 'name-only';
}
// Determine how high a file the current user may read
function getUserReadLevel() {
  // Guests / observers get baseline CL3 read access (read-only of standard files)
  if (!currentUser) return 3;
  var cl = parseInt(currentUser.clearance || '3');
  if (cl >= 5) return 6;
  if (currentUser.linkedEfId) {
    var ef = allEthicsPersonnel.find(function(p){ return p.id === currentUser.linkedEfId; });
    if (ef) {
      if (ef.role === 'Chairman' || ef.role === 'Member') return 6;
      if (ef.role === 'Assistant') return 5;
    }
    return cl >= 4 ? 5 : 3;
  }
  if (currentUser.linkedPfId) {
    var pf = allPersonnel.find(function(p){ return p.id === currentUser.linkedPfId; });
    if (pf) {
      if (CL4_SENIOR_RANKS.includes(pf.rank)) return 5;
      if (CL4_JUNIOR_RANKS.includes(pf.rank)) return 4;
      return 3;
    }
  }
  if (cl >= 4) return 4;
  return 3;
}

function renderPersonnelFiles() {
  var query = (document.getElementById('pfSearch') && document.getElementById('pfSearch').value || '').toLowerCase();
  var fStatus = (document.getElementById('pfFilterStatus') && document.getElementById('pfFilterStatus').value) || '';
  var list  = document.getElementById('pfList');
  if (!list) return;
  // Populate the rank filter once (idempotent), then read the active value so the
  // selection works regardless of call order.
  var rankSel = document.getElementById('pfFilterRank');
  if (rankSel && rankSel.options.length <= 1) {
    RANKS.forEach(function(rk){
      var o = document.createElement('option'); o.value = rk; o.textContent = rk.toUpperCase();
      rankSel.appendChild(o);
    });
  }
  var fRank = (rankSel && rankSel.value) || '';

  var canEdit = canEditPersonnel();
  var pfNewBtn = document.getElementById('pfNewBtn');
  if (pfNewBtn) pfNewBtn.style.display = canEdit ? 'inline-block' : 'none';

  var pfNotice = document.getElementById('pfAccessNotice');
  if (pfNotice) pfNotice.style.display = (!currentUser || !canEdit) && currentUser ? 'block' : 'none';

  var filtered = allPersonnel.filter(function(p) {
    if (fStatus && (p.status || 'Active') !== fStatus) return false;
    if (fRank && p.rank !== fRank) return false;
    if (!query) return true;
    return (p.name     || '').toLowerCase().includes(query) ||
           (p.nickname || '').toLowerCase().includes(query) ||
           (p.rank     || '').toLowerCase().includes(query);
  });

  // Result count readout (filtered vs total)
  var pfCountEl = document.getElementById('pfCount');
  if (pfCountEl) {
    var anyFilter = !!(query || fStatus || fRank);
    pfCountEl.textContent = anyFilter
      ? '(' + filtered.length + ' of ' + allPersonnel.length + ')'
      : '(' + allPersonnel.length + ')';
  }

  // Access control: hide files of ranks above the current user's level.
  // Users always see their own file regardless of rank.
  var readLevel = getUserReadLevel();
  var pfRedactedIds = new Set();
  if (readLevel < 6) {
    filtered.forEach(function(p) {
      var isSelf = currentUser && currentUser.linkedPfId === p.id;
      if (!isSelf && getPfReadLevel(p) > readLevel) pfRedactedIds.add(p.id);
    });
  }

  // Sort alphabetically within rank for display; roster sorts by rank
  filtered.sort(function(a, b) {
    var ri = rankIndex(a.rank) - rankIndex(b.rank);
    if (ri !== 0) return ri;
    return (a.name || '').localeCompare(b.name || '');
  });

  if (!filtered.length) {
    list.innerHTML = '<div class="pf-empty">[ NO PERSONNEL RECORDS FOUND ]</div>';
    return;
  }

  var linkedPfIds = new Set();
  // Ensure allUsers is populated before using it
  if (Object.keys(allUsers).length > 0) {
      Object.values(allUsers).forEach(function(u) {
        if (u.linkedPfId) linkedPfIds.add(u.linkedPfId);
        if (u.linkedEfId) linkedPfIds.add(u.linkedEfId);
      });
  }

if (g('pfSort')) filtered = applySort(filtered, g('pfSort'), {
    name:function(p){return (p.name||p.nickname||'').toLowerCase();},
    status:function(p){return p.status||'';},
    rank:function(p){var i=(typeof RANKS!=='undefined')?RANKS.indexOf(p.rank):-1;return i<0?999:i;},
    date:function(p){return p.created||p.enrolled||0;}
  });
list.innerHTML = filtered.map(function(p) {
    // Redacted entry: file is above the viewer's clearance — show codename only
    if (pfRedactedIds.has(p.id)) {
      var cn = p.nickname ? e(p.nickname) : '[ REDACTED ]';
      return '<div class="pf-card redacted" style="opacity:.6;border:1px dashed var(--border2);padding:.6rem .9rem;margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;">'
        + '<div style="display:flex;align-items:center;gap:.6rem;">'
        + '<span style="font-family:\'VT323\',monospace;color:var(--text-dim);letter-spacing:.1em;">▨ ' + cn + '</span>'
        + '<span class="badge b-dim" style="font-size:.5rem;">CLASSIFIED</span>'
        + '</div>'
        + '<span style="font-size:.55rem;color:var(--text-faint);letter-spacing:.08em;">CLEARANCE INSUFFICIENT</span>'
        + '</div>';
    }
    var isOpen  = pfExpanded.has(p.id);
    var canEdit = canManageFile(p, 'pf');
    var isSelf = currentUser && currentUser.linkedPfId === p.id;
    var isCL5 = currentUser && parseInt(currentUser.clearance) >= 5;
    var selfRestricted = isSelf && !isCL5;
    var pStatus = p.status || 'Active';
    var notes   = Array.isArray(p.notes)      ? p.notes.filter(function(n){return n && typeof n==='object';}).sort((a,b)=>a.created-b.created) : [];
    var awards  = objArr(p.awards);
    var tags    = Array.isArray(p.tags)       ? p.tags   : [];
    var history = objArr(p.rankHistory).sort((a,b)=>(b.changedAt||0)-(a.changedAt||0));
    var pfSqdns = allSquadrons.filter(s => s.members && s.members.some(m => m && (m.memberId||m.pfId) === p.id));

    // ── header badges ──
    var rankBadge   = `<span class="badge ${rankBadgeClass(p.rank)}">${e(p.rank||'—')}</span>`;
    var statusBadge = pStatus !== 'Active'
      ? `<span class="badge ${pStatus==='Retired'?'b-retired':'b-discharged'}">${e(pStatus)}</span>` : '';
    var tagPills = tags.map(t => {
      var cls = 'tag-' + t.type.toLowerCase();
      var del = canEdit ? `<button class="tag-del" data-action="remove-tag" data-id="${e(p.id)}" data-tagtype="${e(t.type)}" title="Remove">×</button>` : '';
      return `<span class="tag-pill ${cls}"><span class="tag-manager">${e(t.role)}</span> · ${e(t.type)}${del}</span>`;
    }).join('');
var linkedBadge = linkedPfIds.has(p.id) 
    ? '<span class="badge b-green" style="font-size:.5rem; margin-left:4px;">● LINKED</span>' 
    : '';
    var fileSecBadges = fileIntegrityBadge(p.id, 'pf') + fileCompartmentBadges(p.id, 'pf');

    if (!isOpen) {
      return `<div class="pf-card" id="pfcard_${e(p.id)}">
        <div class="pf-card-header" data-action="toggle-pf" data-id="${e(p.id)}" style="cursor:pointer;padding:.6rem .9rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.4rem;" onmouseover="this.style.background='var(--accent-softer)'" onmouseout="this.style.background=''">
          <div>
            <div class="pf-name">${e(p.name||'—')}${p.nickname?` <span style="color:var(--text-dim);font-size:.75rem;">"${e(p.nickname)}"</span>`:''}</div>
            <div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap;margin-top:2px;">${rankBadge}${statusBadge}${tagPills}${linkedBadge}${fileSecBadges}</div>
          </div>
          <span style="font-size:.62rem;color:var(--text-dim);">▸</span>
        </div>
      </div>`;
    }

    // ── awards section ──
    var TIERS = ['Prestigious','Distinguished','Medal'];
    var TIER_LABELS = {Prestigious:'★ PRESTIGIOUS',Distinguished:'◆ DISTINGUISHED',Medal:'● MEDALS'};
    var awardsByTier = {Prestigious:[],Distinguished:[],Medal:[]};
    awards.forEach(a => { if(awardsByTier[a.tier]) awardsByTier[a.tier].push(a); });
    var awardsHtml = TIERS.map(tier => {
      if(!awardsByTier[tier].length) return '';
      var cls = tier.toLowerCase();
      var badges = awardsByTier[tier].map(a => {
        var del = canEdit ? `<button class="award-del" data-action="del-award" data-id="${e(p.id)}" data-awardid="${e(a.id)}" title="Remove">×</button>` : '';
        return `<span class="award-badge award-${cls}" title="${e(a.notes||'')}">${e(a.name)}<span class="award-date">${a.date||''}</span>${del}</span>`;
      }).join('');
      return `<div class="award-tier-header ${cls}">${TIER_LABELS[tier]}</div><div class="awards-grid">${badges}</div>`;
    }).join('');
    if(!awardsHtml) awardsHtml = '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO AWARDS ON RECORD ]</div>';

    // ── rank history ──
    var histHtml = history.length ? history.map(h => {
      var hts = safeDateTime(h.changedAt);
      return `<div class="rank-history-entry">
        <div class="rank-history-gutter"></div>
        <div class="rank-history-body">
          <div class="rank-history-meta">EC·${e(h.changedBy||'—')} [L${e(h.clearance||'—')}] · ${hts} UTC</div>
          <div class="rank-history-change"><span class="badge ${rankBadgeClass(h.from)}">${e(h.from||'—')}</span><span class="rank-arrow">→</span><span class="badge ${rankBadgeClass(h.to)}">${e(h.to||'—')}</span></div>
        </div>
      </div>`;
    }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO RANK CHANGES ]</div>';

    // ── notes ──
    var notesHtml = notes.length ? notes.map(n => {
      var nts = safeDateTime(n.created);
      return `<div class="pf-note"><div class="pf-note-gutter"></div><div class="pf-note-body"><div class="pf-note-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·${e(n.author)} [L${e(n.clearance)}] · ${nts} UTC</span>${canDeleteComment()?`<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-pf-note" data-pfid="${e(p.id)}" data-created="${n.created}" title="Delete note">×</button>`:''}</div><div class="pf-note-text">${e(n.text)}</div></div></div>`;
    }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO NOTES ]</div>';
    var noteForm = currentUser ? `<div class="pf-note-form"><textarea class="pf-note-input" id="pfnote_${e(p.id)}" placeholder="Add note..." rows="2" onkeydown="handleNoteKey(event,this)"></textarea><button class="pf-btn" data-action="add-pf-note" data-id="${e(p.id)}">[ ADD ]</button></div>` : '';

    // ── tags section ──
    // ── Strikes ──
    var strikes = objArr(p.strikes);
    var strikesHtml = strikes.length ? strikes.map(function(s) {
      var ds  = strikeDisplayStatus(s);
      var exp = s.expiresAt ? new Date(s.expiresAt).toLocaleDateString('en-GB') : 'Permanent';
      var issuedDate = safeDate(s.issuedAt);
      var appealBlock = '';
      if (s.appeal) {
        var aDate = safeDate(s.appeal.submittedAt);
        appealBlock = `<div class="strike-appeal-block${s.appeal.resolution?' resolved':''}">
          <div style="font-size:.57rem;color:var(--amber);letter-spacing:.08em;margin-bottom:2px;">▸ APPEAL${s.appeal.resolution?' — '+s.appeal.resolution.toUpperCase():' — PENDING REVIEW'}</div>
          <div style="color:var(--text);line-height:1.6;">${e(s.appeal.reason)}</div>
          <div style="font-size:.57rem;color:var(--text-dim);margin-top:2px;">Submitted by EC·${e(s.appeal.submittedBy)} · ${aDate}${s.appeal.resolvedBy?' · Resolved by EC·'+e(s.appeal.resolvedBy):''}</div>
        </div>`;
      }
      var btns = '<div class="strike-btns">';
      if (canIssueStrike()) {
        btns += `<button class="strike-btn edit"    data-action="edit-strike"   data-id="${e(p.id)}" data-strikeid="${e(s.id)}">EDIT</button>`;
        if (s.status === 'Appealed' && s.appeal && !s.appeal.resolution) {
          btns += `<button class="strike-btn overturn" data-action="overturn-strike" data-id="${e(p.id)}" data-strikeid="${e(s.id)}">OVERTURN</button>`;
          btns += `<button class="strike-btn uphold"   data-action="uphold-strike"   data-id="${e(p.id)}" data-strikeid="${e(s.id)}">UPHOLD</button>`;
        }
        btns += `<button class="strike-btn del"    data-action="delete-strike" data-id="${e(p.id)}" data-strikeid="${e(s.id)}">✕ REMOVE</button>`;
      }
      if (currentUser && s.status === 'Active') {
        btns += `<button class="strike-btn appeal" data-action="appeal-strike" data-id="${e(p.id)}" data-strikeid="${e(s.id)}">APPEAL</button>`;
      }
      btns += '</div>';
      return `<div class="strike-card ${ds.cardCls}">
        <div class="strike-header">
          <div>
            <span class="badge ${ds.cls}">${ds.label}</span>
            <div class="strike-meta">Issued by EC·${e(s.issuedBy)} · ${issuedDate} · Expires: ${e(exp)}</div>
          </div>
        </div>
        <div class="strike-reason">${e(s.reason)}</div>
        ${appealBlock}${btns}
      </div>`;
    }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO STRIKES ON RECORD ]</div>';
    var strikesHeader = canIssueStrike()
      ? `<button class="pf-section-btn" data-action="issue-strike" data-id="${e(p.id)}" style="float:right;margin-top:-2px;">[ + ISSUE STRIKE ]</button>`
      : '';

    var tagsSection = `<div class="tags-row">${tagPills||'<span style="font-size:.6rem;color:var(--text-faint);">[ NO TAGS ]</span>'}${canEdit?`<button class="pf-section-btn" data-action="open-tag-modal" data-id="${e(p.id)}">+ TAG</button>`:''}</div>`;

    // ── squadrons section ──
    var sqdHtml = pfSqdns.length ? pfSqdns.map(s => {
      var myEntry = s.members.find(m => m && (m.memberId||m.pfId) === p.id);
      var myRank  = myEntry ? myEntry.rank : '—';
      var rankCls = myRank==='Director'?'sqd-director':myRank==='Co Director'?'sqd-codirector':myRank==='Supervisor'?'sqd-supervisor':'sqd-agent';
      var membersHtml = objArr(s.members).map(m =>
        `<div class="sqd-member-row"><span>${e(m.name||(m.memberId||m.pfId))}</span><span class="sqd-rank-badge ${m.rank==='Director'?'sqd-director':m.rank==='Co Director'?'sqd-codirector':m.rank==='Supervisor'?'sqd-supervisor':'sqd-agent'}">${e(m.rank)}</span></div>`
      ).join('');
      return `<div class="sqd-card"><div class="sqd-name">${e(s.name)} <span class="sqd-rank-badge ${rankCls}">${e(myRank)}</span>
        <span style="float:right;display:flex;gap:.3rem;">
          ${canEdit?`<button class="pf-section-btn" data-action="open-sqd-add" data-sqdid="${e(s.id)}" data-pfid="${e(p.id)}">+ MEMBER</button>`:''}
          ${(currentUser && parseInt(currentUser.clearance)>=5)?`<button class="pf-section-btn" style="border-color:#4a1414;color:#dd4444;" data-action="delete-pf-sqd" data-sqdid="${e(s.id)}">✕ DELETE</button>`:''}
        </span>
        </div><div style="margin-top:.4rem;">${membersHtml}</div></div>`;
    }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NOT IN ANY SQUADRON ]</div>';

    // ── action buttons ──
    var actionBtns = (canEdit && !selfRestricted) ? `
      <div class="pf-card-actions">
        <button class="pf-btn"    data-action="edit-pf"    data-id="${e(p.id)}">[ EDIT RECORD ]</button>
        <button class="pf-btn"    data-action="award-pf"   data-id="${e(p.id)}">[ AWARD MEDAL ]</button>
        <button class="pf-btn"    data-action="open-tag-modal" data-id="${e(p.id)}" style="display:none;">+ TAG</button>
        <button class="pf-btn"    data-action="create-sqd" data-id="${e(p.id)}">[ + SQUADRON ]</button>
        <button class="pf-btn danger" data-action="delete-pf" data-id="${e(p.id)}">[ DELETE ]</button>
      </div>` : '';
    var statusBtns = canEdit ? `
      <div class="pf-status-btns">
        ${pStatus==='Active'
          ? `<button class="pf-status-btn retire"    data-action="status-pf" data-id="${e(p.id)}" data-status="Retired">[ RETIRE ]</button>
             <button class="pf-status-btn discharge" data-action="status-pf" data-id="${e(p.id)}" data-status="Discharged">[ DISCHARGE ]</button>`
          : `<button class="pf-status-btn reactivate" data-action="status-pf" data-id="${e(p.id)}" data-status="Active">[ REACTIVATE ]</button>`
        }
      </div>` : '';

    return `<div class="pf-card" id="pfcard_${e(p.id)}">
      <div class="pf-card-header" data-action="toggle-pf" data-id="${e(p.id)}" style="cursor:pointer;padding:.6rem .9rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.4rem;" onmouseover="this.style.background='var(--accent-softer)'" onmouseout="this.style.background=''">
        <div>
          <div class="pf-name">${e(p.name||'—')}${p.nickname?` <span style="color:var(--text-dim);font-size:.75rem;">"${e(p.nickname)}"</span>`:''}</div>
          <div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap;margin-top:2px;">${rankBadge}${statusBadge}${fileSecBadges}</div>
        </div>
        <span style="font-size:.62rem;color:var(--text-dim);">▾</span>
      </div>
      <div class="pf-card-body open">
        ${selfRestricted ? '<div class="order-denied" style="margin-bottom:.75rem;"><span>⛔</span><span>FULL SELF-VIEW OF YOUR OWN PERSONNEL FILE IS RESTRICTED.</span><br><span style="font-size:.58rem;">You may request LoA/RoA, view medals, rank changes, strikes, and notes below. For full access, contact a CL5 user.</span></div>' : `
        <div class="pf-detail-grid">
          <div class="pf-detail"><span class="pf-detail-label">FULL NAME · </span><span class="pf-detail-val">${e(p.name||'—')}</span></div>
          <div class="pf-detail"><span class="pf-detail-label">NICKNAME · </span><span class="pf-detail-val">${e(p.nickname||'—')}</span></div>
          <div class="pf-detail"><span class="pf-detail-label">DATE OF BIRTH · </span><span class="pf-detail-val">${formatDob(p.dob)}</span></div>
          <div class="pf-detail"><span class="pf-detail-label">RANK · </span><span class="pf-detail-val">${e(p.rank||'—')}</span></div>
          <div class="pf-detail"><span class="pf-detail-label">ISD BADGE NO. · </span><span class="pf-detail-val" style="color:var(--amber);">${e(p.isdBadge||'—')}</span></div>
          <div class="pf-detail"><span class="pf-detail-label">STEAM ID · </span><span class="pf-detail-val" style="color:var(--amber);">${e(p.steamId||'—')}</span></div>
          <div class="pf-detail"><span class="pf-detail-label">STATUS · </span><span class="pf-detail-val"><span class="badge ${pStatus==='Active'?'b-green':pStatus==='Retired'?'b-retired':'b-discharged'}">${e(pStatus)}</span></span></div>
          <div class="pf-detail"><span class="pf-detail-label">CREATED · </span><span class="pf-detail-val">${safeDate(p.created)} · EC·${e(p.createdBy||'—')}</span></div>
        </div>
`}

        ${(()=>{
           var leaves  = objArr(p.leaves);
          var activeLv = leaves.filter(isLeaveActive);
          var sections = [
            { key:'tags',      label:'MANAGEMENT TAGS',      count:'',                    body: tagsSection },
            { key:'awards',    label:'AWARDS & DECORATIONS', count: ' ('+awards.length+')', body: awardsHtml },
            { key:'strikes',   label:'STRIKES',              count: ' ('+strikes.length+')', btn: strikesHeader, body: strikesHtml },
            { key:'leave',     label:'LEAVE (LOA / ROA)',    count: ' ('+activeLv.length+' active)', body: buildLeaveSection(p, 'pf') },
            { key:'ranks',     label:'RANK CHANGE LOG',      count: ' ('+history.length+')',body: buildPromoteControl(p) + histHtml },
            { key:'squadrons', label:'SQUADRON ASSIGNMENTS',  count:'',
              body: sqdHtml + (canEdit?`<button class="pf-section-btn" data-action="create-sqd" data-id="${e(p.id)}" style="margin-top:.4rem;">[ + CREATE SQUADRON ]</button>`:'') },
            { key:'notes',     label:'NOTES ON FILE',        count: ' ('+notes.length+')', body: notesHtml + noteForm },
          ];
          (function(){
            var pr = promoReqsFor(p.rank);
            var cnt = '';
            if (pr && pr.items && pr.items.length) {
              var prog = (p.promoProgress && typeof p.promoProgress==='object') ? p.promoProgress : {};
              var done = pr.items.filter(function(it){ return prog[it.id] && prog[it.id].met; }).length;
              cnt = ' ('+done+'/'+pr.items.length+')';
            }
            sections.push({ key:'promo', label:'▲ PROMOTION REQUIREMENTS', count: cnt, body: buildPromoSection(p, canMarkPromoReq(p)) });
          })();
          sections.push({ key:'activity', label:'◷ ACTIVITY', count: activityHdrLabel(p, 'pf'), body: buildActivitySection(p, 'pf') });
          (function(){
            var tc = allTrainings.filter(function(t){
              return t.conductedByPfId === p.id ||
                (Array.isArray(t.attendees) && t.attendees.some(function(a){ return a && a.pfId === p.id; }));
            }).length;
            sections.push({ key:'trainings', label:'⌖ TRAININGS', count: ' ('+tc+')', body: buildTrainingSection(p) });
          })();
          (function(){
            var svcAll = buildServiceRecord(p);
            sections.push({ key:'service', label:'◳ SERVICE RECORD', count:' ('+svcAll.length+')', body: buildServiceSection(p) });
          })();
          if (typeof canAccessIntel === 'function' && canAccessIntel()) {
            var svMeta = surveillanceSectionMeta(p, 'pf');
            sections.unshift({ key:'surveillance', label:svMeta.label, count:svMeta.count, body: buildSurveillanceSection(p, 'pf') });
          }
          if (canViewFileIntegrity()) {
            sections.push({ key:'security', label:'⚕ SECURITY STATUS', count:'', body: fileIntegrityControl(p.id, 'pf') });
          }
          return sections.map(sec => {
            var collapsed = pfCollapsed.has(p.id + ':' + sec.key);
            return `<div class="pf-sec-hdr" data-action="toggle-section" data-id="${e(p.id)}" data-section="${sec.key}">
              <span style="display:flex;align-items:center;justify-content:space-between;flex:1;gap:.5rem;">
                <span>▸ ${sec.label}${sec.count}</span>
                ${sec.btn || ''}
              </span>
              <span class="pf-sec-arrow" style="transform:rotate(${collapsed?'-90':'0'}deg)">▾</span>
            </div>
            <div class="pf-sec-body" style="display:${collapsed?'none':'block'};padding:0 .1rem .4rem;">
              ${sec.body}
            </div>`;
          }).join('');
        })()}

        ${actionBtns}${statusBtns}
      </div>
    </div>`;
  }).join('');
  applyPagination(document.getElementById('pfList'), 'pf', g('pfSearch')+'|'+g('pfFilterStatus')+'|'+g('pfFilterRank')+'|'+g('pfSort'));
}

function rankBadgeClass(rank) {
  var idx = rankIndex(rank);
  if (idx < 0)  return 'b-dim';
  if (idx <= 1) return 'b-red';   // Commander, Lt Commander
  if (idx <= 4) return 'b-amber'; // Major → Lieutenant
  return 'b-cyan';                // NCOs and below
}

// ── Render Roster ──
function renderRoster() {
  var tbody = document.getElementById('rosterBody');
  if (!tbody) return;

  var active = allPersonnel.filter(function(p){ return !p.status || p.status === 'Active'; });

  // Access control: hide personnel above the current user's read level (own file always shown)
  var rosterReadLevel = getUserReadLevel();
  var rosterRedacted = new Set();
  if (rosterReadLevel < 6) {
    active.forEach(function(p) {
      var isSelf = currentUser && currentUser.linkedPfId === p.id;
      if (!isSelf && getPfReadLevel(p) > rosterReadLevel) rosterRedacted.add(p.id);
    });
  }

  if (!active.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="roster-empty">[ NO ACTIVE PERSONNEL ON RECORD ]</td></tr>';
    return;
  }

  var sorted = active.slice().sort(function(a, b) {
    var ri = rankIndex(a.rank) - rankIndex(b.rank);
    if (ri !== 0) return ri;
    return (a.name || '').localeCompare(b.name || '');
  });

  var rows    = '';
  var lastRank = null;
  var counter  = 1;

  sorted.forEach(function(p) {
    if (p.rank !== lastRank) {
      rows += '<tr class="roster-rank-divider"><td colspan="5">▸ ' + e(p.rank || '—').toUpperCase() + '</td></tr>';
      lastRank = p.rank;
    }
    // Redacted personnel: show codename only, dashes elsewhere
    if (rosterRedacted.has(p.id)) {
      rows +=
        '<tr style="opacity:.55;">' +
          '<td class="roster-num" data-label="#">' + counter++ + '</td>' +
          '<td class="roster-name" data-label="NAME" style="font-family:\'VT323\',monospace;letter-spacing:.08em;">▨ ' + (p.nickname ? e(p.nickname) : '[ REDACTED ]') + '</td>' +
          '<td class="roster-nick" data-label="NICKNAME" style="color:var(--text-faint);">— CLASSIFIED —</td>' +
          '<td data-label="RANK"><span class="badge b-dim" style="font-size:.5rem;">●●●</span></td>' +
          '<td data-label="D.O.B" style="font-size:.62rem;color:var(--text-faint);">——</td>' +
        '</tr>';
      return;
    }
    var activeLeavePf = getActiveLeave(p);
    rows +=
      '<tr>' +
        '<td class="roster-num" data-label="#">' + counter++ + '</td>' +
        '<td class="roster-name" data-label="NAME">' + e(p.name || '—') +
          ((p.strikes||[]).some(isStrikeActive) ? ' <span class="roster-strike">⚠ ACTIVE STRIKE</span>' : '') +
          (activeLeavePf ? ' <span class="roster-leave roster-' + activeLeavePf.type.toLowerCase() + '">' + activeLeavePf.type.toUpperCase() + '</span>' : '') +
        '</td>' +
        '<td class="roster-nick" data-label="NICKNAME">' + (p.nickname ? '"' + e(p.nickname) + '"' : '—') + '</td>' +
        '<td data-label="RANK"><span class="badge ' + rankBadgeClass(p.rank) + '">' + e(p.rank || '—') + '</span></td>' +
        '<td data-label="D.O.B" style="font-size:.62rem;color:var(--text-dim);">' + formatDob(p.dob) + '</td>' +
      '</tr>';
  });

  tbody.innerHTML = rows;
}

// ── Modal ──
var pfModalMode = 'new'; // 'new' | 'edit'

// ── Optimistic concurrency (conflict detection on save) ──
// When an edit modal opens, we remember the record's `updated` stamp. On save we
// re-fetch the record fresh and, if someone else saved in the meantime, warn before
// overwriting. The whole check is best-effort and FAILS OPEN — any error lets the
// save proceed, so the conflict guard can never block a legitimate save.
var _pfEditBaseStamp = null;   // baseline `updated` of the Omega-1 file being edited
var _efEditBaseStamp = null;   // baseline `updated` of the Ethics file being edited
// Returns a warning string if the stored record changed since `baseStamp`, else null.
async function detectSaveConflict(unit, id, baseStamp) {
  try {
    if (baseStamp == null) return null; // no baseline (new record / legacy) → no check
    var list = unit === 'ef' ? await ethicsPersonnelGetAll() : await personnelGetAll();
    var cur = (list || []).find(function(r){ return r && r.id === id; });
    if (!cur) return null; // record gone (deleted/restored) → let save proceed
    var curStamp = cur.updated || 0;
    if (curStamp && curStamp > baseStamp) {
      var who = cur.updatedBy ? ('EC·' + cur.updatedBy) : 'another user';
      return 'This file was modified by ' + who + ' while you were editing it'
           + (cur.updated ? ' (' + safeDateTime(cur.updated) + ' UTC)' : '')
           + '.\n\nSaving now will overwrite their changes. Continue?';
    }
  } catch(_) { /* fail open */ }
  return null;
}

function openPersonnelModal(id) {
  // Allow opening when triggered from the link-file flow, even if clearance is low
  if (!window._awaitingPfLink && !canEditPersonnel()) return;
  // Editing an existing file requires management authority over that file
  if (id && !window._awaitingPfLink) {
    var editRec = allPersonnel.find(function(p){ return p.id === id; });
    if (editRec && !canManageFile(editRec, 'pf')) { alert('You do not have authority to edit this file.'); return; }
  }
  pfModalMode = id ? 'edit' : 'new';
  // Capture the file's current version stamp so we can detect a conflicting save later.
  if (id) {
    var _baseRec = allPersonnel.find(function(p){ return p.id === id; });
    _pfEditBaseStamp = _baseRec ? (_baseRec.updated || null) : null;
  } else {
    _pfEditBaseStamp = null;
  }

  // During first-time link flow, restrict rank options to those that match the
  // user's approved stored clearance — prevents self-promotion via rank selection.
  var rankSel = document.getElementById('pfRank');
  if (rankSel && window._awaitingPfLink && currentUser) {
    var storedCl = parseInt(currentUser.clearance || '3');
    // CL4+ ranks: Commander, Lieutenant Commander, Major, Captain, Lieutenant
    var cl4Ranks = ['Commander','Lieutenant Commander','Major','Captain','Lieutenant'];
    Array.from(rankSel.options).forEach(function(opt) {
      if (!opt.value) return; // keep the placeholder
      opt.disabled = (cl4Ranks.includes(opt.value) && storedCl < 4);
      opt.style.display = opt.disabled ? 'none' : '';
    });
  } else if (rankSel) {
    // Normal edit mode: restrict to ranks the user is allowed to assign
    // (one below their own and lower), unless CL5.
    var isCL5edit = currentUser && parseInt(currentUser.clearance) >= 5;
    Array.from(rankSel.options).forEach(function(opt) {
      if (!opt.value) { opt.disabled = false; opt.style.display = ''; return; }
      var allowed = isCL5edit || canAssignPfRank(opt.value, null);
      opt.disabled = !allowed;
      opt.style.display = allowed ? '' : 'none';
    });
  }
  var titleEl = document.getElementById('pfModalTitle') || document.querySelector('#pfModal .modal-title');
  if (titleEl) titleEl.textContent = id ? 'EDIT PERSONNEL RECORD' : 'NEW PERSONNEL RECORD';
  document.getElementById('pfEditId').value = id || '';

  if (id) {
    var rec = allPersonnel.find(function(p){ return p.id === id; });
    if (!rec) return;
    document.getElementById('pfName').value    = rec.name     || '';
    document.getElementById('pfNick').value    = rec.nickname || '';
    document.getElementById('pfDob').value     = rec.dob      || '';
    document.getElementById('pfRank').value    = rec.rank     || '';
    document.getElementById('pfIsdBadge').value= rec.isdBadge || '';
    document.getElementById('pfSteamId').value  = rec.steamId  || '';
  } else {
    document.getElementById('pfName').value     = '';
    document.getElementById('pfNick').value     = '';
    document.getElementById('pfDob').value      = '';
    document.getElementById('pfRank').value     = '';
    document.getElementById('pfIsdBadge').value = '';
    document.getElementById('pfSteamId').value   = '';
  }

  document.getElementById('pfModal').classList.add('open');
  document.getElementById('pfName').focus();
}

function closePersonnelModal() {
  document.getElementById('pfModal').classList.remove('open');
}

async function savePersonnelRecord() {
  if (!window._awaitingPfLink && !canEditPersonnel()) return;
  var name = document.getElementById('pfName').value.trim();
  var rank = document.getElementById('pfRank').value;
  if (!name) { alert('FULL NAME REQUIRED'); return; }
  if (!rank) { alert('RANK REQUIRED'); return; }

  var btn = document.getElementById('pfSaveBtn');
  btn.disabled = true; btn.textContent = '[ SAVING... ]';

  var editId = document.getElementById('pfEditId').value;

  if (editId) {
    var rec = allPersonnel.find(function(p){ return p.id === editId; });
    if (rec && !window._awaitingPfLink && !canManageFile(rec, 'pf')) {
      alert('You do not have authority to edit this file.');
      btn.disabled = false; btn.textContent = '[ SAVE ]'; return;
    }
    if (rec) {
      // Cross-unit rule: Ethics-only members (no Omega-1 file) can't edit Omega-1 files unless CL5
      if (!window._awaitingPfLink && !canEditUnitFile('pf')) {
        alert('CROSS-UNIT EDIT DENIED\n\nOnly Omega-1 personnel (or CL5 command) may modify Omega-1 files.');
        return;
      }
      // Rank-change rule: enforce promotion limits when rank actually changes
      if (rec.rank && rec.rank !== rank && !window._awaitingPfLink) {
        if (!canAssignPfRank(rank, rec.rank)) {
          alert('PROMOTION DENIED\n\nYou may only assign ranks below your own, and may not modify personnel at or above your rank. CL5 command may override.');
          return;
        }
      }
      // Log rank change if rank has changed
      if (rec.rank && rec.rank !== rank) {
        if (!rec.rankHistory) rec.rankHistory = [];
        rec.rankHistory.push({
          from: rec.rank, to: rank,
          changedBy: currentUser.id, clearance: currentUser.clearance,
          changedAt: Date.now()
        });
        // Rank changed → the next-promotion target changed, so reset the requirement checklist.
        rec.promoProgress = {};
      }
      rec.name      = name;
      rec.nickname  = document.getElementById('pfNick').value.trim();
      rec.dob       = document.getElementById('pfDob').value;
      rec.rank      = rank;
      rec.isdBadge  = document.getElementById('pfIsdBadge').value.trim();
      rec.steamId   = document.getElementById('pfSteamId').value.trim();
      rec.updatedBy = currentUser.id;
      rec.updated   = Date.now();
      var _conflict = await detectSaveConflict('pf', editId, _pfEditBaseStamp);
      if (_conflict && !(await pfConfirm(_conflict))) {
        if (btn) { btn.disabled = false; btn.textContent = '[ SAVE ]'; }
        return;
      }
      try { await personnelSet(editId, rec); } catch(err) { alert('SAVE ERROR: ' + err.message); }
    }
  } else {
    // New record: enforce the same rank-assignment limit (CL5 unrestricted).
    // The link flow handles its own restriction separately.
    if (!window._awaitingPfLink && !canAssignPfRank(rank, null)) {
      alert('RANK NOT PERMITTED\n\nYou may only create files ranked below your own. CL5 command may override.');
      return;
    }
    var id = 'per_' + Date.now() + '_' + Math.random().toString(36).slice(2,5);
    var newRec = {
      id: id, name: name,
      nickname:  document.getElementById('pfNick').value.trim(),
      dob:       document.getElementById('pfDob').value,
      rank:      rank,
      isdBadge:  document.getElementById('pfIsdBadge').value.trim(),
      steamId:   document.getElementById('pfSteamId').value.trim(),
      status:    'Active',
      rankHistory: [],
      notes:     [],
      createdBy: currentUser.id,
      created:   Date.now()
    };
    try {
      await personnelSet(id, newRec);
      allPersonnel.push(newRec);
      if (window._pendingRecruitApproval) finaliseRecruitApproval(id);
if (window._awaitingPfLink) {
    var linkUserRec = await userGet(currentUser.id);
    if (linkUserRec) {
      linkUserRec.linkedPfId = id;
      await userSet(currentUser.id, linkUserRec);
      currentUser.linkedPfId = id;
      // allPersonnel already has newRec (pushed above), so deriveClearance
      // can find the rank right now and give the correct clearance level
      currentUser.clearance = deriveClearance(linkUserRec);
    }
    window._awaitingPfLink = false;
    onLogin();
}
    } catch(err) { alert('SAVE ERROR: ' + err.message); }
  }

  btn.disabled = false; btn.textContent = '[ SAVE RECORD ]';
  closePersonnelModal();
  await loadPersonnel();
}

// ── Status action wrappers ──
// These exist to avoid quoting issues in dynamically-built onclick attributes.
// The onclick only needs to pass one string arg (the id); the status value
// is hardcoded in the wrapper, so no extra string quoting is needed in the HTML.
function pfRetire(id)      { setPersonnelStatus(id, 'Retired');    }
function pfDischarge(id)   { setPersonnelStatus(id, 'Discharged'); }
function pfReactivate(id)  { setPersonnelStatus(id, 'Active');     }
function efRetire(id)      { setEthicsStatus(id, 'Retired');       }
function efDischarge(id)   { setEthicsStatus(id, 'Discharged');    }
function efReactivate(id)  { setEthicsStatus(id, 'Active');        }

// ── Universal delegated event handler ──
// All card interactions use data-action attributes — no JS string quoting issues ever.
// ── Modal dismissal: Escape key + backdrop click ──
// Modals that must be acted on explicitly (security / acknowledgement) are never
// auto-dismissed by Escape or a backdrop click.
var NON_DISMISSIBLE_MODALS = ['sessionWarnModal', 'recoveryShowModal', 'changePassModal'];
// Map of confirm-style modals to the button that should fire on Escape (cancel path),
// so their pending Promise resolves correctly instead of hanging.
var MODAL_CANCEL_BTN = {
  pfConfirmModal: 'pfConfirmNo'
};
// Modals that manage their own teardown (form reset etc.): route Escape/backdrop
// through the dedicated close function rather than just stripping the .open class.
var MODAL_CLOSE_FN = {
  pfModal: 'closePersonnelModal',
  efModal: 'closeEthicsModal',
  linkPersonnelModal: 'closeLinkPersonnelModal'
};
// Return the open modal with the highest z-index (the visually topmost one).
function topOpenModal() {
  var open = Array.prototype.slice.call(
    document.querySelectorAll('.modal-overlay.open, .modal-overlay-2.open, .ef-modal-bg.open'));
  if (!open.length) return null;
  open.sort(function(a, b){
    return (parseInt(getComputedStyle(b).zIndex) || 0) - (parseInt(getComputedStyle(a).zIndex) || 0);
  });
  return open[0];
}
// Dismiss a specific modal element safely (respecting cancel buttons + the block list).
function dismissModal(modal) {
  if (!modal || !modal.id) return false;
  if (NON_DISMISSIBLE_MODALS.indexOf(modal.id) !== -1) return false;
  var cancelBtnId = MODAL_CANCEL_BTN[modal.id];
  if (cancelBtnId) {
    var btn = document.getElementById(cancelBtnId);
    if (btn) { btn.click(); return true; } // routes through the modal's own cancel logic
  }
  var closeFn = MODAL_CLOSE_FN[modal.id];
  if (closeFn && typeof window[closeFn] === 'function') {
    window[closeFn]();           // dedicated teardown (also removes .open via its own logic)
    modal.classList.remove('open');
    return true;
  }
  modal.classList.remove('open');
  return true;
}
function dismissTopModal() {
  var m = topOpenModal();
  return m ? dismissModal(m) : false;
}
document.addEventListener('keydown', function(ev) {
  if (ev.key === 'Escape' || ev.keyCode === 27) {
    if (dismissTopModal()) { ev.preventDefault(); ev.stopPropagation(); }
  }
});
// Backdrop click: dismiss only when both press and release land on the overlay
// itself (prevents accidental dismissal when text selection ends on the backdrop).
var _backdropDownTarget = null;
document.addEventListener('mousedown', function(ev) {
  _backdropDownTarget = ev.target;
});
document.addEventListener('mouseup', function(ev) {
  var t = ev.target;
  var sameTarget = (t === _backdropDownTarget);
  _backdropDownTarget = null;
  if (!sameTarget || !t || !t.classList) return;
  if ((t.classList.contains('modal-overlay') || t.classList.contains('modal-overlay-2') || t.classList.contains('ef-modal-bg')) && t.classList.contains('open')) {
    dismissModal(t);
  }
});

document.addEventListener('click', function(ev) {
  var el = ev.target.closest('[data-action]');
  if (!el) return;
  var action = el.dataset.action;
  var id     = el.dataset.id;
  var status = el.dataset.status;

  switch (action) {
    // Omega-1 trainings
    case 'close-training-modal':   closeTrainingModal(); break;
    case 'edit-training':          openTrainingModal(el.dataset.id); break;
    case 'delete-training':        deleteTraining(el.dataset.id); break;
    case 'open-pf-from-training':  openPersonnelFromTraining(el.dataset.pfid); break;
    case 'remove-trn-attendee':    removeTrainingAttendee(el.dataset.pfid); break;
    case 'open-training-tab':      { var tn=document.querySelector('#ngt-omega1 .nav-tab[onclick*="trainings"]'); if(tn) tn.click(); break; }
    case 'open-service-record':    openServiceRecord(el.dataset.pfid); break;
    case 'close-service-record':   closeServiceRecord(); break;
    case 'export-jacket':          exportPersonnelJacket(); break;
    case 'close-case-modal':       closeCaseModal(); break;
    case 'edit-case':              openCaseModal(el.dataset.id); break;
    case 'delete-case':            deleteCase(el.dataset.id); break;
    case 'cast-case-vote':         castCaseVote(el.dataset.id, el.dataset.vote); break;
    case 'remove-case-link':       removeCaseLink(el.dataset.sys, el.dataset.pfid); break;
    case 'open-case-file':         openFileFromCase(el.dataset.pfid, el.dataset.sys); break;
    // Tribunals
    case 'close-tribunal-modal':   closeTribunalModal(); break;
    case 'add-trib-item':          addTribItem(el.dataset.kind); break;
    case 'remove-trib-item':       removeTribItem(el.dataset.kind, el.dataset.idx); break;
    case 'accept-tribunal':        acceptTribunal(el.dataset.id); break;
    case 'deny-tribunal':          denyTribunal(el.dataset.id); break;
    case 'set-hearing-date':       setHearingDate(el.dataset.id); break;
    case 'post-tribunal-msg':      postTribunalMsg(el.dataset.id); break;
    case 'toggle-tribunal-thread': toggleTribunalThread(el.dataset.id); break;
    case 'open-outcome':           openOutcomeModal(el.dataset.id); break;
    case 'close-outcome-modal':    closeOutcomeModal(); break;
    case 'file-appeal':            fileAppeal(el.dataset.id); break;
    case 'take-appeal':            takeAppeal(el.dataset.id); break;
    case 'export-tribunal':        exportTribunal(el.dataset.id); break;
    case 'delete-tribunal':        deleteTribunal(el.dataset.id); break;
    case 'close-reason-modal':     closeReasonModal(); break;
    case 'submit-reason-modal':    submitReasonModal(); break;
    case 'save-tribunal-cfg':      saveTribunalCfg(); break;
    // Intel network
    case 'intel-view':             setIntelView(el.dataset.view); break;
    case 'close-informant-modal':  closeInformantModal(); break;
    case 'edit-informant':         openInformantModal(el.dataset.id); break;
    case 'delete-informant':       deleteInformant(el.dataset.id); break;
    case 'file-from-source':       openIntelReportModal(null, el.dataset.id); break;
    case 'close-intel-report-modal': closeIntelReportModal(); break;
    case 'edit-intel-report':      openIntelReportModal(el.dataset.id); break;
    case 'delete-intel-report':    deleteIntelReport(el.dataset.id); break;
    case 'escalate-report':        escalateReportToCase(el.dataset.id); break;
    case 'open-intel-file':        openIntelFile(el.dataset.pfid, el.dataset.sys); break;
    // Surveillance
    case 'place-surveillance':     openSurveillanceModal(el.dataset.sys, el.dataset.pfid); break;
    case 'adjust-surveillance':    openSurveillanceModal(el.dataset.sys, el.dataset.pfid); break;
    case 'lift-surveillance':      liftSurveillance(el.dataset.sys, el.dataset.pfid); break;
    case 'close-surveillance-modal': closeSurveillanceModal(); break;
    case 'open-intel-ref':         openIntelRef(el.dataset.ref); break;
    // Operations
    case 'close-operation-modal':  closeOperationModal(); break;
    case 'edit-operation':         openOperationModal(el.dataset.id); break;
    case 'delete-operation':       deleteOperation(el.dataset.id); break;
    case 'remove-op-operator':     removeOpOperator(el.dataset.pfid); break;
    case 'open-op-file':           openOpFile(el.dataset.pfid); break;
    case 'page-more':              pageMore(el.dataset.key); break;
    case 'select-theme':           selectTheme(el.dataset.theme); break;
    // Omega-1 card
    case 'toggle-pf':        ev.stopPropagation(); togglePfCard(id); break;
    case 'toggle-section':   ev.stopPropagation(); togglePfSection(id, el.dataset.section); break;
    case 'toggle-nav-dd': ev.stopPropagation(); toggleNavDd(el.dataset.group); break;
    case 'open-scout-modal':  openScoutModal(null); break;
    case 'close-scout-modal': closeScoutModal(); break;
    case 'save-scout':        saveScout(); break;
    case 'rec-advance':       recAdvance(el.dataset.id, el.dataset.to); break;
    case 'rec-archive':       recArchive(el.dataset.id, el.dataset.reason); break;
    case 'rec-vote':          recVote(el.dataset.id, el.dataset.vote); break;
    case 'rec-approve-final': recApproveFinal(el.dataset.id); break;
    case 'rec-add-strike':    recAddStrike(el.dataset.id, el.dataset.amount); break;
    case 'rec-remove-strike': recRemoveStrike(el.dataset.id); break;
    case 'close-strike-reason-modal': closeStrikeReasonModal(); break;
    case 'confirm-full-strike':       confirmFullStrike(); break;
    case 'add-rec-comment':   addRecComment(el.dataset.id); break;
    case 'toggle-rec-archive':toggleRecArchive(); break;
    // Ethics Orders
    case 'del-ethics-order-comment': deleteEthicsOrderComment(el.dataset.orderid, el.dataset.commentid); break;
    case 'toggle-eo-comments':       toggleEthicsComments(el.dataset.id); break;
    case 'del-eo':                   deleteEthicsOrder(el.dataset.id); break;
    case 'eo-status':                updateEthicsOrderStatus(el.dataset.id, el.value); break;
    case 'post-ethics-comment':      postEthicsComment(el.dataset.id); break;
    // Ethics Recruit
    case 'toggle-ethics-rec-archive': toggleEthicsRecArchive(); break;
    case 'open-ethics-app-modal':   openEthicsAppModal(el.dataset.id||null); break;
    case 'close-ethics-app-modal':  closeEthicsAppModal(); break;
    case 'save-ethics-app':         saveEthicsApp(); break;
    case 'open-ethics-deny-modal':  openEthicsDenyModal(el.dataset.id); break;
    case 'close-ethics-deny-modal': closeEthicsDenyModal(); break;
    case 'save-ethics-deny':        saveEthicsDeny(); break;
    case 'ethics-app-tag':          ethicsAppTag(el.dataset.id, el.dataset.tag); break;
    case 'ethics-rec-vote':         ethicsRecVote(el.dataset.id, el.dataset.vote); break;
    case 'ethics-rec-advance':      ethicsRecAdvance(el.dataset.id); break;
    case 'ethics-rec-pass':         ethicsRecPass(el.dataset.id); break;
    case 'add-ethics-app-comment':  addEthicsAppComment(el.dataset.id); break;
    case 'add-ethics-int-comment':  addEthicsIntComment(el.dataset.id); break;
    case 'del-ethics-app-comment':  deleteEthicsAppComment(el.dataset.recid, parseInt(el.dataset.created)); break;
    case 'del-ethics-int-comment':  deleteEthicsIntComment(el.dataset.recid, parseInt(el.dataset.created)); break;
    case 'poi-back':         renderPoiList(); break;
    case 'open-poi-file':        renderPoiFile(el.dataset.type, el.dataset.id); break;
    case 'edit-poi':             openPoiModal(el.dataset.id, el.dataset.poitype); break;
    case 'poi-photo-upload':     triggerPoiPhoto(el.dataset.poitype, el.dataset.id); break;
    case 'poi-photo-remove':     removePoiPhoto(el.dataset.poitype, el.dataset.id); break;
    case 'delete-poi':           deletePoi(el.dataset.id, el.dataset.poitype); break;
    case 'toggle-poi-archive':   togglePoiArchive(); break;
    case 'close-poi-file':       openPoiCloseModal(el.dataset.id, el.dataset.poitype); break;
    case 'reopen-poi':           reopenPoi(el.dataset.id, el.dataset.poitype); break;
    case 'close-poi-close-modal':closePoiCloseModal(); break;
    case 'save-poi-close':       savePoiClose(); break;
    case 'add-poi-note':     addPoiNote(el.dataset.id, el.dataset.poitype); break;
    case 'close-poi-modal':  closePoiModal(); break;
    case 'save-poi':         savePoi(); break;
    case 'del-order-comment':deleteOrderComment(el.dataset.orderid, el.dataset.commentid); break;
    case 'del-pf-note':      deletePfNote(el.dataset.pfid, parseInt(el.dataset.created)); break;
    case 'del-ef-note':      deleteEfNote(el.dataset.efid, parseInt(el.dataset.created)); break;
    case 'del-poi-note':     deletePoiNote(el.dataset.recid, el.dataset.poitype, parseInt(el.dataset.created)); break;
    case 'del-rec-comment':  deleteRecComment(el.dataset.recid, el.dataset.stage, parseInt(el.dataset.created)); break;
    case 'edit-pf':          ev.stopPropagation(); openPersonnelModal(id); break;
    case 'delete-pf':        ev.stopPropagation(); deletePersonnelRecord(id); break;
    case 'add-pf-note':      ev.stopPropagation(); addPersonnelNote(id); break;
    case 'apply-promote':    ev.stopPropagation(); applyPromote(id); break;
    case 'add-activity':            ev.stopPropagation(); addActivityEntry(id, el.dataset.unit || 'pf'); break;
    case 'del-activity':            ev.stopPropagation(); removeActivityEntry(id, el.dataset.unit || 'pf', el.dataset.actid); break;
    case 'set-activity-override':   ev.stopPropagation(); setActivityOverride(id, el.dataset.unit || 'pf'); break;
    case 'clear-activity-override': ev.stopPropagation(); clearActivityOverride(id, el.dataset.unit || 'pf'); break;
    case 'status-pf':        ev.stopPropagation(); setPersonnelStatus(id, status); break;
    case 'award-pf':         ev.stopPropagation(); openAwardModal(id); break;
    case 'del-award':        ev.stopPropagation(); removeAward(id, el.dataset.awardid); break;
    case 'open-tag-modal':   ev.stopPropagation(); openTagModal(id); break;
    case 'remove-tag':       ev.stopPropagation(); removeTag(id, el.dataset.tagtype); break;
    case 'issue-strike':     ev.stopPropagation(); openStrikeModal(id, null, el.dataset.sys||'pf'); break;
    case 'edit-strike':      ev.stopPropagation(); openStrikeModal(id, el.dataset.strikeid, el.dataset.sys||'pf'); break;
    case 'delete-strike':    ev.stopPropagation(); deleteStrike(id, el.dataset.strikeid, el.dataset.sys||'pf'); break;
    case 'appeal-strike':    ev.stopPropagation(); openAppealModal(id, el.dataset.strikeid, el.dataset.sys||'pf'); break;
    case 'uphold-strike':    ev.stopPropagation(); resolveStrikeAppeal(id, el.dataset.strikeid, 'Upheld',     el.dataset.sys||'pf'); break;
    case 'overturn-strike':  ev.stopPropagation(); resolveStrikeAppeal(id, el.dataset.strikeid, 'Overturned', el.dataset.sys||'pf'); break;
    case 'close-strike-modal':   closeStrikeModal(); break;
    case 'save-strike':          saveStrike(); break;
    case 'close-appeal-modal':   closeAppealModal(); break;
    case 'save-appeal':          saveAppeal(); break;
    case 'create-sqd':       ev.stopPropagation(); openSquadronModal('create', id, null, 'pf'); break;
    case 'open-sqd-add':     ev.stopPropagation(); openSquadronModal('add', el.dataset.pfid, el.dataset.sqdid, 'pf'); break;
    case 'delete-pf-sqd':   ev.stopPropagation(); deletePfSquadron(el.dataset.sqdid); break;
    // Ethics card
    case 'toggle-ef':        ev.stopPropagation(); toggleEfCard(id); break;
    case 'toggle-bl-dept':       toggleBlDept(el.dataset.id); break;
    case 'toggle-bl-sheet':      toggleBlSheet(el.dataset.id); break;
    case 'open-bl-appeal':       openBlAppeal(el.dataset.id); break;
    case 'close-bl-appeal':      closeBlAppeal(); break;
    case 'save-bl-appeal':       saveBlAppeal(); break;
    case 'bl-appeal-resolve':    resolveBlAppeal(el.dataset.id, el.dataset.res); break;
    case 'open-bl-entry-modal':  openBlEntryModal(el.dataset.deptid, el.dataset.deptname); break;
    case 'close-bl-entry-modal': closeBlEntryModal(); break;
    case 'save-bl-entry':        saveBlEntry(); break;
    case 'del-bl-entry':         deleteBlEntry(el.dataset.id); break;
    case 'open-bl-dept-modal':   openBlDeptModal(el.dataset.id || null); break;
    case 'close-bl-dept-modal':  closeBlDeptModal(); break;
    case 'save-bl-dept':         saveBlDept(); break;
    case 'del-bl-dept':          deleteBlDept(el.dataset.id); break;
    case 'toggle-ef-section': ev.stopPropagation(); toggleEfSection(id, el.dataset.section); break;
    case 'toggle-ethics-tag': toggleEthicsTag(el.dataset.efid, el.dataset.tag); break;
    case 'edit-ef':          ev.stopPropagation(); openEthicsModal(id); break;
    case 'delete-ef':        ev.stopPropagation(); deleteEthicsRecord(id); break;
    case 'add-ef-note':      ev.stopPropagation(); addEthicsNote(id); break;
    case 'status-ef':        ev.stopPropagation(); setEthicsStatus(id, status); break;
    case 'create-ef-sqd':    ev.stopPropagation(); openSquadronModal('create', id, null, 'ef'); break;
    case 'open-ef-sqd-add':  ev.stopPropagation(); openSquadronModal('add', el.dataset.efid, el.dataset.sqdid, 'ef'); break;
    case 'delete-ef-sqd':    ev.stopPropagation(); deleteEfSquadron(el.dataset.sqdid); break;
    // Modals
    case 'close-admin-modal':  closeAdminPanel(); break;
    case 'admin-approve':      adminApprove(el.dataset.uid); break;
    case 'admin-deny':         adminDeny(el.dataset.uid); break;
    case 'admin-set-cl':       adminSetClearance(el.dataset.uid); break;
    case 'admin-set-unit':     adminSetUnit(el.dataset.uid); break;
    case 'admin-link-file':    adminLinkFile(el.dataset.uid); break;
    case 'admin-unlink-file':  adminUnlinkFile(el.dataset.uid); break;
    case 'admin-reset-pass':   adminResetPass(el.dataset.uid); break;
    case 'admin-unlock':       adminUnlock(el.dataset.uid); break;
    case 'admin-ack-duress':   adminAckDuress(el.dataset.uid); break;
    case 'new-compartment':    openCompartmentModal(null); break;
    case 'edit-promoreq':      openPromoReqModal(el.dataset.key); break;
    case 'save-promo-meta':    savePromoMeta(); break;
    case 'save-activity-reqs': saveActivityReqs(); break;
    case 'restore-rec':        restoreRecord(el.dataset.kind, el.dataset.id); break;
    case 'purge-rec':          purgeRecord(el.dataset.kind, el.dataset.id); break;
    case 'close-promoreq':     closePromoReqModal(); break;
    case 'save-promoreq':      savePromoReq(); break;
    case 'edit-compartment':   openCompartmentModal(el.dataset.id); break;
    case 'close-compartment':  closeCompartmentModal(); break;
    case 'save-compartment':   saveCompartment(); break;
    case 'delete-compartment': deleteCompartment(); break;
    case 'admin-notes':        openAdminNotes(el.dataset.uid); break;
    case 'dir-select':         toggleDirSelect(el.dataset.uid, el.checked); break;
    case 'bulk-approve':       bulkApprove(); break;
    case 'bulk-clearance':     bulkSetClearance(); break;
    case 'bulk-retire':        bulkRetire(); break;
    case 'bulk-revoke':        bulkRevoke(); break;
    case 'bulk-clear':         clearDirSelection(); break;
    case 'close-admin-notes':  closeAdminNotes(); break;
    case 'save-admin-notes':   saveAdminNotes(); break;
    case 'del-admin-note':     delAdminNote(el.dataset.uid, el.dataset.at); break;
    case 'close-reason':       closeReasonModal(); break;
    case 'save-reason':        saveReason(); break;
    case 'export-users':       exportUsersCSV(); break;
    case 'export-audit':       exportAuditCSV(); break;
    case 'export-roster-pf':   exportRosterCSV('pf'); break;
    case 'export-roster-ef':   exportRosterCSV('ef'); break;
    case 'close-pass-reset':   closePassReset(); break;
    case 'save-pass-reset':    savePassReset(); break;
    case 'close-my-account':   closeMyAccount(); break;
    case 'open-change-pass':   openChangePass(); break;
    case 'session-stay':       sessionStay(); break;
    case 'session-logout-now': sessionExpire(); break;
    case 'ack-recovery':       ackRecoveryCodes(); break;
    case 'copy-recovery':      copyRecoveryCodes(); break;
    case 'open-forgot':        openForgot(); break;
    case 'close-forgot':       closeForgot(); break;
    case 'save-forgot':        saveForgot(); break;
    case 'regen-recovery':     regenerateRecoveryCodes(); break;
    case 'open-duress':        openDuressModal(); break;
    case 'close-duress':       closeDuressModal(); break;
    case 'save-duress':        saveDuressCode(); break;
    case 'clear-duress':       clearDuressCode(); break;
    case 'close-change-pass':  closeChangePass(); break;
    case 'save-change-pass':   saveChangePass(); break;
    case 'do-logout':          closeMyAccount(); logout(); break;
    case 'admin-retire':       adminRetire(el.dataset.uid); break;
    case 'admin-bulk-approve': adminBulkApprove(); break;
    case 'admin-refresh-audit':loadAuditLog(); break;
    case 'admin-revoke':       adminRevoke(el.dataset.uid); break;
    case 'close-award-modal':    closeAwardModal(); break;
    case 'save-award':           saveAward(); break;
    case 'close-tag-modal':      closeTagModal(); break;
    case 'save-tag':             saveTag(); break;
    case 'close-squadron-modal': closeSquadronModal(); break;
    case 'save-squadron':        saveSquadron(); break;
    // Leave / LoA / RoA
    case 'open-leave-modal': ev.stopPropagation(); openLeaveModal(el.dataset.id, el.dataset.division); break;
    case 'end-leave':        ev.stopPropagation(); endLeave(el.dataset.id, el.dataset.leaveid, el.dataset.division); break;
    case 'del-leave':        ev.stopPropagation(); deleteLeave(el.dataset.id, el.dataset.leaveid, el.dataset.division); break;
    case 'close-leave-modal': closeLeaveModal(); break;
    case 'save-leave':        saveLeave(); break;
  }
});

// Handle note Ctrl+Enter — uses data attributes, no quoting needed
function handleNoteKey(ev, textarea) {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    var id   = textarea.getAttribute('id'); // pfnote_xxx or efnote_xxx
    if (id && id.startsWith('pfnote_')) addPersonnelNote(id.slice(7));
    if (id && id.startsWith('efnote_')) addEthicsNote(id.slice(7));
  }
}

// ── Fix togglePfCard / toggleEfCard — these now just re-render ──
function togglePfCard(id) {
  if (pfExpanded.has(id)) pfExpanded.delete(id); else pfExpanded.add(id);
  renderPersonnelFiles();
}
function togglePfSection(pfId, section) {
  var key = pfId + ':' + section;
  if (pfCollapsed.has(key)) pfCollapsed.delete(key); else pfCollapsed.add(key);
  renderPersonnelFiles();
}
function toggleEfCard(id) {
  if (efExpanded.has(id)) efExpanded.delete(id); else efExpanded.add(id);
  renderEthicsFiles();
}
function toggleEfSection(efId, section) {
  var key = efId + ':' + section;
  if (efCollapsed.has(key)) efCollapsed.delete(key); else efCollapsed.add(key);
  renderEthicsFiles();
}

// ================================================================
//  AWARDS SYSTEM
// ================================================================
var AWARD_META = {
  'Medal of Honour':             { tier: 'Prestigious',   cls: 'award-prestigious' },
  'Distinguished Service Medal': { tier: 'Distinguished', cls: 'award-distinguished' },
  'Medal of Excellence':         { tier: 'Distinguished', cls: 'award-distinguished' },
  'Medal of Merit':              { tier: 'Distinguished', cls: 'award-distinguished' },
  'Medal of Valor':              { tier: 'Distinguished', cls: 'award-distinguished' },
  'Medal of Initiative':         { tier: 'Medal',         cls: 'award-medal' },
  'Medal of Novice':             { tier: 'Medal',         cls: 'award-medal' },
  'Medal of Heroism':            { tier: 'Medal',         cls: 'award-medal' },
  'Enforcement Medal':           { tier: 'Medal',         cls: 'award-medal' },
  'Specialist Medal':            { tier: 'Medal',         cls: 'award-medal' },
  'Leatherback Medal':           { tier: 'Medal',         cls: 'award-medal' },
};

function openAwardModal(pfId) {
  if (currentUser && currentUser.linkedPfId === pfId) {
    alert('YOU CANNOT AWARD MEDALS TO YOURSELF.');
    return;
  }
  if (!canEditPersonnel()) return;
  document.getElementById('awardTargetId').value = pfId;
  document.getElementById('awardName').value = '';
  document.getElementById('awardDate').value = new Date().toISOString().slice(0,10);
  document.getElementById('awardNotes').value = '';
  document.getElementById('awardErr').textContent = '';
  document.getElementById('awardModal').classList.add('open');
}
function closeAwardModal() { document.getElementById('awardModal').classList.remove('open'); }

async function saveAward() {
  var pfId    = document.getElementById('awardTargetId').value;
  var nameVal = document.getElementById('awardName').value;
  if (!nameVal) { document.getElementById('awardErr').textContent = '> SELECT AN AWARD'; return; }
  var parts   = nameVal.split('|');
  var name    = parts[0], tier = parts[1] || 'Medal';
  var date    = document.getElementById('awardDate').value;
  var notes   = document.getElementById('awardNotes').value.trim();
  if (!date)  { document.getElementById('awardErr').textContent = '> DATE REQUIRED'; return; }

  var rec = allPersonnel.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  if (!Array.isArray(rec.awards)) rec.awards = [];

  var award = {
    id: 'aw_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    name: name, tier: tier, date: date, notes: notes,
    awardedBy: currentUser ? currentUser.id : '—',
    created: Date.now()
  };
  rec.awards.push(award);
  rec.updated = Date.now();

  try {
    await personnelSet(pfId, rec);
    closeAwardModal();
    renderPersonnelFiles();
  } catch(err) {
    document.getElementById('awardErr').textContent = '> SAVE ERROR: ' + err.message;
  }
}

async function removeAward(pfId, awardId) {
  if (!canEditPersonnel()) return;
  if (!await pfConfirm('REMOVE THIS AWARD FROM RECORD?')) return;
  var rec = allPersonnel.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  rec.awards = (rec.awards || []).filter(function(a){ return a.id !== awardId; });
  rec.updated = Date.now();
  try { await personnelSet(pfId, rec); renderPersonnelFiles(); } catch(e) { alert('ERROR: ' + e.message); }
}

// ================================================================
//  TAGS SYSTEM
// ================================================================
var TAG_TYPES = ['Recruitment','Engagement','Development'];

function openTagModal(pfId) {
  if (!canEditPersonnel()) return;
  var tagRec = allPersonnel.find(function(p){ return p.id === pfId; });
  if (tagRec && !canManageFile(tagRec, 'pf')) { alert('You do not have authority to manage this file.'); return; }
  document.getElementById('tagTargetId').value = pfId;
  document.getElementById('tagType').value = '';
  document.getElementById('tagRole').value = '';
  document.getElementById('tagErr').textContent = '';
  document.getElementById('tagModal').classList.add('open');
}
function closeTagModal() { document.getElementById('tagModal').classList.remove('open'); }

async function saveTag() {
  var pfId = document.getElementById('tagTargetId').value;
  var type = document.getElementById('tagType').value;
  var role = document.getElementById('tagRole').value;
  if (!type) { document.getElementById('tagErr').textContent = '> SELECT A TEAM'; return; }
  if (!role) { document.getElementById('tagErr').textContent = '> SELECT A ROLE'; return; }

  var rec = allPersonnel.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  if (!Array.isArray(rec.tags)) rec.tags = [];
  // Remove any existing tag of the same type first
  rec.tags = rec.tags.filter(function(t){ return t.type !== type; });
  rec.tags.push({ type: type, role: role, assignedBy: currentUser ? currentUser.id : '—', assigned: Date.now() });
  rec.updated = Date.now();

  try {
    await personnelSet(pfId, rec);
    closeTagModal();
    renderPersonnelFiles();
  } catch(err) {
    document.getElementById('tagErr').textContent = '> SAVE ERROR: ' + err.message;
  }
}

async function removeTag(pfId, tagType) {
  if (!canEditPersonnel()) return;
  var rec = allPersonnel.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  if (!canManageFile(rec, 'pf')) { alert('You do not have authority to manage this file.'); return; }
  rec.tags = (rec.tags || []).filter(function(t){ return t.type !== tagType; });
  rec.updated = Date.now();
  try { await personnelSet(pfId, rec); renderPersonnelFiles(); } catch(e) { alert('ERROR: ' + e.message); }
}

// ================================================================
//  STRIKES SYSTEM
//  CL5 can issue, edit and delete strikes.
//  Any authenticated user can submit an appeal.
//  CL5 can resolve appeals (Uphold / Overturn).
//  Expired or overturned strikes disappear from the roster
//  but remain on the personnel file for documentation.
// ================================================================

// ── Comment / Note deletion (CL5 only) ──
function canDeleteComment() { return currentUser && parseInt(currentUser.clearance) >= 5; }

async function deleteOrderComment(orderId, commentId) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS COMMENT?')) return;
  try {
    if (firebaseReady) await fbDelete('/comments/' + orderId + '/' + commentId);
    else { var k = 'comments/'+orderId+'/'+commentId; lsDel(k); }
    toggleComments(orderId); // refresh
  } catch(e) { alert('ERROR: ' + e.message); }
}

async function deletePfNote(pfId, noteCreated) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS NOTE FROM THE RECORD?')) return;
  var rec = allPersonnel.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  rec.notes = (rec.notes||[]).filter(function(n){ return n && n.created !== noteCreated; });
  rec.updated = Date.now();
  try { await personnelSet(pfId, rec); renderPersonnelFiles(); } catch(e) { alert('ERROR: '+e.message); }
}

async function deleteEfNote(efId, noteCreated) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS NOTE FROM THE RECORD?')) return;
  var rec = allEthicsPersonnel.find(function(p){ return p.id === efId; });
  if (!rec) return;
  rec.notes = (rec.notes||[]).filter(function(n){ return n && n.created !== noteCreated; });
  rec.updated = Date.now();
  try { await ethicsPersonnelSet(efId, rec); renderEthicsFiles(); } catch(e) { alert('ERROR: '+e.message); }
}

async function deletePoiNote(id, type, noteCreated) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS NOTE?')) return;
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){ return x.id === id; });
  if (!rec) return;
  rec.notes = (rec.notes||[]).filter(function(n){ return n && n.created !== noteCreated; });
  try {
    if (type==='poi') await poiSet(id, rec); else await targetSet(id, rec);
    renderPoiFile(type, id);
  } catch(e) { alert('ERROR: '+e.message); }
}

async function deleteRecComment(recId, stage, noteCreated) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS COMMENT?')) return;
  var rec = allRecruitment.find(function(x){ return x.id === recId; });
  if (!rec) return;
  var key = stage+'Comments';
  rec[key] = (rec[key]||[]).filter(function(c){ return c.created !== noteCreated; });
  try { await recruitSet(recId, rec); renderRecruitment(); } catch(e) { alert('ERROR: '+e.message); }
}

function canIssueStrike() {
  return currentUser && parseInt(currentUser.clearance) >= 5;
}

function isStrikeActive(s) {
  if (!s) return false;
  if (s.status === 'Overturned') return false;
  if (s.expiresAt && new Date(s.expiresAt) < new Date()) return false;
  return true; // Active or Appealed, not expired
}

function strikeDisplayStatus(s) {
  if (s.status === 'Overturned')                              return { label: 'OVERTURNED',   cls: 'b-green',  cardCls: 'overturned' };
  if (s.expiresAt && new Date(s.expiresAt) < new Date())     return { label: 'EXPIRED',       cls: 'b-dim',    cardCls: 'expired'    };
  if (s.status === 'Appealed')                                return { label: 'UNDER APPEAL',  cls: 'b-amber',  cardCls: 'appealed'   };
  return                                                             { label: 'ACTIVE',        cls: 'b-red',    cardCls: ''           };
}

// ── Modal: Issue / Edit strike ──
function openStrikeModal(pfId, strikeId, system) {
  if (!canIssueStrike()) { alert('CLEARANCE LEVEL 5 REQUIRED TO ISSUE STRIKES'); return; }
  system = system || 'pf';
  document.getElementById('strikeTargetPfId').value    = pfId;
  document.getElementById('strikeTargetStrikeId').value= strikeId || '';
  document.getElementById('strikeSystem').value        = system;
  document.getElementById('strikeErr').textContent     = '';
  if (strikeId) {
    var system_edit = document.getElementById('strikeSystem').value || 'pf';
    var editSrcList = system_edit === 'ef' ? allEthicsPersonnel : allPersonnel;
    var rec = editSrcList.find(function(p){ return p.id === pfId; });
    var s   = rec && (rec.strikes||[]).find(function(x){ return x.id === strikeId; });
    if (!s) return;
    document.getElementById('strikeModalTitle').textContent = 'EDIT STRIKE';
    document.getElementById('strikeReason').value  = s.reason || '';
    document.getElementById('strikeExpiry').value  = s.expiresAt || '';
  } else {
    document.getElementById('strikeModalTitle').textContent = 'ISSUE STRIKE';
    document.getElementById('strikeReason').value  = '';
    document.getElementById('strikeExpiry').value  = '';
  }
  document.getElementById('strikeModal').classList.add('open');
}
function closeStrikeModal() { document.getElementById('strikeModal').classList.remove('open'); }

async function saveStrike() {
  if (!canIssueStrike()) return;
  var pfId     = document.getElementById('strikeTargetPfId').value;
  var strikeId = document.getElementById('strikeTargetStrikeId').value;
  var system   = document.getElementById('strikeSystem').value || 'pf';
  var reason   = document.getElementById('strikeReason').value.trim();
  var expiry   = document.getElementById('strikeExpiry').value;
  if (!reason) { document.getElementById('strikeErr').textContent = '> REASON REQUIRED'; return; }

  // Resolve which personnel list and save function to use
  var srcList = system === 'ef' ? allEthicsPersonnel : allPersonnel;
  var saveFn  = system === 'ef'
    ? function(id, data){ return ethicsPersonnelSet(id, data); }
    : function(id, data){ return personnelSet(id, data); };
  var renderFn = system === 'ef' ? function(){ renderEthicsFiles(); } : function(){ renderPersonnelFiles(); renderRoster(); };

  var rec = srcList.find(function(p){ return p.id === pfId; });
  if (!rec) {
    // allPersonnel may be stale — try a fresh fetch
    try {
      if (system === 'ef') {
        allEthicsPersonnel = partitionDeleted((await ethicsPersonnelGetAll()).filter(function(p){ return p && p.id; }), function(d){ deletedEthics = d; });
        srcList = allEthicsPersonnel;
      } else {
        var fresh = await personnelGetAll();
        allPersonnel = partitionDeleted(fresh.filter(function(p){ return p && p.id; }), function(d){ deletedPersonnel = d; });
        srcList = allPersonnel;
      }
      rec = srcList.find(function(p){ return p.id === pfId; });
    } catch(_) {}
    if (!rec) {
      document.getElementById('strikeErr').textContent = '> ERROR: Personnel record not found. Please refresh the page.';
      return;
    }
  }
  if (!Array.isArray(rec.strikes)) rec.strikes = [];

  if (strikeId) {
    var s = rec.strikes.find(function(x){ return x.id === strikeId; });
    if (!s) return;
    s.reason    = reason;
    s.expiresAt = expiry || null;
    s.editedBy  = currentUser.id;
    s.editedAt  = Date.now();
  } else {
    rec.strikes.push({
      id:         'str_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
      reason:     reason,
      expiresAt:  expiry || null,
      status:     'Active',
      appeal:     null,
      issuedBy:   currentUser.id,
      issuedAt:   Date.now()
    });
  }
  rec.updated = Date.now();
  try {
    await saveFn(pfId, rec);
    auditRecord('ISSUED STRIKE', (system==='ef'?'EC':'Ω-1')+' file '+pfId);
    closeStrikeModal();
    renderFn();
  } catch(e) { document.getElementById('strikeErr').textContent = '> SAVE ERROR: ' + e.message; }
}


async function deleteStrike(pfId, strikeId, system) {
  if (!canIssueStrike()) return;
  if (!await pfConfirm('CONFIRM: PERMANENTLY REMOVE THIS STRIKE FROM THE RECORD?')) return;
  system = system || 'pf';
  var srcList = system === 'ef' ? allEthicsPersonnel : allPersonnel;
  var rec = srcList.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  rec.strikes = (rec.strikes||[]).filter(function(s){ return s.id !== strikeId; });
  rec.updated = Date.now();
  try {
    if (system === 'ef') { await ethicsPersonnelSet(pfId, rec); efCollapsed.delete(pfId + ':strikes'); renderEthicsFiles(); }
    else { await personnelSet(pfId, rec); pfCollapsed.delete(pfId + ':strikes'); renderPersonnelFiles(); renderRoster(); }
  } catch(e) { alert('ERROR: ' + e.message); }
}

// ── Modal: Appeal ──
function openAppealModal(pfId, strikeId, system) {
  if (!currentUser) { alert('AUTHENTICATE TO SUBMIT AN APPEAL'); return; }
  document.getElementById('appealTargetPfId').value    = pfId;
  document.getElementById('appealTargetStrikeId').value= strikeId;
  document.getElementById('appealSystem').value        = system || 'pf';
  document.getElementById('appealReason').value        = '';
  document.getElementById('appealErr').textContent     = '';
  document.getElementById('appealModal').classList.add('open');
}
function closeAppealModal() { document.getElementById('appealModal').classList.remove('open'); }

async function saveAppeal() {
  var pfId     = document.getElementById('appealTargetPfId').value;
  var strikeId = document.getElementById('appealTargetStrikeId').value;
  var system   = document.getElementById('appealSystem').value || 'pf';
  var reason   = document.getElementById('appealReason').value.trim();
  if (!reason) { document.getElementById('appealErr').textContent = '> GROUNDS FOR APPEAL REQUIRED'; return; }

  var srcList = system === 'ef' ? allEthicsPersonnel : allPersonnel;
  var rec = srcList.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  var s = (rec.strikes||[]).find(function(x){ return x.id === strikeId; });
  if (!s) return;

  s.status = 'Appealed';
  s.appeal = { reason: reason, submittedBy: currentUser.id, submittedAt: Date.now(),
               resolution: null, resolvedBy: null, resolvedAt: null };
  rec.updated = Date.now();
  try {
    if (system === 'ef') { await ethicsPersonnelSet(pfId, rec); closeAppealModal(); renderEthicsFiles(); }
    else { await personnelSet(pfId, rec); closeAppealModal(); renderPersonnelFiles(); renderRoster(); }
  } catch(e) { document.getElementById('appealErr').textContent = '> SAVE ERROR: ' + e.message; }
}

// ── Resolve appeal (CL5 only) ──
async function resolveStrikeAppeal(pfId, strikeId, resolution, system) {
  if (currentUser && (currentUser.linkedPfId === pfId || currentUser.linkedEfId === pfId)) {
    alert('YOU CANNOT RESOLVE APPEALS ON YOUR OWN RECORD.');
    return;
  }
  if (!canIssueStrike()) return;
  var label = resolution === 'Overturned' ? 'OVERTURN (remove strike)' : 'UPHOLD (keep strike active)';
  if (!await pfConfirm('CONFIRM: ' + label + '?')) return;
  system = system || 'pf';
  var srcList = system === 'ef' ? allEthicsPersonnel : allPersonnel;
  var rec = srcList.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  var s = (rec.strikes||[]).find(function(x){ return x.id === strikeId; });
  if (!s || !s.appeal) return;

  s.status            = resolution === 'Overturned' ? 'Overturned' : 'Active';
  s.appeal.resolution = resolution;
  s.appeal.resolvedBy = currentUser.id;
  s.appeal.resolvedAt = Date.now();
  rec.updated = Date.now();
  try {
    if (system === 'ef') {
      await ethicsPersonnelSet(pfId, rec);
      efCollapsed.delete(pfId + ':strikes');
      renderEthicsFiles();
    } else {
      await personnelSet(pfId, rec);
      pfCollapsed.delete(pfId + ':strikes');
      renderPersonnelFiles(); renderRoster();
    }
  } catch(e) { alert('ERROR: ' + e.message); }
}
// ================================================================
var allSquadrons = [];

async function loadSquadrons() {
  try {
    if (firebaseReady) {
      var raw = await fbGetAll('/squadrons');
      allSquadrons = raw ? Object.values(raw).filter(function(s){ return s && s.id; }) : [];
    } else {
      allSquadrons = Object.values(lsAll('squadrons/')).filter(function(s){ return s && s.id; });
    }
  } catch(e) { allSquadrons = []; }
}

var allEthicsSquadrons = [];

async function loadEthicsSquadrons() {
  try {
    if (firebaseReady) {
      var raw = await fbGetAll('/ethics-squadrons');
      allEthicsSquadrons = raw ? Object.values(raw).filter(function(s){ return s && s.id; }) : [];
    } else {
      allEthicsSquadrons = Object.values(lsAll('ethics-squadrons/')).filter(function(s){ return s && s.id; });
    }
  } catch(e) { allEthicsSquadrons = []; }
}

async function squadronSet(id, data) {
  if (firebaseReady) await fbSet('/squadrons/' + id, data);
  else lsSet('squadrons/' + id, data);
}

async function ethicsSquadronSet(id, data) {
  if (firebaseReady) await fbSet('/ethics-squadrons/' + id, data);
  else lsSet('ethics-squadrons/' + id, data);
}

async function ethicsSquadronDel(id) {
  if (firebaseReady) await fbDelete('/ethics-squadrons/' + id);
  else lsDel('ethics-squadrons/' + id);
}

async function squadronDel(id) {
  if (firebaseReady) await fbDelete('/squadrons/' + id);
  else lsDel('squadrons/' + id);
}

function openSquadronModal(mode, memberId, sqdId, type) {
  if (!canEditPersonnel()) return;
  type = type || 'pf';
  if (memberId) {
    var sqUnit = type === 'ef' ? 'ef' : 'pf';
    var sqRec = (sqUnit === 'ef' ? allEthicsPersonnel : allPersonnel).find(function(p){ return p.id === memberId; });
    if (sqRec && !canManageFile(sqRec, sqUnit)) { alert('You do not have authority to manage this file.'); return; }
  }
  document.getElementById('squadronModalMode').value    = mode;
  document.getElementById('squadronType').value         = type;
  document.getElementById('squadronTargetPfId').value   = memberId || '';
  document.getElementById('squadronTargetSqdId').value  = sqdId || '';
  document.getElementById('squadronErr').textContent    = '';

  // Populate member select from the correct personnel list
  var sel = document.getElementById('squadronMemberSelect');
  sel.innerHTML = '<option value="">— SELECT PERSONNEL —</option>';
  var personnelList = type === 'ef'
    ? allEthicsPersonnel.filter(function(p){ return !p.status || p.status === 'Active'; })
    : allPersonnel.filter(function(p){ return !p.status || p.status === 'Active'; });
  personnelList.forEach(function(p) {
    var opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.name + (type === 'pf' && p.rank ? ' · ' + p.rank : type === 'ef' && p.role ? ' · ' + p.role : '');
    sel.appendChild(opt);
  });

  var sqdList = type === 'ef' ? allEthicsSquadrons : allSquadrons;

  if (mode === 'create') {
    document.getElementById('squadronModalTitle').textContent = 'CREATE ' + (type==='ef'?'ETHICS ':'') + 'SQUADRON';
    document.getElementById('squadronNameGroup').style.display   = 'block';
    document.getElementById('squadronMemberGroup').style.display = 'none';
    document.getElementById('squadronRankGroup').style.display   = 'none';
    document.getElementById('squadronName').value = '';
    document.getElementById('squadronCurrentMembers').innerHTML  = '';
  } else {
    document.getElementById('squadronModalTitle').textContent = 'ADD SQUADRON MEMBER';
    document.getElementById('squadronNameGroup').style.display   = 'none';
    document.getElementById('squadronMemberGroup').style.display = 'block';
    document.getElementById('squadronRankGroup').style.display   = 'block';
    var sqd = sqdList.find(function(s){ return s.id === sqdId; });
    if (sqd) {
      document.getElementById('squadronCurrentMembers').innerHTML =
        '<div style="font-size:.6rem;color:var(--text-dim);margin-bottom:.4rem;">CURRENT MEMBERS:</div>' +
        objArr(sqd.members).map(function(m) {
          return `<div class="sqd-member-row"><span>${e(m.name||m.memberId||m.pfId)}</span><span class="sqd-rank-badge ${m.rank==='Director'?'sqd-director':m.rank==='Co Director'?'sqd-codirector':m.rank==='Supervisor'?'sqd-supervisor':'sqd-agent'}">${e(m.rank)}</span><button class="award-del" data-action="remove-sqd-member" data-sqdid="${e(sqdId)}" data-memberid="${e(m.memberId||m.pfId)}" data-sqdtype="${type}" title="Remove">×</button></div>`;
        }).join('');
    }
  }
  document.getElementById('squadronModal').classList.add('open');
}

// Handle remove-sqd-member inside the modal
document.addEventListener('click', function(ev) {
  if (ev.target.dataset && ev.target.dataset.action === 'remove-sqd-member') {
    ev.stopPropagation();
    removeSqdMember(ev.target.dataset.sqdid, ev.target.dataset.memberid || ev.target.dataset.pfid, ev.target.dataset.sqdtype || 'pf');
  }
});

// Handle ethics orders status select (change event)
document.addEventListener('change', function(ev) {
  var el = ev.target.closest('[data-action]');
  if (!el) return;
  if (el.dataset.action === 'eo-status') {
    updateEthicsOrderStatus(el.dataset.id, el.value);
  }
});

async function removeSqdMember(sqdId, memberId, type) {
  type = type || 'pf';
  var sqdList = type === 'ef' ? allEthicsSquadrons : allSquadrons;
  var sqd = sqdList.find(function(s){ return s.id === sqdId; });
  if (!sqd) return;
  sqd.members = (sqd.members||[]).filter(function(m){ return (m.memberId||m.pfId) !== memberId; });
  if (type === 'ef') {
    await ethicsSquadronSet(sqdId, sqd);
    await loadEthicsSquadrons();
    renderEthicsFiles();
  } else {
    await squadronSet(sqdId, sqd);
    await loadSquadrons();
    renderPersonnelFiles();
  }
  openSquadronModal('add', null, sqdId, type);
}

function closeSquadronModal() { document.getElementById('squadronModal').classList.remove('open'); }

async function saveSquadron() {
  if (!canEditPersonnel()) return;
  var mode     = document.getElementById('squadronModalMode').value;
  var type     = document.getElementById('squadronType').value || 'pf';
  var memberId = document.getElementById('squadronTargetPfId').value;
  var sqdId    = document.getElementById('squadronTargetSqdId').value;
  document.getElementById('squadronErr').textContent = '';

  var sqdList     = type === 'ef' ? allEthicsSquadrons : allSquadrons;
  var setFn       = type === 'ef' ? ethicsSquadronSet  : squadronSet;
  var loadFn      = type === 'ef' ? loadEthicsSquadrons : loadSquadrons;
  var renderFn    = type === 'ef' ? renderEthicsFiles  : renderPersonnelFiles;
  var personnelList = type === 'ef' ? allEthicsPersonnel : allPersonnel;

  if (mode === 'create') {
    var name = document.getElementById('squadronName').value.trim();
    if (!name) { document.getElementById('squadronErr').textContent = '> NAME REQUIRED'; return; }
    var creator = personnelList.find(function(p){ return p.id === memberId; });
    var newSqd = {
      id: (type==='ef'?'efsqd_':'sqd_') + Date.now() + '_' + Math.random().toString(36).slice(2,5),
      name: name, type: type,
      createdByMemberId: memberId,
      members: [{ memberId: memberId, pfId: memberId, name: creator ? creator.name : memberId, rank: 'Director', addedBy: currentUser ? currentUser.id : '—', added: Date.now() }],
      createdBy: currentUser ? currentUser.id : '—',
      created: Date.now()
    };
    try {
      await setFn(newSqd.id, newSqd);
      sqdList.push(newSqd);
      closeSquadronModal();
      renderFn();
    } catch(e) { document.getElementById('squadronErr').textContent = '> ERROR: ' + e.message; }
  } else {
    var newMemberId = document.getElementById('squadronMemberSelect').value;
    var rank        = document.getElementById('squadronMemberRank').value;
    if (!newMemberId) { document.getElementById('squadronErr').textContent = '> SELECT A MEMBER'; return; }
    var sqd = sqdList.find(function(s){ return s.id === sqdId; });
    if (!sqd) return;
    if (!sqd.members) sqd.members = [];
    if (sqd.members.find(function(m){ return (m.memberId||m.pfId) === newMemberId; })) {
      document.getElementById('squadronErr').textContent = '> ALREADY A MEMBER'; return;
    }
    var memberRec = personnelList.find(function(p){ return p.id === newMemberId; });
    sqd.members.push({ memberId: newMemberId, pfId: newMemberId, name: memberRec ? memberRec.name : newMemberId, rank: rank, addedBy: currentUser ? currentUser.id : '—', added: Date.now() });
    try {
      await setFn(sqdId, sqd);
      await loadFn();
      closeSquadronModal();
      renderFn();
    } catch(e) { document.getElementById('squadronErr').textContent = '> ERROR: ' + e.message; }
  }
}

async function deletePfSquadron(sqdId) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) { alert('CLEARANCE LEVEL 5 REQUIRED TO DELETE SQUADRONS'); return; }
  var sqd = allSquadrons.find(function(s){ return s.id === sqdId; });
  if (!sqd) return;
  if (!await pfConfirm('CONFIRM: PERMANENTLY DELETE SQUADRON "' + sqd.name + '"?')) return;
  try {
    await squadronDel(sqdId);
    allSquadrons = allSquadrons.filter(function(s){ return s.id !== sqdId; });
    renderPersonnelFiles();
  } catch(e) { alert('ERROR: ' + e.message); }
}

async function deleteEfSquadron(sqdId) {
  if (!currentUser || parseInt(currentUser.clearance) < 5) { alert('CLEARANCE LEVEL 5 REQUIRED TO DELETE SQUADRONS'); return; }
  var sqd = allEthicsSquadrons.find(function(s){ return s.id === sqdId; });
  if (!sqd) return;
  if (!await pfConfirm('CONFIRM: PERMANENTLY DELETE SQUADRON "' + sqd.name + '"?')) return;
  try {
    await ethicsSquadronDel(sqdId);
    allEthicsSquadrons = allEthicsSquadrons.filter(function(s){ return s.id !== sqdId; });
    renderEthicsFiles();
  } catch(e) { alert('ERROR: ' + e.message); }
}

// ================================================================
//  RECRUITMENT SYSTEM
// ================================================================
var allRecruitment = [];
var recArchiveOpen = false;

// ── Firebase helpers ──
async function recruitGetAll() {
  if (firebaseReady) { var r=await fbGetAll('/recruitment'); return r?Object.values(r).filter(x=>x&&x.id):[];}
  return Object.values(lsAll('recruitment/')).filter(x=>x&&x.id);
}
async function recruitSet(id,data) {
  if(firebaseReady) await fbSet('/recruitment/'+id,data); else lsSet('recruitment/'+id,data);
}
async function recruitDel(id) {
  if(firebaseReady) await fbDelete('/recruitment/'+id); else lsDel('recruitment/'+id);
}

// ── Load ──
async function loadRecruitment() {
  try { allRecruitment = (await recruitGetAll()).sort(function(a,b){return b.created-a.created;}); }
  catch(e) { allRecruitment = []; }
  var canEdit = currentUser && parseInt(currentUser.clearance) >= 4;
  var btn = document.getElementById('newScoutBtn');
  if (btn) btn.style.display = canEdit ? 'inline-block' : 'none';
  renderRecruitment();
}

// ── Helpers ──
function recYes(r)   { return Object.values(r.votes||{}).filter(function(v){return v==='yes';}).length; }
function recNo(r)    { return Object.values(r.votes||{}).filter(function(v){return v==='no';}).length;  }
function recMajYes(r){ var y=recYes(r),n=recNo(r); return (y+n)>0 && y>n; }

// ── Render ──
function renderRecruitment() {
  var scouting  = allRecruitment.filter(function(r){return r.stage==='scouting';});
  var greenlit  = allRecruitment.filter(function(r){return r.stage==='greenlit';});
  var tryout    = allRecruitment.filter(function(r){return r.stage==='tryout';});
  var archived  = allRecruitment.filter(function(r){return r.stage==='archived';});
  var canEdit   = currentUser && parseInt(currentUser.clearance) >= 4;

  var el; var empty = '<div class="poi-empty">[ NONE ]</div>';

  // Section 1 — Scouting
  el = document.getElementById('recScoutingList');
  if (el) el.innerHTML = scouting.length ? scouting.map(function(r){ return buildRecCard(r, canEdit); }).join('') : empty;

  // Section 2 — Greenlit
  el = document.getElementById('recGreenlitList');
  if (el) el.innerHTML = greenlit.length ? greenlit.map(function(r){ return buildRecCard(r, canEdit); }).join('') : empty;

  // Section 3 — Tryout
  el = document.getElementById('recTryoutList');
  if (el) el.innerHTML = tryout.length ? tryout.map(function(r){ return buildRecCard(r, canEdit); }).join('') : empty;

  // Archive count
  var cnt = document.getElementById('recArchiveCount');
  if (cnt) cnt.textContent = archived.length;
  if (recArchiveOpen) renderRecArchive();
  updateRecruitBadge();
}

function buildRecCard(r, canEdit) {
  var stageCls = {scouting:'b-cyan', greenlit:'b-green', tryout:'b-amber', archived:'b-dim'};
  var myVote   = currentUser ? (r.votes||{})[currentUser.id] : null;
  var y = recYes(r), n = recNo(r), maj = recMajYes(r);

  // Show comments from ALL stages up to and including current, so history persists
  var stageOrder = ['scouting','greenlit','tryout'];
  var stageKeys  = {scouting:'scoutingComments', greenlit:'greenlitComments', tryout:'tryoutComments'};
  var stageLabels= {scouting:'SCOUTING', greenlit:'GREENLIT', tryout:'TRYOUT'};
  var currentStageIdx = stageOrder.indexOf(r.stage);
  var commKey  = stageKeys[r.stage] || 'scoutingComments';

  // Build comment HTML showing prior stages as read-only history, current stage with add-form
  function buildStageCommentBlock(stageKey, stageLabel, isCurrent) {
    var arr = Array.isArray(r[stageKey]) ? r[stageKey] : [];
    if (!arr.length && !isCurrent) return '';
    var header = isCurrent ? '' :
      '<div style="font-size:.54rem;letter-spacing:.12em;color:var(--text-faint);margin:.4rem 0 .2rem;border-top:1px dashed var(--border);padding-top:.4rem;">▸ FROM ' + stageLabel + ' STAGE</div>';
    var rows = arr.length ? arr.map(function(c) {
      var ct = safeDateTime(c.created);
      return '<div class="rec-comment"><div class="rec-comment-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·'+e(c.author)+' [L'+e(c.clearance)+'] · '+ct+'</span>'
        + (canDeleteComment() ? '<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-rec-comment" data-recid="'+e(r.id)+'" data-stage="'+stageKey.replace('Comments','')+'" data-created="'+c.created+'" title="Delete">×</button>' : '')
        + '</div>'+e(c.text)+'</div>';
    }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);">[ NO COMMENTS ]</div>';
    return header + rows;
  }

  var commHtml = '';
  if (currentStageIdx > 0) {
    // Show history from prior stages
    for (var si = 0; si < currentStageIdx; si++) {
      commHtml += buildStageCommentBlock(stageKeys[stageOrder[si]], stageLabels[stageOrder[si]], false);
    }
    if (commHtml) commHtml += '<div style="font-size:.54rem;letter-spacing:.12em;color:var(--text-dim);margin:.4rem 0 .2rem;border-top:1px dashed var(--border);padding-top:.4rem;">▸ CURRENT STAGE COMMENTS</div>';
  }
  // Current stage comments
  var currComments = Array.isArray(r[commKey]) ? r[commKey] : [];
  commHtml += currComments.length
    ? currComments.map(function(c) {
        var ct = safeDateTime(c.created);
        return '<div class="rec-comment"><div class="rec-comment-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·'+e(c.author)+' [L'+e(c.clearance)+'] · '+ct+'</span>'
          + (canDeleteComment() ? '<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-rec-comment" data-recid="'+e(r.id)+'" data-stage="'+e(r.stage)+'" data-created="'+c.created+'" title="Delete">×</button>' : '')
          + '</div>'+e(c.text)+'</div>';
      }).join('')
    : '<div style="font-size:.6rem;color:var(--text-faint);">[ NO COMMENTS ]</div>';

  var commentForm = currentUser
    ? `<div class="poi-note-form" style="margin-top:.35rem;">
        <textarea class="poi-note-input" id="recnote_${e(r.id)}" placeholder="Add comment... (Ctrl+Enter)" rows="2" onkeydown="handleRecNoteKey(event,this)"></textarea>
        <button class="rec-btn" data-action="add-rec-comment" data-id="${e(r.id)}">[ ADD ]</button>
      </div>` : '';

  // Vote bar (greenlit only)
  var voteBar = r.stage === 'greenlit' && canEdit ? `
    <div class="rec-vote-bar">
      <span>VOTES:</span>
      <span style="color:#44dd88;">✓ ${y} YES</span>
      <span style="color:#dd4444;">✗ ${n} NO</span>
      ${maj ? '<span class="rec-majority">⚑ MAJORITY YES — READY FOR APPROVAL</span>' : ''}
      ${currentUser ? `
        <button class="rec-vote-btn yes${myVote==='yes'?' voted':''}" data-action="rec-vote" data-id="${e(r.id)}" data-vote="yes">✓ YES</button>
        <button class="rec-vote-btn no${myVote==='no'?' voted':''}"  data-action="rec-vote" data-id="${e(r.id)}" data-vote="no">✗ NO</button>
      ` : ''}
    </div>` : '';

  // Action buttons
  var btns = '<div class="rec-btns">';
  if (canEdit) {
    if (r.stage==='scouting') {
      btns += `<button class="rec-btn approve" data-action="rec-advance" data-id="${e(r.id)}" data-to="greenlit">→ GREENLIT</button>`;
      btns += `<button class="rec-btn deny"    data-action="rec-archive" data-id="${e(r.id)}" data-reason="denied">✗ DENY</button>`;
    }
    if (r.stage==='greenlit') {
      if (maj) btns += `<button class="rec-btn approve" data-action="rec-advance" data-id="${e(r.id)}" data-to="tryout">→ TRYOUT</button>`;
      btns += `<button class="rec-btn deny" data-action="rec-archive" data-id="${e(r.id)}" data-reason="denied">✗ DENY</button>`;
    }
    if (r.stage==='tryout') {
      var strikes    = (r.tryoutStrikes !== undefined) ? r.tryoutStrikes : 0;
      var strikeLbl  = strikes === 0 ? '<span style="color:var(--green-dim);">○ ○  0 / 1</span>'
                     : strikes === 0.5 ? '<span style="color:var(--amber);">◑ ○  0.5 / 1</span>'
                     : '<span style="color:#dd4444;">● ●  1 / 1 — DISQUALIFIED</span>';
      btns += '<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem;flex-wrap:wrap;border:1px solid var(--border2);padding:.3rem .5rem;">'
            + '<span style="font-size:.58rem;color:var(--text-dim);letter-spacing:.08em;">STRIKES:</span>'
            + strikeLbl;
      if (canEdit && strikes < 1) {
        if (strikes < 0.5) {
          btns += `<button class="rec-btn" data-action="rec-add-strike" data-id="${e(r.id)}" data-amount="0.5" style="font-size:.55rem;padding:1px 7px;border-color:var(--amber);color:var(--amber);">+ ½ STRIKE</button>`;
        }
        btns += `<button class="rec-btn deny" data-action="rec-add-strike" data-id="${e(r.id)}" data-amount="1" style="font-size:.55rem;padding:1px 7px;">+ FULL STRIKE</button>`;
      }
      if (canEdit && strikes > 0 && strikes < 1) {
        btns += `<button class="rec-btn" data-action="rec-remove-strike" data-id="${e(r.id)}" style="font-size:.55rem;padding:1px 6px;opacity:.65;">↩ CLEAR</button>`;
      }
      btns += '</div>';
      if (strikes < 1) {
        btns += `<button class="rec-btn approve" data-action="rec-approve-final" data-id="${e(r.id)}">✓ APPROVE & CREATE FILE</button>`;
      }
      btns += `<button class="rec-btn deny" data-action="rec-archive" data-id="${e(r.id)}" data-reason="denied">✗ DENY</button>`;
    }
  }
  btns += '</div>';

  return `<div class="rec-card" id="reccard_${e(r.id)}">
    <div class="rec-card-header">
      <div>
        <div class="rec-name">${e(r.name||'—')}</div>
        <div class="rec-meta">SteamID: ${e(r.steamId||'—')} · Dept: ${e(r.department||'—')} · Rank: ${e(r.rank||'—')}</div>
        <div style="margin-top:3px;"><span class="badge ${stageCls[r.stage]||'b-dim'}">${r.stage.toUpperCase()}</span></div>
      </div>
    </div>
    ${voteBar}
    <div style="border-top:1px solid var(--border);margin:.4rem 0 .3rem;"></div>
    ${commHtml}
    ${commentForm}
    ${btns}
  </div>`;
}

function renderRecArchive() {
  var el = document.getElementById('recArchivedList');
  if (!el) return;
  var archived = allRecruitment.filter(function(r){return r.stage==='archived';});
  archived.sort(function(a,b){return (b.archivedAt||0)-(a.archivedAt||0);});
  if (!archived.length) { el.innerHTML = '<div class="poi-empty">[ NO ARCHIVED RECRUITMENT ]</div>'; return; }
  el.innerHTML = archived.map(function(r) {
    var status = r.archiveStatus === 'approved'
      ? '<span class="badge b-green">APPROVED</span>'
      : '<span class="badge b-red">DENIED</span>';
    var reasonHtml = r.archiveReason
      ? `<div style="font-size:.6rem;color:var(--text-dim);margin-top:5px;border-left:2px solid var(--border2);padding-left:6px;font-style:italic;">${e(r.archiveReason)}</div>`
      : '';
    return `<div class="rec-card" style="opacity:.82;">
      <div class="rec-card-header">
        <div>
          <div class="rec-name">${e(r.name||'—')}</div>
          <div class="rec-meta">SteamID: ${e(r.steamId||'—')} · ${e(r.department||'—')} · ${e(r.rank||'—')}</div>
          <div style="margin-top:3px;">${status}</div>
          ${reasonHtml}
        </div>
      </div>
    </div>`;
  }).join('');
}

function toggleRecArchive() {
  recArchiveOpen = !recArchiveOpen;
  var el    = document.getElementById('recArchivedList');
  var arrow = document.getElementById('recArchiveArrow');
  if (arrow) arrow.textContent = recArchiveOpen ? '▾' : '▸';
  if (el)    el.style.display  = recArchiveOpen ? 'block' : 'none';
  if (recArchiveOpen) renderRecArchive();
}

// ── Modal: create scouting target ──
function openScoutModal(editId) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) return;
  document.getElementById('scoutModalEditId').value = editId || '';
  document.getElementById('scoutErr').textContent   = '';
  document.getElementById('scoutModalTitle').textContent = editId ? 'EDIT SCOUTING TARGET' : 'NEW SCOUTING TARGET';
  if (editId) {
    var r = allRecruitment.find(function(x){return x.id===editId;});
    if (r) {
      document.getElementById('scoutName').value    = r.name    || '';
      document.getElementById('scoutSteamId').value = r.steamId || '';
      document.getElementById('scoutDept').value    = r.department || '';
      document.getElementById('scoutRank').value    = r.rank    || '';
    }
  } else {
    document.getElementById('scoutName').value = '';
    document.getElementById('scoutSteamId').value = '';
    document.getElementById('scoutDept').value = '';
    document.getElementById('scoutRank').value = '';
  }
  document.getElementById('scoutModal').classList.add('open');
}
function closeScoutModal() { document.getElementById('scoutModal').classList.remove('open'); }

async function saveScout() {
  var editId = document.getElementById('scoutModalEditId').value;
  var name   = document.getElementById('scoutName').value.trim();
  var steam  = document.getElementById('scoutSteamId').value.trim();
  var dept   = document.getElementById('scoutDept').value;
  var rank   = document.getElementById('scoutRank').value.trim();
  if (!name)  { document.getElementById('scoutErr').textContent = '> NAME REQUIRED';       return; }
  if (!steam) { document.getElementById('scoutErr').textContent = '> STEAM ID REQUIRED';   return; }
  if (!dept)  { document.getElementById('scoutErr').textContent = '> DEPARTMENT REQUIRED'; return; }

  if (editId) {
    var r = allRecruitment.find(function(x){return x.id===editId;});
    if (!r) return;
    r.name = name; r.steamId = steam; r.department = dept; r.rank = rank;
    r.updatedBy = currentUser.id; r.updated = Date.now();
    try { await recruitSet(editId, r); } catch(err) { document.getElementById('scoutErr').textContent='> ERROR: '+err.message; return; }
  } else {
    var newR = {
      id:               'rec_'+Date.now()+'_'+Math.random().toString(36).slice(2,4),
      stage:            'scouting', archiveStatus: null,
      name: name, steamId: steam, department: dept, rank: rank,
      scoutingComments: [], greenlitComments: [], tryoutComments: [],
      votes: {}, tryoutStrikes: 0, personnelFileId: null,
      createdBy: currentUser.id, created: Date.now(), transitions: []
    };
    try { await recruitSet(newR.id, newR); allRecruitment.unshift(newR); }
    catch(err) { document.getElementById('scoutErr').textContent='> ERROR: '+err.message; return; }
  }
  closeScoutModal();
  renderRecruitment();
}

// ── Stage actions ──
async function recAdvance(id, toStage) {
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r || !currentUser || parseInt(currentUser.clearance) < 4) return;
  var label = toStage === 'greenlit' ? '→ GREENLIT' : '→ TRYOUT';
  if (!await pfConfirm('ADVANCE ' + e(r.name) + ' ' + label + '?')) return;
  r.transitions = r.transitions || [];
  r.transitions.push({ from: r.stage, to: toStage, by: currentUser.id, at: Date.now() });
  r.stage = toStage;
  try { await recruitSet(id, r); renderRecruitment(); } catch(err) { alert('ERROR: '+err.message); }
}

async function recArchive(id, reason) {
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r || !currentUser || parseInt(currentUser.clearance) < 4) return;
  if (!await pfConfirm('DENY AND ARCHIVE ' + e(r.name) + '?')) return;
  r.transitions = r.transitions || [];
  r.transitions.push({ from: r.stage, to: 'archived', by: currentUser.id, at: Date.now(), reason: reason });
  r.stage = 'archived'; r.archiveStatus = 'denied'; r.archivedAt = Date.now();
  try { await recruitSet(id, r); renderRecruitment(); } catch(err) { alert('ERROR: '+err.message); }
}

async function recVote(id, vote) {
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r || !currentUser || parseInt(currentUser.clearance) < 4) return;
  if (!r.votes) r.votes = {};
  r.votes[currentUser.id] = vote;
  try { await recruitSet(id, r); renderRecruitment(); } catch(err) { alert('ERROR: '+err.message); }
}

// ── Tryout strike management ──
function openStrikeReasonModal(id) {
  document.getElementById('strikeReasonId').value   = id;
  document.getElementById('strikeReasonText').value  = '';
  document.getElementById('strikeReasonErr').textContent = '';
  document.getElementById('strikeReasonModal').classList.add('open');
}
function closeStrikeReasonModal() { document.getElementById('strikeReasonModal').classList.remove('open'); }

async function confirmFullStrike() {
  var id     = document.getElementById('strikeReasonId').value;
  var reason = document.getElementById('strikeReasonText').value.trim();
  if (!reason) { document.getElementById('strikeReasonErr').textContent = '> REASON REQUIRED'; return; }
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r) return;
  r.tryoutStrikes = 1;
  r.strikeLog = r.strikeLog || [];
  r.strikeLog.push({ amount: 1, reason: reason, by: currentUser.id, at: Date.now() });
  r.stage = 'archived'; r.archiveStatus = 'denied';
  r.archiveReason = 'Full strike issued during tryout: ' + reason;
  r.archivedAt = Date.now();
  r.transitions = r.transitions || [];
  r.transitions.push({ from:'tryout', to:'archived', by:currentUser.id, at:Date.now(), reason:'full strike: '+reason });
  try {
    await recruitSet(id, r);
    closeStrikeReasonModal();
    renderRecruitment();
  } catch(err) { document.getElementById('strikeReasonErr').textContent = '> ERROR: '+err.message; }
}

async function recAddStrike(id, amount) {
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r || !currentUser || parseInt(currentUser.clearance) < 4) return;
  if (parseFloat(amount) >= 1) {
    // Full strike → open reason modal
    openStrikeReasonModal(id);
    return;
  }
  // Half strike — no reason required, just confirm
  var current = r.tryoutStrikes || 0;
  if (!await pfConfirm('Issue ½ strike to ' + e(r.name) + '?\nCurrent: ' + current + ' → 0.5 / 1')) return;
  r.tryoutStrikes = 0.5;
  r.strikeLog = r.strikeLog || [];
  r.strikeLog.push({ amount: 0.5, by: currentUser.id, at: Date.now() });
  try { await recruitSet(id, r); renderRecruitment(); }
  catch(err) { alert('ERROR: ' + err.message); }
}

async function recRemoveStrike(id) {
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r || !currentUser || parseInt(currentUser.clearance) < 4) return;
  if (!await pfConfirm('CLEAR strikes for ' + e(r.name) + '?')) return;
  r.tryoutStrikes = 0;
  try { await recruitSet(id, r); renderRecruitment(); } catch(err) { alert('ERROR: ' + err.message); }
}

async function recApproveFinal(id) {
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r || !currentUser || parseInt(currentUser.clearance) < 4) return;
  if (!await pfConfirm('APPROVE ' + e(r.name) + ' AND CREATE OMEGA-1 PERSONNEL FILE?')) return;
  // Store pending recruitment ID so savePersonnelRecord can close it
  window._pendingRecruitApproval = { recId: id, rec: r };
  // Pre-fill modal
  openPersonnelModal(null);
  setTimeout(function() {
    var nameEl = document.getElementById('pfName');
    if (nameEl) nameEl.value = r.name || '';
  }, 50);
}

// Called by savePersonnelRecord after creating the file
async function finaliseRecruitApproval(newPersonnelId) {
  if (!window._pendingRecruitApproval) return;
  var rec = window._pendingRecruitApproval.rec;
  rec.transitions = rec.transitions || [];
  rec.transitions.push({ from: rec.stage, to: 'archived', by: currentUser.id, at: Date.now(), reason: 'approved' });
  rec.stage = 'archived'; rec.archiveStatus = 'approved';
  rec.archivedAt = Date.now(); rec.personnelFileId = newPersonnelId;
  try { await recruitSet(rec.id, rec); renderRecruitment(); } catch(e) { console.error(e); }
  window._pendingRecruitApproval = null;
}

// ── Comments ──
async function addRecComment(id) {
  if (!currentUser) return;
  var inp = document.getElementById('recnote_' + id);
  if (!inp || !inp.value.trim()) return;
  var r = allRecruitment.find(function(x){return x.id===id;});
  if (!r) return;
  var stageKeys = {scouting:'scoutingComments', greenlit:'greenlitComments', tryout:'tryoutComments'};
  var key = stageKeys[r.stage] || 'scoutingComments';
  if (!Array.isArray(r[key])) r[key] = [];
  r[key].push({ author: currentUser.id, clearance: currentUser.clearance, text: inp.value.trim(), created: Date.now() });
  try { await recruitSet(id, r); inp.value = ''; renderRecruitment(); } catch(err) { alert('ERROR: '+err.message); }
}

function handleRecNoteKey(ev, el) {
  if (ev.key==='Enter' && (ev.ctrlKey||ev.metaKey)) {
    ev.preventDefault();
    var id = el.id.replace('recnote_','');
    addRecComment(id);
  }
}

// ================================================================
//  ETHICS ORDERS SYSTEM
//  Mirrors Omega-1 orders but uses /ethics-orders/ and /ethics-comments/
// ================================================================
var allEthicsOrders = [];
var activeEthicsFilter = 'ALL';

function setEthicsFilter(f, btn) {
  activeEthicsFilter = f; _filtSet('ethicsOrders', f);
  document.querySelectorAll('#ethicsOrderFilters .filter-btn').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  renderEthicsOrders();
}

async function ethicsOrdersGetAll() {
  if (firebaseReady) { var r=await fbGetAll('/ethics-orders'); return r?Object.values(r):[];}
  return Object.values(lsAll('ethics-orders/'));
}
async function ethicsOrderSet(id,d)  { if(firebaseReady)await fbSet('/ethics-orders/'+id,d);  else lsSet('ethics-orders/'+id,d); }
async function ethicsOrderDel(id)    { if(firebaseReady)await fbDelete('/ethics-orders/'+id);  else lsDel('ethics-orders/'+id); }
async function ethicsCommentSet(oid,cid,d){ if(firebaseReady)await fbSet('/ethics-comments/'+oid+'/'+cid,d); else lsSet('ethics-comments/'+oid+'/'+cid,d); }
async function ethicsCommentDel(oid,cid)  { if(firebaseReady)await fbDelete('/ethics-comments/'+oid+'/'+cid); else lsDel('ethics-comments/'+oid+'/'+cid); }
async function ethicsCommentsGetAll(oid){ if(firebaseReady){var r=await fbGetAll('/ethics-comments/'+oid);return r?Object.values(r):[]; } return Object.values(lsAll('ethics-comments/'+oid+'/')); }

// Ethics orders state (mirrors Omega-1 pattern)
var ethicsExpandedOrders = new Set();
var ethicsCommentCache   = {};

async function loadEthicsOrders() {
  try {
    var raw = await ethicsOrdersGetAll();
    allEthicsOrders = partitionDeleted(raw.filter(function(o){return o&&o.id;}), function(d){ deletedEthicsOrders = d; }).sort(function(a,b){return b.created-a.created;});
  } catch(e){ allEthicsOrders=[]; }
  renderEthicsOrders();
  updateEthicsOrderBadge();
}

async function submitEthicsOrder() {
  if (!currentUser) return;
  var title = document.getElementById('ethicsOrderTitle').value.trim();
  var body  = document.getElementById('ethicsOrderBody').value.trim();
  if (!title) return;
  var id = 'eord_'+Date.now()+'_'+Math.random().toString(36).slice(2,4);
  var order = { id:id, title:title, body:body,
    priority: document.getElementById('ethicsOrderPriority').value,
    status:   document.getElementById('ethicsOrderStatus').value,
    minClearance: document.getElementById('ethicsOrderMinClearance').value || '3',
    compartment: (document.getElementById('ethicsOrderCompartment') || {}).value || null,
    author: currentUser.id, clearance: currentUser.clearance, created: Date.now() };
  try {
    await ethicsOrderSet(id, order);
    allEthicsOrders.unshift(order);
    document.getElementById('ethicsOrderTitle').value = '';
    document.getElementById('ethicsOrderBody').value  = '';
    document.getElementById('ethicsOrderMinClearance').value = '3';
    renderEthicsOrders();
    updateEthicsOrderBadge();
  } catch(e){ alert('ERROR: '+e.message); }
}

async function updateEthicsOrderStatus(id, status) {
  var o = allEthicsOrders.find(function(x){return x.id===id;});
  if (!o) return;
  o.status = status;
  try { await ethicsOrderSet(id, o); renderEthicsOrders(); updateEthicsOrderBadge(); } catch(e){ alert('ERROR: '+e.message); }
}

async function deleteEthicsOrder(id) {
  if (!await pfConfirm('Move this Ethics order to the recycle bin?\n\nIt can be restored by CL5 command from the admin panel.')) return;
  var o = allEthicsOrders.find(function(x){ return x.id===id; });
  if (o) {
    o.deleted = true; o.deletedBy = currentUser.id; o.deletedAt = Date.now();
    try { await ethicsOrderSet(id, o); } catch(e){ alert('ERROR: '+e.message); return; }
    auditRecord('DELETED ETHICS ORDER', (o.title||id) + ' → recycle bin');
    allEthicsOrders = allEthicsOrders.filter(function(x){return x.id!==id;});
    if (!deletedEthicsOrders.some(function(x){ return x.id===id; })) deletedEthicsOrders.push(o);
  }
  ethicsExpandedOrders.delete(id);
  delete ethicsCommentCache[id];
  renderEthicsOrders();
  updateEthicsOrderBadge();
}

async function toggleEthicsComments(orderId) {
  if (ethicsExpandedOrders.has(orderId)) {
    ethicsExpandedOrders.delete(orderId);
    renderEthicsOrders();
  } else {
    ethicsExpandedOrders.add(orderId);
    if (!ethicsCommentCache[orderId]) {
      ethicsCommentCache[orderId] = [];
      try {
        var raw = await ethicsCommentsGetAll(orderId);
        ethicsCommentCache[orderId] = raw.filter(function(c){ return c&&c.id; });
      } catch(err) {}
    }
    renderEthicsOrders();
    var inp = document.getElementById('ethcinput_'+orderId);
    if (inp) inp.focus();
  }
}

async function postEthicsComment(orderId) {
  if (!currentUser) return;
  var inp = document.getElementById('ethcinput_'+orderId);
  if (!inp) return;
  var text = inp.value.trim();
  if (!text) return;
  var btn = inp.nextElementSibling;
  if (btn) { btn.disabled=true; btn.textContent='[ POSTING... ]'; }
  inp.disabled = true;
  var comment = {
    id: 'ec_'+Date.now()+'_'+Math.random().toString(36).slice(2,5),
    author: currentUser.id, clearance: currentUser.clearance, text: text, created: Date.now()
  };
  try {
    await ethicsCommentSet(orderId, comment.id, comment);
    if (!ethicsCommentCache[orderId]) ethicsCommentCache[orderId] = [];
    ethicsCommentCache[orderId].push(comment);
    inp.value = '';
  } catch(err) { alert('POST ERROR: '+err.message); }
  if (btn) { btn.disabled=false; btn.textContent='[ POST ]'; }
  inp.disabled = false;
  renderEthicsOrders();
  var newInp = document.getElementById('ethcinput_'+orderId);
  if (newInp) newInp.focus();
}

function handleEthicsCommentKey(ev, orderId) {
  if (ev.key==='Enter' && (ev.ctrlKey||ev.metaKey)) { ev.preventDefault(); postEthicsComment(orderId); }
}

async function deleteEthicsOrderComment(orderId, commentId) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS COMMENT?')) return;
  try {
    await ethicsCommentDel(orderId, commentId);
    if (ethicsCommentCache[orderId])
      ethicsCommentCache[orderId] = ethicsCommentCache[orderId].filter(function(c){ return c.id!==commentId; });
    renderEthicsOrders();
  } catch(e){ alert('ERROR: '+e.message); }
}

function renderEthicsOrders() {
  var el = document.getElementById('ethicsOrdersList');
  if (!el) return;
  var canEdit = currentUser && parseInt(currentUser.clearance) >= 4;
  var isCL5   = currentUser && parseInt(currentUser.clearance) >= 5;
  var PBADGE  = { ELEVATED:'b-cyan', URGENT:'b-amber', CRITICAL:'b-red' };
  var SBADGE  = { PENDING:'b-amber', ACTIVE:'b-green', COMPLETE:'b-dim', CANCELLED:'b-dim' };

  // Update stats
  var pend   = allEthicsOrders.filter(function(o){return o.status==='PENDING';}).length;
  var active = allEthicsOrders.filter(function(o){return o.status==='ACTIVE';}).length;
  var done   = allEthicsOrders.filter(function(o){return o.status==='COMPLETE';}).length;
  var tot = document.getElementById('eoStatTotal');  if(tot)  tot.textContent  = allEthicsOrders.length;
  var ep  = document.getElementById('eoStatPend');   if(ep)   ep.textContent   = pend;
  var ea  = document.getElementById('eoStatActive'); if(ea)   ea.textContent   = active;
  var ed  = document.getElementById('eoStatDone');   if(ed)   ed.textContent   = done;

  var filtered = activeEthicsFilter === 'ALL'
    ? allEthicsOrders
    : allEthicsOrders.filter(function(o){ return o.status === activeEthicsFilter; });

  if (!filtered.length) {
    el.innerHTML = '<div class="order-empty">[ NO ETHICS ORDERS MATCH CURRENT FILTER ]</div>';
    return;
  }
  el.innerHTML = filtered.map(function(o) {
    var ts       = safeDateTime(o.created);
    var expanded = ethicsExpandedOrders.has(o.id);
    var cached   = ethicsCommentCache[o.id] || [];
    var cCount   = cached.length;

    var statusOpts = ['PENDING','ACTIVE','COMPLETE','CANCELLED'].map(function(s) {
      return '<option value="' + s + '"' + (o.status===s?' selected':'') + '>' + s + '</option>';
    }).join('');
    // Use onchange inline (not data-action) to prevent re-render from destroying the select mid-interaction
    var statusCtrl = canEdit
      ? '<select class="status-select" onchange="updateEthicsOrderStatus(\'' + e(o.id) + '\',this.value)">' + statusOpts + '</select>'
      : '<span class="badge ' + (SBADGE[o.status]||'b-dim') + '">' + e(o.status) + '</span>';

    var commentsHtml = '';
    if (expanded) {
      var threadHtml = cCount === 0
        ? '<div class="comment-empty">[ NO COMMENTS ]</div>'
        : cached.slice().sort(function(a,b){return a.created-b.created;}).map(function(c) {
            var cts = safeDateTime(c.created);
            var del = canDeleteComment()
              ? '<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-ethics-order-comment" data-orderid="' + e(o.id) + '" data-commentid="' + e(c.id) + '">×</button>'
              : '';
            return '<div class="comment-entry">' +
              '<div class="comment-gutter"></div>' +
              '<div class="comment-body">' +
                '<div class="comment-meta" style="display:flex;justify-content:space-between;align-items:center;">' +
                  '<span>EC·' + e(c.author) + ' [L' + e(c.clearance) + '] · ' + cts + ' UTC</span>' + del +
                '</div>' +
                '<div class="comment-text">' + e(c.text) + '</div>' +
              '</div>' +
            '</div>';
          }).join('');

      var formHtml = currentUser
        ? '<div class="comment-form">' +
            '<textarea class="comment-input" id="ethcinput_' + e(o.id) + '" placeholder="Add comment..." rows="2" data-orderid="' + e(o.id) + '" onkeydown="if(event.key===\'Enter\'&&(event.ctrlKey||event.metaKey)){event.preventDefault();postEthicsComment(this.dataset.orderid);}"></textarea>' +
            '<button class="comment-submit" data-action="post-ethics-comment" data-id="' + e(o.id) + '">[ POST ]</button>' +
          '</div>'
        : '<div class="comment-empty">[ AUTHENTICATE TO COMMENT ]</div>';

      commentsHtml = '<div class="order-comments"><div class="comment-thread">' + threadHtml + '</div>' + formHtml + '</div>';
    }

    var toggleLabel = expanded
      ? '▾ hide comments' + (cCount ? ' (' + cCount + ')' : '')
      : '▸ comments' + (cCount ? ' (' + cCount + ')' : ' (0)');

    // ── Clearance gate ──
    if (orderIsRestricted(o)) return buildOrderDeniedCard(o, 'eocard_' + e(o.id));

    return '<div class="order-card" id="eocard_' + e(o.id) + '">' +
      '<div class="dir-banner top ' + directiveBannerClass(o.priority) + '">' + directiveClassification(o) + '</div>' +
      '<div class="dir-letterhead">' +
        '<div class="dir-seal-mark">' +
          '<span class="org">◆ ETHICS COMMITTEE</span>' +
          'O5 OVERSIGHT · CAIRO.AIC TERMINAL' +
        '</div>' +
        '<div class="dir-ref">' +
          '<span class="refno">' + directiveRef(o) + '</span><br>' +
          ts + ' UTC' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:.5rem;flex-wrap:wrap;">' +
        '<div style="flex:1;min-width:0;">' +
          '<div style="font-family:\'Share Tech Mono\',monospace;font-size:.5rem;letter-spacing:.18em;color:var(--text-faint);">ETHICS COMMITTEE DIRECTIVE</div>' +
          '<div class="dir-title">' + e(o.title) + '</div>' +
        '</div>' +
        '<div class="order-card-actions">' +
          statusCtrl +
          '<button class="order-action-btn" onclick="exportOrderDocument(\'' + e(o.id) + '\', \'ef\')" title="Export as formal document" style="font-size:.6rem;">⎙ DOC</button>' +
          (isCL5 ? '<button class="order-action-btn" onclick="openEthicsOrderEdit(\'' + e(o.id) + '\')" title="Edit order" style="font-size:.6rem;">✎</button>' : '') +
          (canEdit ? '<button class="order-action-btn del-btn" data-action="del-eo" data-id="' + e(o.id) + '">✕</button>' : '') +
        '</div>' +
      '</div>' +
      '<div class="dir-fields">' +
        '<div class="dir-field"><span class="k">Priority</span><span class="v"><span class="badge ' + (PBADGE[o.priority]||'b-dim') + '">' + e(o.priority) + '</span></span></div>' +
        '<div class="dir-field"><span class="k">Filed</span><span class="v">' + ts + ' UTC</span></div>' +
        (o.compartment ? '<div class="dir-field"><span class="k">Program</span><span class="v">▢ ' + e(compartmentName(o.compartment) || 'COMPARTMENTED') + '</span></div>' : '') +
      '</div>' +
      (o.body ? '<div class="dir-body">' + e(o.body) + '</div>' : '') +
      '<div class="dir-authorization">' +
        '<div class="dir-sig"><span class="by">By order of</span><br><span class="who">EC·' + e(o.author) + '</span> · Clearance L' + e(o.clearance) + '</div>' +
        '<div class="dir-stamp ' + directiveStamp(o.status).cls + '">' + e(directiveStamp(o.status).label) + '</div>' +
      '</div>' +
      (o.editedBy ? '<div style="font-size:.56rem;color:var(--text-faint);margin-top:5px;">✎ last amended by EC·' + e(o.editedBy) + ' · ' + safeDateTime(o.editedAt) + ' UTC</div>' : '') +
      '<div class="comment-toggle" data-action="toggle-eo-comments" data-id="' + e(o.id) + '">' + toggleLabel + '</div>' +
      commentsHtml +
      '<div class="dir-banner bottom ' + directiveBannerClass(o.priority) + '">' + directiveClassification(o) + '</div>' +
    '</div>';
  }).join('');
}


// ================================================================
//  ETHICS RECRUIT SYSTEM
// ================================================================
var allEthicsRecruit   = [];
var ethicsRecArchiveOpen = false;

async function ethicsRecruitGetAll() {
  if (firebaseReady){ var r=await fbGetAll('/ethics-recruitment'); return r?Object.values(r).filter(function(x){return x&&x.id;}):[];}
  return Object.values(lsAll('ethics-recruitment/')).filter(function(x){return x&&x.id;});
}
async function ethicsRecruitSet(id,data){ if(firebaseReady)await fbSet('/ethics-recruitment/'+id,data); else lsSet('ethics-recruitment/'+id,data); }

async function loadEthicsRecruit() {
  try { allEthicsRecruit=(await ethicsRecruitGetAll()).sort(function(a,b){return b.created-a.created;}); }
  catch(e){ allEthicsRecruit=[]; }
  var canEdit = currentUser && parseInt(currentUser.clearance) >= 4;
  var btn = document.getElementById('newEthicsAppBtn');
  if (btn) btn.style.display = canEdit ? 'inline-block' : 'none';
  renderEthicsRecruit();
  updateEthicsRecruitBadge();
}

var ETHICS_APP_TAGS = ['In Progress','Taken to interview','Accepted','Denied'];
var ETHICS_TAG_CLS  = { 'In Progress':'b-cyan','Taken to interview':'b-amber','Accepted':'b-green','Denied':'b-red' };

function ethicsRecYes(r) { return Object.values(r.votes||{}).filter(function(v){return v==='yes';}).length; }
function ethicsRecNo(r)  { return Object.values(r.votes||{}).filter(function(v){return v==='no';}).length; }
function ethicsRecMajYes(r){ var y=ethicsRecYes(r),n=ethicsRecNo(r); return (y+n)>0&&y>n; }

function renderEthicsRecruit() {
  var apps       = allEthicsRecruit.filter(function(r){return r.stage==='application';});
  var interviews = allEthicsRecruit.filter(function(r){return r.stage==='interview';});
  var archived   = allEthicsRecruit.filter(function(r){return r.stage==='archived';});
  var canEdit    = currentUser && parseInt(currentUser.clearance) >= 4;
  var isCL5      = currentUser && parseInt(currentUser.clearance) >= 5;
  var empty      = '<div class="poi-empty">[ NONE ]</div>';

  var appEl = document.getElementById('ethicsAppList');
  if (appEl) appEl.innerHTML = apps.length ? apps.map(function(r){ return buildEthicsAppCard(r, canEdit, isCL5); }).join('') : empty;

  var intEl = document.getElementById('ethicsInterviewList');
  if (intEl) intEl.innerHTML = interviews.length ? interviews.map(function(r){ return buildEthicsInterviewCard(r, isCL5); }).join('') : empty;

  var cnt = document.getElementById('ethicsRecArchiveCount');
  if (cnt) cnt.textContent = archived.length;
  if (ethicsRecArchiveOpen) renderEthicsRecArchive();
  updateEthicsRecruitBadge();
}

function buildEthicsAppCard(r, canEdit, isCL5) {
  var tag     = r.tag || 'In Progress';
  var tagCls  = ETHICS_TAG_CLS[tag] || 'b-dim';
  var myVote  = currentUser ? (r.votes||{})[currentUser.id] : null;
  var y=ethicsRecYes(r), n=ethicsRecNo(r), maj=ethicsRecMajYes(r);
  var comments = Array.isArray(r.applicationComments) ? r.applicationComments : [];

  var commHtml = comments.map(function(c){
    var ct = safeDateTime(c.created);
    return `<div class="rec-comment"><div class="rec-comment-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·${e(c.author)} [L${e(c.clearance)}] · ${ct}</span>${canDeleteComment()?`<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-ethics-app-comment" data-recid="${e(r.id)}" data-created="${c.created}">×</button>`:''}</div>${e(c.text)}</div>`;
  }).join('') || '<div style="font-size:.6rem;color:var(--text-faint);">[ NO COMMENTS ]</div>';

  var commentForm = canEdit ? `<div class="poi-note-form" style="margin-top:.35rem;"><textarea class="poi-note-input" id="ethicsappnote_${e(r.id)}" placeholder="Add comment... (Ctrl+Enter)" rows="2" onkeydown="handleEthicsAppNoteKey(event,this)"></textarea><button class="rec-btn" data-action="add-ethics-app-comment" data-id="${e(r.id)}">[ ADD ]</button></div>` : '';

  var tagBar = canEdit ? `<div style="margin:.4rem 0;display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;"><span style="font-size:.58rem;color:var(--text-dim);">TAG:</span>${ETHICS_APP_TAGS.map(function(t){ return `<button class="rec-btn${tag===t?' approve':''}" data-action="ethics-app-tag" data-id="${e(r.id)}" data-tag="${t}" style="font-size:.55rem;padding:1px 6px;">${t}</button>`; }).join('')}</div>` : `<div style="margin:.3rem 0;"><span class="badge ${tagCls}">${e(tag)}</span></div>`;

  var voteBar = canEdit ? `<div class="rec-vote-bar">
    <span>VOTES:</span><span style="color:#44dd88;">✓ ${y} YES</span><span style="color:#dd4444;">✗ ${n} NO</span>
    ${maj ? '<span class="rec-majority">⚑ MAJORITY YES</span>' : ''}
    <button class="rec-vote-btn yes${myVote==='yes'?' voted':''}" data-action="ethics-rec-vote" data-id="${e(r.id)}" data-vote="yes">✓ YES</button>
    <button class="rec-vote-btn no${myVote==='no'?' voted':''}"  data-action="ethics-rec-vote" data-id="${e(r.id)}" data-vote="no">✗ NO</button>
  </div>` : '';

  var actionBtns = `<div class="rec-btns">
    ${isCL5 && maj ? `<button class="rec-btn approve" data-action="ethics-rec-advance" data-id="${e(r.id)}">→ INTERVIEW</button>` : ''}
    ${isCL5 ? `<button class="rec-btn deny" data-action="open-ethics-deny-modal" data-id="${e(r.id)}">✗ DENY</button>` : ''}
    ${canEdit ? `<button class="rec-btn" data-action="open-ethics-app-modal" data-id="${e(r.id)}" style="font-size:.55rem;">EDIT</button>` : ''}
  </div>`;

  return `<div class="rec-card">
    <div class="rec-card-header"><div>
      <div class="rec-name">${e(r.name||'—')}</div>
      <div class="rec-meta">SteamID: ${e(r.steamId||'—')} · Dept: ${e(r.department||'—')} · Rank: ${e(r.rank||'—')}</div>
      ${r.applicationLink ? `<div class="rec-meta"><a href="${e(r.applicationLink)}" target="_blank" style="color:var(--cyan);">📄 Application Link</a></div>` : ''}
    </div></div>
    ${tagBar}${voteBar}
    <div style="border-top:1px solid var(--border);margin:.4rem 0 .3rem;"></div>
    ${commHtml}${commentForm}${actionBtns}
  </div>`;
}

function buildEthicsInterviewCard(r, isCL5) {
  // Show application comments as history, then interview comments
  var appComments = Array.isArray(r.applicationComments) ? r.applicationComments : [];
  var comments    = Array.isArray(r.interviewComments)   ? r.interviewComments   : [];

  var historyHtml = appComments.length
    ? '<div style="font-size:.54rem;letter-spacing:.12em;color:var(--text-faint);margin-bottom:.3rem;border-bottom:1px dashed var(--border);padding-bottom:.3rem;">▸ FROM APPLICATION STAGE</div>'
      + appComments.map(function(c){
          var ct = safeDateTime(c.created);
          return '<div class="rec-comment" style="opacity:.75;"><div class="rec-comment-meta">EC·'+e(c.author)+' [L'+e(c.clearance)+'] · '+ct+'</div>'+e(c.text)+'</div>';
        }).join('')
      + '<div style="font-size:.54rem;letter-spacing:.12em;color:var(--text-dim);margin:.4rem 0 .2rem;border-top:1px dashed var(--border);padding-top:.4rem;">▸ INTERVIEW NOTES (CL5 ONLY)</div>'
    : '';
  var commHtml = historyHtml + (comments.length
    ? comments.map(function(c){
        var ct = safeDateTime(c.created);
        return `<div class="rec-comment"><div class="rec-comment-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·${e(c.author)} [L${e(c.clearance)}] · ${ct}</span>${canDeleteComment()?`<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-ethics-int-comment" data-recid="${e(r.id)}" data-created="${c.created}">×</button>`:''}</div>${e(c.text)}</div>`;
      }).join('')
    : '<div style="font-size:.6rem;color:var(--text-faint);">[ NO INTERVIEW NOTES ]</div>');

  var commentForm = isCL5 ? `<div class="poi-note-form" style="margin-top:.35rem;"><textarea class="poi-note-input" id="ethicsinterviewnote_${e(r.id)}" placeholder="Interview notes (CL5 only)..." rows="2" onkeydown="handleEthicsIntNoteKey(event,this)"></textarea><button class="rec-btn" data-action="add-ethics-int-comment" data-id="${e(r.id)}">[ ADD ]</button></div>` : '<div style="font-size:.6rem;color:var(--text-faint);margin-top:.3rem;">[ CL5 ONLY — INTERVIEW NOTES ]</div>';

  var actionBtns = isCL5 ? `<div class="rec-btns">
    <button class="rec-btn approve" data-action="ethics-rec-pass" data-id="${e(r.id)}">✓ PASS INTERVIEW & CREATE FILE</button>
    <button class="rec-btn deny"    data-action="open-ethics-deny-modal" data-id="${e(r.id)}">✗ FAIL INTERVIEW</button>
  </div>` : '';

  return `<div class="rec-card">
    <div class="rec-card-header"><div>
      <div class="rec-name">${e(r.name||'—')}</div>
      <div class="rec-meta">SteamID: ${e(r.steamId||'—')} · Dept: ${e(r.department||'—')} · Rank: ${e(r.rank||'—')}</div>
      <span class="badge b-amber">TAKEN TO INTERVIEW</span>
    </div></div>
    <div style="border-top:1px solid var(--border);margin:.4rem 0 .3rem;"></div>
    ${commHtml}${commentForm}${actionBtns}
  </div>`;
}

function renderEthicsRecArchive() {
  var el = document.getElementById('ethicsRecArchivedList');
  if (!el) return;
  var archived = allEthicsRecruit.filter(function(r){return r.stage==='archived';}).sort(function(a,b){return (b.archivedAt||0)-(a.archivedAt||0);});
  el.innerHTML = archived.length ? archived.map(function(r){
    var cls = r.archiveStatus==='approved' ? 'b-green' : 'b-red';
    var lbl = r.archiveStatus==='approved' ? 'APPROVED' : 'DENIED';
    return `<div class="rec-card" style="opacity:.75;">
      <div class="rec-name">${e(r.name||'—')}</div>
      <div class="rec-meta">SteamID: ${e(r.steamId||'—')} · ${e(r.department||'—')}</div>
      <span class="badge ${cls}">${lbl}</span>
      ${r.archiveReason ? `<div style="font-size:.6rem;color:var(--text-dim);margin-top:3px;"><em>${e(r.archiveReason)}</em></div>` : ''}
    </div>`;
  }).join('') : '<div class="poi-empty">[ NO ARCHIVED APPLICATIONS ]</div>';
}

function toggleEthicsRecArchive() {
  ethicsRecArchiveOpen = !ethicsRecArchiveOpen;
  var el    = document.getElementById('ethicsRecArchivedList');
  var arrow = document.getElementById('ethicsRecArchiveArrow');
  if (arrow) arrow.textContent = ethicsRecArchiveOpen ? '▾' : '▸';
  if (el)    el.style.display  = ethicsRecArchiveOpen ? 'block' : 'none';
  if (ethicsRecArchiveOpen) renderEthicsRecArchive();
}

// ── Application modal ──
function openEthicsAppModal(editId) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) return;
  document.getElementById('ethicsAppEditId').value = editId || '';
  document.getElementById('ethicsAppErr').textContent = '';
  document.getElementById('ethicsAppModalTitle').textContent = editId ? 'EDIT APPLICATION' : 'NEW ETHICS APPLICATION';
  if (editId) {
    var r = allEthicsRecruit.find(function(x){return x.id===editId;});
    if (r) {
      document.getElementById('ethicsAppName').value    = r.name||'';
      document.getElementById('ethicsAppSteamId').value = r.steamId||'';
      document.getElementById('ethicsAppDept').value    = r.department||'';
      document.getElementById('ethicsAppRank').value    = r.rank||'';
      document.getElementById('ethicsAppLink').value    = r.applicationLink||'';
    }
  } else {
    ['ethicsAppName','ethicsAppSteamId','ethicsAppDept','ethicsAppRank','ethicsAppLink'].forEach(function(id){ document.getElementById(id).value=''; });
  }
  document.getElementById('ethicsAppModal').classList.add('open');
}
function closeEthicsAppModal() { document.getElementById('ethicsAppModal').classList.remove('open'); }

async function saveEthicsApp() {
  var editId = document.getElementById('ethicsAppEditId').value;
  var name   = document.getElementById('ethicsAppName').value.trim();
  var steam  = document.getElementById('ethicsAppSteamId').value.trim();
  var dept   = document.getElementById('ethicsAppDept').value;
  var rank   = document.getElementById('ethicsAppRank').value.trim();
  var link   = document.getElementById('ethicsAppLink').value.trim();
  if (!name)  { document.getElementById('ethicsAppErr').textContent='> NAME REQUIRED';       return; }
  if (!steam) { document.getElementById('ethicsAppErr').textContent='> STEAM ID REQUIRED';   return; }
  if (!dept)  { document.getElementById('ethicsAppErr').textContent='> DEPARTMENT REQUIRED'; return; }
  if (editId) {
    var r = allEthicsRecruit.find(function(x){return x.id===editId;});
    if (!r) return;
    r.name=name; r.steamId=steam; r.department=dept; r.rank=rank; r.applicationLink=link;
    r.updatedBy=currentUser.id; r.updated=Date.now();
    try { await ethicsRecruitSet(editId, r); } catch(err){ document.getElementById('ethicsAppErr').textContent='> ERROR: '+err.message; return; }
  } else {
    var newR = { id:'erec_'+Date.now()+'_'+Math.random().toString(36).slice(2,4),
      stage:'application', archiveStatus:null, archiveReason:null, tag:'In Progress',
      name, steamId:steam, department:dept, rank, applicationLink:link,
      applicationComments:[], interviewComments:[], votes:{},
      createdBy:currentUser.id, created:Date.now(), transitions:[] };
    try { await ethicsRecruitSet(newR.id, newR); allEthicsRecruit.unshift(newR); }
    catch(err){ document.getElementById('ethicsAppErr').textContent='> ERROR: '+err.message; return; }
  }
  closeEthicsAppModal();
  renderEthicsRecruit();
}

// ── Tag update ──
async function ethicsAppTag(id, tag) {
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r) return;
  r.tag = tag; r.updated = Date.now();
  try { await ethicsRecruitSet(id, r); renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}

// ── Voting ──
async function ethicsRecVote(id, vote) {
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r||!currentUser||parseInt(currentUser.clearance)<4) return;
  if (!r.votes) r.votes={};
  r.votes[currentUser.id] = vote;
  try { await ethicsRecruitSet(id, r); renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}

// ── Advance to interview (CL5, majority yes required) ──
async function ethicsRecAdvance(id) {
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r||!currentUser||parseInt(currentUser.clearance)<5) return;
  if (!await pfConfirm('ADVANCE '+e(r.name)+' TO INTERVIEW STAGE?')) return;
  r.stage='interview'; r.tag='Taken to interview';
  r.transitions=r.transitions||[];
  r.transitions.push({from:'application',to:'interview',by:currentUser.id,at:Date.now()});
  try { await ethicsRecruitSet(id, r); renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}

// ── Deny modal ──
function openEthicsDenyModal(id) {
  if (!currentUser||parseInt(currentUser.clearance)<5) return;
  document.getElementById('ethicsDenyId').value = id;
  document.getElementById('ethicsDenyReason').value = '';
  document.getElementById('ethicsDenyErr').textContent = '';
  document.getElementById('ethicsDenyModal').classList.add('open');
}
function closeEthicsDenyModal() { document.getElementById('ethicsDenyModal').classList.remove('open'); }
async function saveEthicsDeny() {
  if (!currentUser || parseInt(currentUser.clearance) < 5) return;
  var id     = document.getElementById('ethicsDenyId').value;
  var reason = document.getElementById('ethicsDenyReason').value.trim();
  if (!reason){ document.getElementById('ethicsDenyErr').textContent='> REASON REQUIRED'; return; }
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r) return;
  var prevStage = r.stage;
r.stage='archived'; r.archiveStatus='denied'; r.archiveReason=reason; r.tag='Denied';
r.archivedAt=Date.now();
r.transitions=r.transitions||[];
r.transitions.push({from:prevStage,to:'archived',by:currentUser.id,at:Date.now(),reason});
  try { await ethicsRecruitSet(id, r); closeEthicsDenyModal(); renderEthicsRecruit(); } catch(e){ document.getElementById('ethicsDenyErr').textContent='> ERROR: '+e.message; }
}

// ── Pass interview → create Ethics file ──
async function ethicsRecPass(id) {
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r||!currentUser||parseInt(currentUser.clearance)<5) return;
  if (!await pfConfirm('PASS INTERVIEW FOR '+e(r.name)+' AND CREATE ETHICS ASSISTANT FILE?')) return;
  window._pendingEthicsRecApproval = { recId: id, rec: r };
  openEthicsModal(null);
  setTimeout(function(){
    var nEl = document.getElementById('efName');
    var rEl = document.getElementById('efRole');
    if (nEl) nEl.value = r.name||'';
    if (rEl) rEl.value = 'Assistant';
  }, 60);
}

async function finaliseEthicsRecApproval(newEfId) {
  if (!window._pendingEthicsRecApproval) return;
  var rec = window._pendingEthicsRecApproval.rec;
  rec.stage='archived'; rec.archiveStatus='approved'; rec.tag='Accepted';
  rec.archivedAt=Date.now(); rec.personnelFileId=newEfId;
  rec.transitions=rec.transitions||[];
  rec.transitions.push({from:'interview',to:'archived',by:currentUser.id,at:Date.now(),reason:'approved'});
  try { await ethicsRecruitSet(rec.id, rec); renderEthicsRecruit(); } catch(e){ console.error(e); }
  window._pendingEthicsRecApproval=null;
}

// ── Comments ──
async function addEthicsAppComment(id) {
  if (!currentUser||parseInt(currentUser.clearance)<4) return;
  var inp = document.getElementById('ethicsappnote_'+id);
  if (!inp||!inp.value.trim()) return;
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r) return;
  if (!Array.isArray(r.applicationComments)) r.applicationComments=[];
  r.applicationComments.push({author:currentUser.id,clearance:currentUser.clearance,text:inp.value.trim(),created:Date.now()});
  try { await ethicsRecruitSet(id, r); inp.value=''; renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}
function handleEthicsAppNoteKey(ev, el) {
  if (ev.key==='Enter'&&(ev.ctrlKey||ev.metaKey)){ ev.preventDefault(); addEthicsAppComment(el.id.replace('ethicsappnote_','')); }
}

async function addEthicsIntComment(id) {
  if (!currentUser||parseInt(currentUser.clearance)<5) { alert('CL5 ONLY FOR INTERVIEW COMMENTS'); return; }
  var inp = document.getElementById('ethicsinterviewnote_'+id);
  if (!inp||!inp.value.trim()) return;
  var r = allEthicsRecruit.find(function(x){return x.id===id;});
  if (!r) return;
  if (!Array.isArray(r.interviewComments)) r.interviewComments=[];
  r.interviewComments.push({author:currentUser.id,clearance:currentUser.clearance,text:inp.value.trim(),created:Date.now()});
  try { await ethicsRecruitSet(id, r); inp.value=''; renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}
function handleEthicsIntNoteKey(ev, el) {
  if (ev.key==='Enter'&&(ev.ctrlKey||ev.metaKey)){ ev.preventDefault(); addEthicsIntComment(el.id.replace('ethicsinterviewnote_','')); }
}

async function deleteEthicsAppComment(recId, noteCreated) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS COMMENT?')) return;
  var r = allEthicsRecruit.find(function(x){return x.id===recId;});
  if (!r) return;
  r.applicationComments=(r.applicationComments||[]).filter(function(c){return c.created!==noteCreated;});
  try { await ethicsRecruitSet(recId, r); renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}

async function deleteEthicsIntComment(recId, noteCreated) {
  if (!canDeleteComment()) return;
  if (!await pfConfirm('DELETE THIS COMMENT?')) return;
  var r = allEthicsRecruit.find(function(x){return x.id===recId;});
  if (!r) return;
  r.interviewComments=(r.interviewComments||[]).filter(function(c){return c.created!==noteCreated;});
  try { await ethicsRecruitSet(recId, r); renderEthicsRecruit(); } catch(e){ alert('ERROR: '+e.message); }
}

// ================================================================
//  NAV GROUP COLLAPSE
// ================================================================
var navCollapsed = new Set(); // (legacy, retained to avoid reference errors — nav now uses dropdowns)

function toggleNavDd(group) {
  var dd = document.querySelector('.nav-dd[data-group="' + group + '"]');
  if (!dd) return;
  var wasOpen = dd.classList.contains('open');
  // Close all dropdowns first
  document.querySelectorAll('.nav-dd').forEach(function(d){ d.classList.remove('open'); });
  // Toggle this one (open only if it wasn't already open)
  if (!wasOpen) dd.classList.add('open');
}

// Close any open nav dropdown when clicking outside the nav
document.addEventListener('click', function(ev) {
  var nav = document.querySelector('.nav');
  if (nav && !nav.contains(ev.target)) {
    document.querySelectorAll('.nav-dd.open').forEach(function(d){ d.classList.remove('open'); });
  }
});

// ================================================================
//  POI / TARGET SYSTEM
// ================================================================
var DEPARTMENTS = ['General Security','Medical','Research','Site Staff','Internal Security',
  'External Affairs','MTF Alpha-1','Floor 3 Assistant','Site Inspector',
  'Site Administration','MTF Nu-7','MTF E-11','Other'];

var STATUS_CLS   = { 'In Progress':'b-cyan', 'Absolved':'b-green', 'Summoned to Tribunal':'b-amber', 'Killed':'b-dim' };
var PRIORITY_CLS = { '1':'b-red', '2':'b-amber', '3':'b-cyan' };
var STANDING_CLS = { 'Friend':'b-green', 'Neutral':'b-dim', 'Foe':'b-red' };

var allPOI     = [];
var allTargets = [];
var currentPoiView = null; // null = list, {type:'poi'|'target', id} = file

// ── Firebase helpers ──
async function poiGetAll()     {
  if (firebaseReady) { var r=await fbGetAll('/poi');     return r?Object.values(r).filter(x=>x&&x.id):[];}
  return Object.values(lsAll('poi/')).filter(x=>x&&x.id);
}
async function targetGetAll()  {
  if (firebaseReady) { var r=await fbGetAll('/targets'); return r?Object.values(r).filter(x=>x&&x.id):[];}
  return Object.values(lsAll('targets/')).filter(x=>x&&x.id);
}
async function poiSet(id,data)    { if(firebaseReady)await fbSet('/poi/'+id,data);     else lsSet('poi/'+id,data);     }
async function targetSet(id,data) { if(firebaseReady)await fbSet('/targets/'+id,data); else lsSet('targets/'+id,data); }
async function poiDel(id)         { if(firebaseReady)await fbDelete('/poi/'+id);        else lsDel('poi/'+id);          }
async function targetDel(id)      { if(firebaseReady)await fbDelete('/targets/'+id);    else lsDel('targets/'+id);      }

// ── Load ──
async function loadPOIData() {
  try {
    var ps = await poiGetAll();
    var ts = await targetGetAll();
    allPOI     = ps.sort(function(a,b){return a.number-b.number;});
    allTargets = ts.sort(function(a,b){return a.number-b.number;});
  } catch(err) { allPOI=[]; allTargets=[]; }
  // Show new buttons for CL4+
  var canEdit = currentUser && parseInt(currentUser.clearance) >= 4;
  var npb = document.getElementById('newPoiBtn');
  var ntb = document.getElementById('newTargetBtn');
  if (npb) npb.style.display = canEdit ? 'inline-block' : 'none';
  if (ntb) ntb.style.display = canEdit ? 'inline-block' : 'none';
  if (currentPoiView) renderPoiFile(currentPoiView.type, currentPoiView.id);
  else renderPoiList();
  updatePoiBadge();
}

function deptDisplay(item) {
  return item.department === 'Other' ? (item.deptOther||'Other') : (item.department||'—');
}
function poiTitle(p) {
  return 'POI ' + String(p.number).padStart(3,'0') + ' — ' + e(p.name||'—') + ', ' + e(deptDisplay(p));
}
function targetTitle(t) {
  return 'TARGET ' + String(t.number).padStart(3,'0') + ' — ' + e(t.name||'—') + ', ' + e(deptDisplay(t));
}

// ── Render list ──
// ── Render list (filters closed records; shows archive count) ──
function renderPoiList() {
  currentPoiView = null;
  var lv = document.getElementById('poiListView');
  var fv = document.getElementById('poiFileView');
  if (lv) lv.style.display = 'block';
  if (fv) fv.classList.remove('open');

  var active    = allPOI.filter(function(p){return !p.closed;});
  var activeTgt = allTargets.filter(function(t){return !t.closed;});
  var closed    = allPOI.filter(function(p){return p.closed;}).concat(allTargets.filter(function(t){return t.closed;}));

  // Search + filter (applied to the open POI/Target lists)
  var poiQ = (document.getElementById('poiSearch') && document.getElementById('poiSearch').value || '').trim().toLowerCase();
  var poiFS = (document.getElementById('poiFilterStatus') && document.getElementById('poiFilterStatus').value) || '';
  var poiFStand = (document.getElementById('poiFilterStanding') && document.getElementById('poiFilterStanding').value) || '';
  function poiMatches(r, prefix) {
    if (poiFS && (r.status || '') !== poiFS) return false;
    if (poiFStand && (r.standing || '') !== poiFStand) return false;
    if (!poiQ) return true;
    var num = prefix + ' ' + String(r.number || '').padStart(3, '0');
    return (r.name || '').toLowerCase().includes(poiQ) ||
           num.toLowerCase().includes(poiQ) ||
           String(r.number || '').includes(poiQ) ||
           (deptDisplay(r) || '').toLowerCase().includes(poiQ);
  }
  active    = active.filter(function(p){ return poiMatches(p, 'POI'); });
  activeTgt = activeTgt.filter(function(t){ return poiMatches(t, 'TGT'); });
  // Result counts (open records; filtered vs total when a filter is active)
  var poiAnyFilter = !!(poiQ || poiFS || poiFStand);
  var poiCountEl = document.getElementById('poiCount');
  var tgtCountEl = document.getElementById('targetCount');
  var totalPoi = allPOI.filter(function(p){ return !p.closed; }).length;
  var totalTgt = allTargets.filter(function(t){ return !t.closed; }).length;
  if (poiCountEl) poiCountEl.textContent = poiAnyFilter ? '(' + active.length + ' of ' + totalPoi + ')' : '(' + totalPoi + ')';
  if (tgtCountEl) tgtCountEl.textContent = poiAnyFilter ? '(' + activeTgt.length + ' of ' + totalTgt + ')' : '(' + totalTgt + ')';

  var _poiSortFields = {
    number:function(r){return r.number||0;},
    name:function(r){return (r.name||'').toLowerCase();},
    status:function(r){return r.status||'';},
    priority:function(r){return r.priority||0;},
    standing:function(r){return r.standing||'';}
  };
  active = applySort(active, g('poiSort'), _poiSortFields);
  activeTgt = applySort(activeTgt, g('poiSort'), _poiSortFields);
  var poiEl = document.getElementById('poiList');
  if (poiEl) poiEl.innerHTML = active.length ? active.map(function(p) {
    return `<div class="poi-list-item" data-action="open-poi-file" data-type="poi" data-id="${e(p.id)}">
      <span class="poi-item-num">POI ${String(p.number).padStart(3,'0')}</span>
      <span class="poi-item-name">${e(p.name||'—')}</span>
      <span class="poi-item-dept">${e(deptDisplay(p))}</span>
      <span class="poi-item-badges">
        <span class="badge ${STATUS_CLS[p.status]||'b-dim'}">${e(p.status)}</span>
        <span class="badge ${PRIORITY_CLS[p.priority]||'b-dim'}">P${e(p.priority)}</span>
        <span class="badge ${STANDING_CLS[p.standing]||'b-dim'}">${e(p.standing)}</span>
      </span>
    </div>`;
  }).join('') : '<div class="poi-empty">[ NO PERSONS OF INTEREST ON RECORD ]</div>';
  applyPagination(poiEl, 'poi', g('poiSearch')+'|'+g('poiFilterStatus')+'|'+g('poiFilterStanding')+'|'+g('poiSort'));

  var tgtEl = document.getElementById('targetList');
  if (tgtEl) tgtEl.innerHTML = activeTgt.length ? activeTgt.map(function(t) {
    return `<div class="poi-list-item" data-action="open-poi-file" data-type="target" data-id="${e(t.id)}">
      <span class="poi-item-num">TGT ${String(t.number).padStart(3,'0')}</span>
      <span class="poi-item-name">${e(t.name||'—')}</span>
      <span class="poi-item-dept">${e(deptDisplay(t))}</span>
      <span class="poi-item-badges">
        <span class="badge b-red" style="letter-spacing:.05em;">TARGET</span>
        ${t.priority ? `<span class="badge ${PRIORITY_CLS[t.priority]||'b-dim'}">P${e(t.priority)}</span>` : ''}
      </span>
    </div>`;
  }).join('') : '<div class="poi-empty">[ NO TARGETS ON RECORD — ADD ONE TO BEGIN TRACKING ]</div>';

  var cntEl = document.getElementById('poiArchiveCount');
  if (cntEl) cntEl.textContent = closed.length;
  // Refresh archive panel if open
  if (poiArchiveOpen) renderPoiArchiveList();
  updatePoiBadge();
}

var poiArchiveOpen = false;
function togglePoiArchive() {
  poiArchiveOpen = !poiArchiveOpen;
  var listEl  = document.getElementById('poiArchivedList');
  var arrowEl = document.getElementById('poiArchiveArrow');
  if (arrowEl) arrowEl.textContent = poiArchiveOpen ? '▾' : '▸';
  if (!listEl) return;
  if (!poiArchiveOpen) { listEl.style.display = 'none'; return; }
  listEl.style.display = 'block';
  renderPoiArchiveList();
}
function renderPoiArchiveList() {
  var listEl = document.getElementById('poiArchivedList');
  if (!listEl) return;
  var closed = allPOI.filter(function(p){return p.closed;}).concat(allTargets.filter(function(t){return t.closed;}));
  closed.sort(function(a,b){return (b.closedAt||0)-(a.closedAt||0);});
  listEl.innerHTML = closed.length ? closed.map(function(r) {
    var isPoi = !!r.status;
    var num   = isPoi ? 'POI '+String(r.number).padStart(3,'0') : 'TGT '+String(r.number).padStart(3,'0');
    return `<div class="poi-list-item" style="opacity:.7;" data-action="open-poi-file" data-type="${isPoi?'poi':'target'}" data-id="${e(r.id)}">
      <span class="poi-item-num">${num}</span>
      <span class="poi-item-name">${e(r.name||'—')}</span>
      <span class="poi-item-dept">${e(deptDisplay(r))}</span>
      <span class="poi-closed-badge">CLOSED</span>
      <span class="poi-item-badges" style="font-size:.56rem;color:var(--text-faint);">${e(r.closedReason||'')}</span>
    </div>`;
  }).join('') : '<div class="poi-empty">[ NO ARCHIVED FILES ]</div>';
}

// ── Close file modal ──
function openPoiCloseModal(id, type) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) return;
  document.getElementById('poiCloseId').value        = id;
  document.getElementById('poiCloseType').value      = type;
  document.getElementById('poiCloseReason').value    = '';
  document.getElementById('poiCloseErr').textContent = '';
  document.getElementById('poiCloseTitle').textContent = type==='poi' ? 'CLOSE POI FILE' : 'CLOSE TARGET FILE';
  document.getElementById('poiCloseModal').classList.add('open');
}
function closePoiCloseModal() { document.getElementById('poiCloseModal').classList.remove('open'); }
async function savePoiClose() {
  if (!currentUser || parseInt(currentUser.clearance) < 4) return;
  var id     = document.getElementById('poiCloseId').value;
  var type   = document.getElementById('poiCloseType').value;
  var reason = document.getElementById('poiCloseReason').value.trim();
  if (!reason) { document.getElementById('poiCloseErr').textContent = '> REASON REQUIRED'; return; }
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){return x.id===id;});
  if (!rec) return;
  rec.closed = true; rec.closedReason = reason; rec.closedBy = currentUser.id; rec.closedAt = Date.now();
  try {
    if (type==='poi') await poiSet(id, rec); else await targetSet(id, rec);
    closePoiCloseModal();
    renderPoiList();
  } catch(err) { document.getElementById('poiCloseErr').textContent = '> ERROR: '+err.message; }
}
async function reopenPoi(id, type) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) { alert('CLEARANCE LEVEL 4 REQUIRED'); return; }
  if (!await pfConfirm('REOPEN THIS FILE?')) return;
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){return x.id===id;});
  if (!rec) return;
  rec.closed = false; rec.closedReason = null; rec.closedBy = null; rec.closedAt = null;
  try {
    if (type==='poi') await poiSet(id, rec); else await targetSet(id, rec);
    renderPoiList();
  } catch(err) { alert('ERROR: '+err.message); }
}


// ── Render file view ──
function renderPoiFile(type, id) {
  var record = type === 'poi'
    ? allPOI.find(function(p){return p.id===id;})
    : allTargets.find(function(t){return t.id===id;});
  if (!record) { renderPoiList(); return; }
  currentPoiView = { type: type, id: id };

  var lv = document.getElementById('poiListView');
  var fv = document.getElementById('poiFileView');
  if (lv) lv.style.display = 'none';
  if (fv) fv.classList.add('open');

  var titleEl = document.getElementById('poiFileTitle');
  if (titleEl) titleEl.innerHTML = type==='poi' ? poiTitle(record) : targetTitle(record);

  var canEdit = currentUser && parseInt(currentUser.clearance) >= 4;
  var notes   = (Array.isArray(record.notes) ? record.notes : []).filter(function(n){return n && typeof n==='object';});

  var fields = [
    ['Name',       e(record.name||'—')],
    ['Department', e(deptDisplay(record))],
    ['Position',   e(record.position||'—')],
    ['Reason',     e(record.reason||'—')],
  ];
  if (type === 'poi') {
    fields.push(['Status',   `<span class="badge ${STATUS_CLS[record.status]||'b-dim'}">${e(record.status||'—')}</span>`]);
    fields.push(['Priority', `<span class="badge ${PRIORITY_CLS[record.priority]||'b-dim'}">PRIORITY ${e(record.priority||'—')}</span>`]);
    fields.push(['Standing', `<span class="badge ${STANDING_CLS[record.standing]||'b-dim'}">${e(record.standing||'—')}</span>`]);
  } else {
    fields.push(['Priority',     `<span class="badge ${PRIORITY_CLS[record.priority]||'b-dim'}">PRIORITY ${e(record.priority||'—')}</span>`]);
    fields.push(['Ethics Authorisation', e(record.authorisedByName||'—')]);
  }
  fields.push(['Created',    safeDate(record.created) + ' · EC·' + e(record.createdBy||'—')]);

  var fieldsHtml = fields.map(function(f) {
    return `<div class="poi-field"><span class="poi-field-label">${f[0]}</span><span class="poi-field-value">${f[1]}</span></div>`;
  }).join('');

  var notesHtml = notes.length ? notes.map(function(n){
    var nts = safeDateTime(n.created);
    return `<div class="pf-note"><div class="pf-note-gutter"></div><div class="pf-note-body"><div class="pf-note-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·${e(n.author)} [L${e(n.clearance)}] · ${nts} UTC</span>${canDeleteComment()?`<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-poi-note" data-recid="${e(id)}" data-poitype="${type}" data-created="${n.created}" title="Delete note">×</button>`:''}</div><div class="pf-note-text">${e(n.text)}</div></div></div>`;
  }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO NOTES ]</div>';

  var noteForm = currentUser
    ? `<div class="poi-note-form"><textarea class="poi-note-input" id="poinote_${e(id)}" placeholder="Add note... (Ctrl+Enter)" rows="2" onkeydown="handlePoiNoteKey(event,this,'${type}')"></textarea><button class="pf-btn" data-action="add-poi-note" data-id="${e(id)}" data-poitype="${type}">[ ADD ]</button></div>`
    : '';

  var actionBtns = canEdit
    ? `<div class="pf-card-actions" style="margin-top:.75rem;">
        <button class="pf-btn" data-action="edit-poi" data-id="${e(id)}" data-poitype="${type}">[ EDIT ]</button>
        ${record.closed
          ? `<button class="pf-btn" data-action="reopen-poi" data-id="${e(id)}" data-poitype="${type}">[ REOPEN ]</button>`
          : `<button class="pf-btn" data-action="close-poi-file" data-id="${e(id)}" data-poitype="${type}" style="border-color:#5a2020;color:#dd6666;">[ CLOSE FILE ]</button>`}
        <button class="pf-btn danger" data-action="delete-poi" data-id="${e(id)}" data-poitype="${type}">[ DELETE ]</button>
      </div>`
    : '';

  var bodyEl = document.getElementById('poiFileBody');
  var closedBanner = record.closed
    ? `<div style="background:#0a0a14;border:1px solid #2a2a4a;padding:.4rem .8rem;font-size:.62rem;color:#8888cc;margin-bottom:.6rem;">⚑ FILE CLOSED · ${e(record.closedReason||'')} · by EC·${e(record.closedBy||'—')} · ${record.closedAt?safeDate(record.closedAt):''}</div>`
    : '';
  if (bodyEl) bodyEl.innerHTML = closedBanner +
    `<div class="pf-card-body open" style="background:var(--bg3);border:1px solid var(--border2);padding:.9rem;">` +
      buildPoiPhotoPanel(type, id, record, canEdit) +
      fieldsHtml +
      `<div style="font-size:.6rem;letter-spacing:.15em;color:var(--green-dim);margin:.6rem 0 .4rem;border-top:1px solid var(--border2);padding-top:.6rem;">▸ NOTES</div>` +
      notesHtml + noteForm + actionBtns +
    `</div>`;
}

// ── Modal open/close ──
function handlePoiDeptChange() {
  var val = document.getElementById('poiDept').value;
  document.getElementById('poiDeptOtherGroup').style.display = val === 'Other' ? 'block' : 'none';
}

function openPoiModal(id, type) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) { alert('CLEARANCE LEVEL 4 REQUIRED'); return; }
  type = type || 'poi';
  document.getElementById('poiModalType').value   = type;
  document.getElementById('poiModalEditId').value = id || '';
  document.getElementById('poiErr').textContent   = '';
  document.getElementById('poiModalTitle').textContent = id
    ? (type==='poi' ? 'EDIT PERSON OF INTEREST' : 'EDIT TARGET')
    : (type==='poi' ? 'NEW PERSON OF INTEREST'  : 'NEW TARGET');

  // Show/hide POI vs Target specific fields
  document.getElementById('poiOnlyFields').style.display    = type==='poi' ? 'block' : 'none';
  document.getElementById('targetOnlyFields').style.display = type==='target' ? 'block' : 'none';

  // Populate ethics authority select for targets
  if (type === 'target') {
    var sel = document.getElementById('poiAuthority');
    sel.innerHTML = '<option value="">— SELECT ETHICS MEMBER —</option>';
    allEthicsPersonnel.filter(function(p){ return !p.status||p.status==='Active'; }).forEach(function(p) {
      var opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = e(p.name) + ' · ' + e(p.role||'');
      sel.appendChild(opt);
    });
  }

  // Pre-fill if editing
  if (id) {
    var rec = type==='poi' ? allPOI.find(function(x){return x.id===id;}) : allTargets.find(function(x){return x.id===id;});
    if (rec) {
      document.getElementById('poiName').value     = rec.name     || '';
      document.getElementById('poiDept').value     = rec.department || '';
      document.getElementById('poiDeptOther').value= rec.deptOther|| '';
      document.getElementById('poiPosition').value = rec.position  || '';
      document.getElementById('poiReason').value   = rec.reason    || '';
      handlePoiDeptChange();
      if (type==='poi') {
        document.getElementById('poiStatus').value   = rec.status   || 'In Progress';
        document.getElementById('poiPriority').value = rec.priority || '2';
        document.getElementById('poiStanding').value = rec.standing || 'Neutral';
      } else {
        document.getElementById('targetPriority').value = rec.priority || '2';
        document.getElementById('poiAuthority').value   = rec.authorisedById || '';
      }
    }
  } else {
    document.getElementById('poiName').value     = '';
    document.getElementById('poiDept').value     = '';
    document.getElementById('poiDeptOther').value= '';
    document.getElementById('poiPosition').value = '';
    document.getElementById('poiReason').value   = '';
    handlePoiDeptChange();
    if (type==='poi') {
      document.getElementById('poiStatus').value   = 'In Progress';
      document.getElementById('poiPriority').value = '2';
      document.getElementById('poiStanding').value = 'Neutral';
    } else {
      document.getElementById('poiAuthority').value = '';
    }
  }
  document.getElementById('poiModal').classList.add('open');
}

function closePoiModal() { document.getElementById('poiModal').classList.remove('open'); }

async function savePoi() {
  if (!canEditPersonnel()) return;
  var type     = document.getElementById('poiModalType').value;
  var editId   = document.getElementById('poiModalEditId').value;
  var name     = document.getElementById('poiName').value.trim();
  var dept     = document.getElementById('poiDept').value;
  var deptOther= document.getElementById('poiDeptOther').value.trim();
  var position = document.getElementById('poiPosition').value.trim();
  var reason   = document.getElementById('poiReason').value.trim();

  if (!name) { document.getElementById('poiErr').textContent = '> NAME REQUIRED'; return; }
  if (!dept) { document.getElementById('poiErr').textContent = '> DEPARTMENT REQUIRED'; return; }
  if (dept === 'Other' && !deptOther) { document.getElementById('poiErr').textContent = '> SPECIFY DEPARTMENT'; return; }

  var now = Date.now();
  if (editId) {
    var list = type==='poi' ? allPOI : allTargets;
    var rec  = list.find(function(x){return x.id===editId;});
    if (!rec) return;
    rec.name = name; rec.department = dept; rec.deptOther = deptOther;
    rec.position = position; rec.reason = reason;
    rec.updatedBy = currentUser.id; rec.updated = now;
    if (type==='poi') {
      rec.status   = document.getElementById('poiStatus').value;
      rec.priority = document.getElementById('poiPriority').value;
      rec.standing = document.getElementById('poiStanding').value;
    } else {
      var authSel = document.getElementById('poiAuthority');
      rec.authorisedById   = authSel.value;
      rec.authorisedByName = authSel.options[authSel.selectedIndex] ? authSel.options[authSel.selectedIndex].text : '';
      rec.priority = document.getElementById('targetPriority').value;
    }
    try {
      if (type==='poi') await poiSet(editId, rec); else await targetSet(editId, rec);
    } catch(err) { document.getElementById('poiErr').textContent = '> SAVE ERROR: '+err.message; return; }
  } else {
    var list2 = type==='poi' ? allPOI : allTargets;
    var nextNum = list2.reduce(function(mx, x){ return Math.max(mx, x.number || 0); }, 0) + 1;
    var newRec = {
      id: (type==='poi'?'poi_':'tgt_') + now + '_' + Math.random().toString(36).slice(2,4),
      number: nextNum, name: name, department: dept, deptOther: deptOther,
      position: position, reason: reason, notes: [],
      createdBy: currentUser.id, created: now
    };
    if (type==='poi') {
      newRec.status   = document.getElementById('poiStatus').value;
      newRec.priority = document.getElementById('poiPriority').value;
      newRec.standing = document.getElementById('poiStanding').value;
    } else {
      var authSel2 = document.getElementById('poiAuthority');
      newRec.authorisedById   = authSel2.value;
      newRec.authorisedByName = authSel2.options[authSel2.selectedIndex] ? authSel2.options[authSel2.selectedIndex].text : '';
      newRec.priority = document.getElementById('targetPriority').value;
    }
    try {
      if (type==='poi') { await poiSet(newRec.id, newRec); allPOI.push(newRec); }
      else              { await targetSet(newRec.id, newRec); allTargets.push(newRec); }
    } catch(err) { document.getElementById('poiErr').textContent = '> SAVE ERROR: '+err.message; return; }
  }
  closePoiModal();
  if (currentPoiView) renderPoiFile(currentPoiView.type, currentPoiView.id);
  else renderPoiList();
}

async function deletePoi(id, type) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) return;
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){return x.id===id;});
  if (!rec) return;
  var label = type==='poi' ? 'POI '+String(rec.number).padStart(3,'0') : 'TARGET '+String(rec.number).padStart(3,'0');
  if (!await pfConfirm('CONFIRM: DELETE ' + label + ' — ' + rec.name + '?')) return;
  try {
    if (type==='poi') { await poiDel(id); allPOI = allPOI.filter(function(x){return x.id!==id;}); }
    else              { await targetDel(id); allTargets = allTargets.filter(function(x){return x.id!==id;}); }
  } catch(err) { alert('ERROR: '+err.message); return; }
  renderPoiList();
}

async function addPoiNote(id, type) {
  if (!currentUser || parseInt(currentUser.clearance) < 4) return;
  var inp = document.getElementById('poinote_' + id);
  if (!inp || !inp.value.trim()) return;
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){return x.id===id;});
  if (!rec) return;
  if (!Array.isArray(rec.notes)) rec.notes = [];
  rec.notes.push({ author: currentUser.id, clearance: currentUser.clearance, text: inp.value.trim(), created: Date.now() });
  try {
    if (type==='poi') await poiSet(id, rec); else await targetSet(id, rec);
    inp.value = '';
    renderPoiFile(type, id);
  } catch(err) { alert('ERROR: '+err.message); }
}

// ── POI / Target photograph (downscaled client-side, stored as a data URL) ──
// Build the photo panel shown at the top of a POI/Target file.
function buildPoiPhotoPanel(type, id, record, canEdit) {
  var has = !!record.photo;
  var inner;
  if (has) {
    inner = '<img src="' + record.photo + '" alt="subject photograph" style="width:130px;height:160px;object-fit:cover;border:1px solid var(--border2);background:#111;border-radius:2px;display:block;"/>'
      + '<div style="font-size:.5rem;color:var(--text-faint);margin-top:.25rem;letter-spacing:.05em;text-align:center;">PHOTOGRAPH ON FILE</div>'
      + (record.photoBy ? '<div style="font-size:.48rem;color:var(--text-faint);text-align:center;">EC·' + e(record.photoBy) + (record.photoAt ? ' · ' + safeDate(record.photoAt) : '') + '</div>' : '');
  } else {
    inner = '<div style="width:130px;height:160px;border:1px dashed var(--border2);background:var(--bg2);display:flex;align-items:center;justify-content:center;text-align:center;font-size:.5rem;color:var(--text-faint);letter-spacing:.08em;border-radius:2px;">NO PHOTOGRAPH<br>ON FILE</div>';
  }
  var controls = '';
  if (canEdit) {
    controls = '<div style="display:flex;flex-direction:column;gap:.3rem;margin-top:.4rem;">'
      + '<button class="pf-btn" data-action="poi-photo-upload" data-poitype="' + e(type) + '" data-id="' + e(id) + '" style="font-size:.54rem;">[ ' + (has?'REPLACE':'UPLOAD') + ' PHOTO ]</button>'
      + (has ? '<button class="pf-btn" data-action="poi-photo-remove" data-poitype="' + e(type) + '" data-id="' + e(id) + '" style="font-size:.54rem;">[ REMOVE ]</button>' : '')
      + '</div>';
  }
  return '<div style="float:right;margin:0 0 .6rem .8rem;width:130px;">' + inner + controls + '</div>';
}
// Triggered by the hidden file input on the file view.
function triggerPoiPhoto(type, id) {
  var inp = document.getElementById('poiPhotoInput');
  if (!inp) return;
  inp.value = '';
  inp.dataset.type = type; inp.dataset.id = id;
  inp.click();
}
// Downscale an image File to a JPEG data URL no larger than maxDim on its long edge.
function downscaleImage(file, maxDim, quality) {
  return new Promise(function(resolve, reject){
    if (!file || !/^image\//.test(file.type)) { reject(new Error('Not an image file.')); return; }
    var reader = new FileReader();
    reader.onerror = function(){ reject(new Error('Could not read file.')); };
    reader.onload = function(){
      var img = new Image();
      img.onerror = function(){ reject(new Error('Could not decode image.')); };
      img.onload = function(){
        var w = img.width, h = img.height;
        var scale = Math.min(1, maxDim / Math.max(w, h));
        var cw = Math.round(w * scale), ch = Math.round(h * scale);
        var canvas = document.createElement('canvas');
        canvas.width = cw; canvas.height = ch;
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#1a1a1a'; ctx.fillRect(0,0,cw,ch);
        ctx.drawImage(img, 0, 0, cw, ch);
        try { resolve(canvas.toDataURL('image/jpeg', quality || 0.72)); }
        catch(err) { reject(err); }
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}
async function handlePoiPhotoSelected(inputEl) {
  if (!canEditPersonnel()) return;
  var type = inputEl.dataset.type, id = inputEl.dataset.id;
  var file = inputEl.files && inputEl.files[0];
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) { alert('Image too large (max 8MB before processing).'); return; }
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){ return x.id===id; });
  if (!rec) return;
  try {
    var dataUrl = await downscaleImage(file, 360, 0.72);
    // Guard against an oversized result (very large images / DB limits)
    if (dataUrl.length > 700000) dataUrl = await downscaleImage(file, 260, 0.6);
    rec.photo = dataUrl;
    rec.photoBy = currentUser.id; rec.photoAt = Date.now();
    if (type==='poi') await poiSet(id, rec); else await targetSet(id, rec);
    auditRecord('ADDED PHOTO', (type==='poi'?'POI ':'TARGET ')+'EC·'+(rec.name||id));
    renderPoiFile(type, id);
  } catch(err) { alert('Could not process image: ' + err.message); }
}
async function removePoiPhoto(type, id) {
  if (!canEditPersonnel()) return;
  if (!await pfConfirm('Remove the photograph from this file?')) return;
  var list = type==='poi' ? allPOI : allTargets;
  var rec  = list.find(function(x){ return x.id===id; });
  if (!rec) return;
  rec.photo = null; rec.photoBy = null; rec.photoAt = null;
  try {
    if (type==='poi') await poiSet(id, rec); else await targetSet(id, rec);
    auditRecord('REMOVED PHOTO', (type==='poi'?'POI ':'TARGET ')+'EC·'+(rec.name||id));
    renderPoiFile(type, id);
  } catch(err) { alert('ERROR: '+err.message); }
}

function handlePoiNoteKey(ev, el, type) {
  if (ev.key==='Enter' && (ev.ctrlKey||ev.metaKey)) {
    ev.preventDefault();
    var id = el.id.replace('poinote_','');
    addPoiNote(id, type);
  }
}

// loadSquadrons is called from onLogin and from loadPersonnel directly

async function setPersonnelStatus(id, status) {
  if (!canEditPersonnel()) return;
  var labels = { Retired: 'RETIRE', Discharged: 'DISCHARGE', Active: 'REACTIVATE' };
  var rec = allPersonnel.find(function(p){ return p.id === id; });
  if (!rec) return;
  if (!canManageFile(rec, 'pf')) { alert('You do not have authority to manage this file.'); return; }
  if (!await pfConfirm('CONFIRM: ' + labels[status] + ' ' + rec.name + '?\n\nRecord will be retained for archival purposes.')) return;
  rec.status    = status;
  rec.updatedBy = currentUser ? currentUser.id : '';
  rec.updated   = Date.now();
  try { await personnelSet(id, rec); } catch(e) { alert('UPDATE ERROR: ' + e.message); return; }
  renderPersonnelFiles();
  renderRoster();
}

async function deletePersonnelRecord(id) {
  if (!canEditPersonnel()) return;
  var rec = allPersonnel.find(function(p){ return p.id === id; });
  if (rec && !canManageFile(rec, 'pf')) { alert('You do not have authority to manage this file.'); return; }
  if (!await pfConfirm('Move the file for ' + (rec ? rec.name : id) + ' to the recycle bin?\n\nIt can be restored by CL5 command from the admin panel.')) return;
  if (rec) {
    rec.deleted = true; rec.deletedBy = currentUser.id; rec.deletedAt = Date.now();
    try { await personnelSet(id, rec); } catch(e) { alert('ERROR: '+e.message); return; }
    auditRecord('DELETED OMEGA-1 FILE', (rec.name||id) + ' → recycle bin');
    allPersonnel = allPersonnel.filter(function(p){ return p.id !== id; });
    if (!deletedPersonnel.some(function(p){ return p.id===id; })) deletedPersonnel.push(rec);
  }
  pfExpanded.delete(id);
  renderPersonnelFiles();
  renderRoster();
}

// ── Notes ──
async function addPersonnelNote(id) {
  if (!canEditPersonnel()) return;
  var noteRec = allPersonnel.find(function(p){ return p.id === id; });
  if (noteRec && !canManageFile(noteRec, 'pf')) { alert('You do not have authority to manage this file.'); return; }
  var inp  = document.getElementById('pfnote_' + id);
  if (!inp) return;
  var text = inp.value.trim();
  if (!text) return;

  inp.disabled = true;
  var note = {
    id:        'note_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    text:      text,
    author:    currentUser.id,
    clearance: currentUser.clearance,
    created:   Date.now()
  };

  var rec = allPersonnel.find(function(p){ return p.id === id; });
  if (rec) {
    if (!Array.isArray(rec.notes)) rec.notes = [];
    rec.notes.push(note);
    try { await personnelSet(id, rec); } catch(err) { alert('ERROR: ' + err.message); rec.notes.pop(); }
  }

  inp.disabled = false;
  inp.value = '';
  renderPersonnelFiles();
}

function handlePfNoteKey(ev, id) {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    addPersonnelNote(id);
  }
}

// Close modal on overlay click
var _pfModal = document.getElementById('pfModal');
if (_pfModal) _pfModal.addEventListener('click', function(ev) {
  if (ev.target === this) closePersonnelModal();
});

// ================================================================
//  ETHICS COMMITTEE PERSONNEL
//  Ranks (highest → lowest): Chairman, Member, Assistant
//  Firebase path: /ethics-personnel/{id}
// ================================================================

var ETHICS_RANKS = ['Chairman', 'Member', 'Assistant'];

function ethicsRankIndex(role) {
  var i = ETHICS_RANKS.indexOf(role);
  return i === -1 ? 99 : i;
}

// Firebase / localStorage helpers for ethics personnel
async function ethicsPersonnelGetAll() {
  if (firebaseReady) {
    var all = await fbGetAll('/ethics-personnel');
    return all ? Object.values(all).filter(function(p){ return p && p.id; }) : [];
  }
  return Object.values(lsAll('ethics-personnel/')).filter(function(p){ return p && p.id; });
}
async function ethicsPersonnelSet(id, data) {
  var k = 'ethics-personnel/' + id;
  if (firebaseReady) await fbSet('/' + k, data);
  else lsSet(k, data);
}
async function ethicsPersonnelDel(id) {
  var k = 'ethics-personnel/' + id;
  if (firebaseReady) await fbDelete('/' + k);
  else lsDel(k);
}

// State
var allEthicsPersonnel = [];
var efExpanded = new Set();
var efCollapsed = new Set(); // "efId:sectionKey"

async function loadEthicsPersonnel() {
  try {
    allEthicsPersonnel = await ethicsPersonnelGetAll();
    allEthicsPersonnel = partitionDeleted(allEthicsPersonnel, function(d){ deletedEthics = d; });
    allEthicsPersonnel.sort(function(a,b){ return ethicsRankIndex(a.role) - ethicsRankIndex(b.role); });
  } catch(err) { allEthicsPersonnel = []; }
  await loadEthicsSquadrons();

  // Show/hide new-record button based on clearance
  var btn = document.getElementById('efNewBtn');
  if (btn) btn.style.display = canEditPersonnel() ? 'inline-block' : 'none';

  renderEthicsFiles();
  renderEthicsRoster();
  refreshClearance(); // silently correct clearance now that allEthicsPersonnel is populated
}

function renderEthicsFiles() {
  var search = (document.getElementById('efSearch') || {}).value || '';
  var q = search.trim().toLowerCase();
  var efStatus = (document.getElementById('efFilterStatus') && document.getElementById('efFilterStatus').value) || '';
  var filtered = allEthicsPersonnel.filter(function(p){
    if (efStatus && (p.status || 'Active') !== efStatus) return false;
    if (!q) return true;
    return (p.name||'').toLowerCase().includes(q) ||
           (p.nickname||'').toLowerCase().includes(q) ||
           (p.role||'').toLowerCase().includes(q);
  });
  var efCountEl = document.getElementById('efCount');
  if (efCountEl) {
    efCountEl.textContent = (q || efStatus)
      ? '(' + filtered.length + ' of ' + allEthicsPersonnel.length + ')'
      : '(' + allEthicsPersonnel.length + ')';
  }

  // Access control: hide files of roles above the current user's level.
  // Users always see their own linked EC file.
  // Ethics files use graduated in-card access control (see getEfFileAccess / buildEthicsCard),
  // so all files render — sensitive sections appear "Restricted" rather than hidden.
  window._efRedactedIds = new Set();

  // Split by role into three groups
  var groups = { Chairman: [], Member: [], Assistant: [] };
  filtered.forEach(function(p) {
    var r = p.role || 'Assistant';
    if (groups[r]) groups[r].push(p); else groups.Assistant.push(p);
  });

  ['Chairman','Member','Assistant'].forEach(function(role) {
    var elId = 'ef' + role + 'List';
    var el = document.getElementById(elId);
    if (!el) return;
    var members = groups[role];
    if (!members.length) {
      el.innerHTML = '<div class="ef-empty">[ NO ' + role.toUpperCase() + 'S ON RECORD ]</div>';
      return;
    }
    el.innerHTML = members.map(function(p) { return buildEthicsCard(p); }).join('');
  });
}

// ── Ethics liaison tag definitions ──
var ETHICS_LIAISON_TAGS = ['ISD Liaison', 'Ethics Assistant Liaison', 'Omega-1 Liaison'];
var ETHICS_TAG_CLS_MAP  = { 'ISD Liaison':'b-amber', 'Ethics Assistant Liaison':'b-cyan', 'Omega-1 Liaison':'b-green' };

async function toggleEthicsTag(efId, tag) {
  if (!canEditPersonnel()) return;
  var rec = allEthicsPersonnel.find(function(p){ return p.id === efId; });
  if (!rec) return;
  if (!canManageFile(rec, 'ef')) { alert('You do not have authority to manage this file.'); return; }
  var tags = Array.isArray(rec.tags) ? rec.tags.slice() : [];
  var idx  = tags.indexOf(tag);
  if (idx > -1) tags.splice(idx, 1); else tags.push(tag);
  rec.tags = tags;
  try { await ethicsPersonnelSet(efId, rec); renderEthicsFiles(); }
  catch(err) { alert('ERROR: ' + err.message); }
}

function buildEthicsCard(p) {
  // Graduated access: 'full' | 'partial' (no strikes/notes) | 'name-only' (most fields Restricted)
  var efAccess = getEfFileAccess(p);
  var restrictAll  = (efAccess === 'name-only'); // DoB, strikes, squadrons, ranks, notes restricted
  var restrictSens = (efAccess !== 'full');      // strikes & notes restricted for partial too
  var RESTRICTED = '<span style="color:var(--text-faint);font-style:italic;letter-spacing:.05em;">[ RESTRICTED ]</span>';

  var isOpen  = efExpanded.has(p.id);
  var canEdit = canManageFile(p, 'ef') && efAccess === 'full'; // can't edit what you can't fully see, and only with management rights
  var pStatus = p.status || 'Active';
  var notes   = Array.isArray(p.notes)      ? p.notes.filter(function(n){return n && typeof n==='object';}).sort((a,b)=>a.created-b.created) : [];
  var history = objArr(p.rankHistory).sort((a,b)=>(b.changedAt||0)-(a.changedAt||0));

  var roleBadge   = `<span class="badge ${p.role==='Chairman'?'b-red':p.role==='Member'?'b-amber':'b-cyan'}">${e(p.role||'—')}</span>`;
  var statusBadge = pStatus !== 'Active' ? `<span class="badge ${pStatus==='Retired'?'b-retired':'b-discharged'}">${e(pStatus)}</span>` : '';

  var efFileSecBadges = fileIntegrityBadge(p.id, 'ef') + fileCompartmentBadges(p.id, 'ef');
  var efLinkedBadge = userForFile(p.id, 'ef')
    ? '<span class="badge b-green" style="font-size:.5rem; margin-left:4px;">● LINKED</span>'
    : '';
  if (!isOpen) {
    return `<div class="pf-card" id="efcard_${e(p.id)}">
      <div class="pf-card-header" data-action="toggle-ef" data-id="${e(p.id)}" style="cursor:pointer;padding:.6rem .9rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.4rem;" onmouseover="this.style.background='var(--accent-softer)'" onmouseout="this.style.background=''">
        <div>
          <div class="pf-name">${e(p.name||'UNNAMED')}${p.nickname?` <span style="color:var(--text-dim);font-size:.6rem;">"${e(p.nickname)}"</span>`:''}</div>
          <div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap;margin-top:2px;">${roleBadge}${statusBadge}${efFileSecBadges}${efLinkedBadge}</div>
        </div>
        <span style="font-size:.62rem;color:var(--text-dim);">▸</span>
      </div>
    </div>`;
  }

  // Role history
  var histHtml = history.length ? history.map(h => {
    var hts = safeDateTime(h.changedAt);
    var fromBadge = `<span class="badge ${h.from==='Chairman'?'b-red':h.from==='Member'?'b-amber':'b-cyan'}">${e(h.from||'—')}</span>`;
    var toBadge   = `<span class="badge ${h.to==='Chairman'?'b-red':h.to==='Member'?'b-amber':'b-cyan'}">${e(h.to||'—')}</span>`;
    return `<div class="rank-history-entry"><div class="rank-history-gutter"></div><div class="rank-history-body"><div class="rank-history-meta">EC·${e(h.changedBy||'—')} [L${e(h.clearance||'—')}] · ${hts} UTC</div><div class="rank-history-change">${fromBadge}<span class="rank-arrow">→</span>${toBadge}</div></div></div>`;
  }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO ROLE CHANGES ]</div>';

  // Notes
  var notesHtml = notes.length ? notes.map(n => {
    var nts = safeDateTime(n.created);
    return `<div class="pf-note"><div class="pf-note-gutter"></div><div class="pf-note-body"><div class="pf-note-meta" style="display:flex;justify-content:space-between;align-items:center;"><span>EC·${e(n.author)} [L${e(n.clearance)}] · ${nts} UTC</span>${canDeleteComment()?`<button style="background:none;border:none;color:var(--text-faint);cursor:pointer;font-size:.7rem;" data-action="del-ef-note" data-efid="${e(p.id)}" data-created="${n.created}" title="Delete note">×</button>`:''}</div><div class="pf-note-text">${e(n.text)}</div></div></div>`;
  }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO NOTES ]</div>';

  // ── Graduated access gating ──
  // name-only: DoB (handled inline), role history & squadrons restricted
  // partial & name-only: strikes & notes restricted
  var RESTR_BLOCK = '<div style="font-size:.6rem;color:var(--text-faint);font-style:italic;padding:5px 2px;letter-spacing:.05em;">[ RESTRICTED — INSUFFICIENT CLEARANCE ]</div>';
  if (restrictAll) {
    histHtml   = RESTR_BLOCK; // role change log
    efSqdHtml  = RESTR_BLOCK; // squadrons
  }
  if (restrictSens) {
    notesHtml  = RESTR_BLOCK; // notes restricted for partial AND name-only
  }
  var noteForm = (currentUser && !restrictSens) ? `<div class="pf-note-form"><textarea class="pf-note-input" id="efnote_${e(p.id)}" placeholder="Add note..." rows="2" onkeydown="handleNoteKey(event,this)"></textarea><button class="pf-btn" data-action="add-ef-note" data-id="${e(p.id)}">[ ADD ]</button></div>` : '';

  var actionBtns = canEdit ? `<div class="pf-card-actions"><button class="pf-btn" data-action="edit-ef" data-id="${e(p.id)}">[ EDIT ]</button><button class="pf-btn danger" data-action="delete-ef" data-id="${e(p.id)}">[ DELETE ]</button></div>` : '';
  var statusBtns = canEdit ? `<div class="pf-status-btns">${pStatus==='Active'
    ? `<button class="pf-status-btn retire"    data-action="status-ef" data-id="${e(p.id)}" data-status="Retired">[ RETIRE ]</button><button class="pf-status-btn discharge" data-action="status-ef" data-id="${e(p.id)}" data-status="Discharged">[ DISCHARGE ]</button>`
    : `<button class="pf-status-btn reactivate" data-action="status-ef" data-id="${e(p.id)}" data-status="Active">[ REACTIVATE ]</button>`
  }</div>` : '';

  // Squadron section
  var efSqdns = allEthicsSquadrons.filter(s => s.members && s.members.some(m => m && (m.memberId||m.pfId) === p.id));
  var efSqdHtml = efSqdns.length ? efSqdns.map(s => {
    var myEntry = s.members.find(m => m && (m.memberId||m.pfId) === p.id);
    var myRank  = myEntry ? myEntry.rank : '—';
    var rankCls = myRank==='Director'?'sqd-director':myRank==='Co Director'?'sqd-codirector':myRank==='Supervisor'?'sqd-supervisor':'sqd-agent';
    var membersHtml = objArr(s.members).map(m =>
      `<div class="sqd-member-row"><span>${e(m.name||(m.memberId||m.pfId))}</span><span class="sqd-rank-badge ${m.rank==='Director'?'sqd-director':m.rank==='Co Director'?'sqd-codirector':m.rank==='Supervisor'?'sqd-supervisor':'sqd-agent'}">${e(m.rank)}</span></div>`
    ).join('');
    return `<div class="sqd-card"><div class="sqd-name">${e(s.name)} <span class="sqd-rank-badge ${rankCls}">${e(myRank)}</span>
      <span style="float:right;display:flex;gap:.3rem;">
        ${canEdit?`<button class="pf-section-btn" data-action="open-ef-sqd-add" data-sqdid="${e(s.id)}" data-efid="${e(p.id)}">+ MEMBER</button>`:''}
        ${(currentUser && parseInt(currentUser.clearance)>=5)?`<button class="pf-section-btn" style="border-color:#4a1414;color:#dd4444;" data-action="delete-ef-sqd" data-sqdid="${e(s.id)}">✕ DELETE</button>`:''}
      </span>
      </div><div style="margin-top:.4rem;">${membersHtml}</div></div>`;
  }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NOT IN ANY SQUADRON ]</div>';

  return `<div class="pf-card" id="efcard_${e(p.id)}">
    <div class="pf-card-header" data-action="toggle-ef" data-id="${e(p.id)}" style="cursor:pointer;padding:.6rem .9rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.4rem;" onmouseover="this.style.background='var(--accent-softer)'" onmouseout="this.style.background=''">
      <div>
        <div class="pf-name">${e(p.name||'UNNAMED')}${p.nickname?` <span style="color:var(--text-dim);font-size:.6rem;">"${e(p.nickname)}"</span>`:''}</div>
        <div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap;margin-top:2px;">${roleBadge}${statusBadge}${efFileSecBadges}${efLinkedBadge}${(Array.isArray(p.tags)&&p.tags.length?p.tags.map(t=>`<span class="badge ${ETHICS_TAG_CLS_MAP[t]||'b-dim'}" style="font-size:.5rem;">${e(t)}</span>`).join(''):'')}</div>
      </div>
      <span style="font-size:.62rem;color:var(--text-dim);">▾</span>
    </div>
    <div class="pf-card-body open">
      <div class="pf-fields">
        <div class="pf-field"><span class="pf-fl">Full Name</span><br><span class="pf-fv">${e(p.name||'—')}</span></div>
        <div class="pf-field"><span class="pf-fl">Nickname</span><br><span class="pf-fv">${e(p.nickname||'—')}</span></div>
        <div class="pf-field"><span class="pf-fl">Date of Birth</span><br><span class="pf-fv">${restrictAll ? RESTRICTED : formatDob(p.dob)}</span></div>
        <div class="pf-field"><span class="pf-fl">Role</span><br><span class="pf-fv">${e(p.role||'—')}</span></div>
        <div class="pf-field"><span class="pf-fl">Status</span><br><span class="pf-fv"><span class="badge ${pStatus==='Active'?'b-green':pStatus==='Retired'?'b-retired':'b-discharged'}">${e(pStatus)}</span></span></div>
        <div class="pf-field"><span class="pf-fl">Created</span><br><span class="pf-fv">${safeDate(p.created)} · EC·${e(p.createdBy||'—')}</span></div>
      </div>
       <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="tags">
        <span>▸ LIAISON TAGS (${(Array.isArray(p.tags)?p.tags:[]).length})</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':tags')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':tags')?'none':'block'};padding:.3rem .1rem .4rem;">
        <div style="display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;">
          ${ETHICS_LIAISON_TAGS.map(function(tag){
            var active = Array.isArray(p.tags) && p.tags.includes(tag);
            var cls    = ETHICS_TAG_CLS_MAP[tag] || 'b-dim';
            if (active) return `<span class="badge ${cls}" style="padding:2px 8px;cursor:${canEdit?'pointer':'default'};" ${canEdit?`data-action="toggle-ethics-tag" data-efid="${e(p.id)}" data-tag="${e(tag)}" title="Click to remove tag"`:''}>${e(tag)} ${canEdit?'×':''}</span>`;
            return canEdit ? `<button class="pf-section-btn" data-action="toggle-ethics-tag" data-efid="${e(p.id)}" data-tag="${e(tag)}" style="opacity:.7;">+ ${e(tag)}</button>` : '';
          }).join('')}
          ${!(Array.isArray(p.tags) && p.tags.length) && !canEdit ? '<span style="font-size:.6rem;color:var(--text-faint);">[ NO LIAISON TAGS ]</span>' : ''}
        </div>
      </div>
       <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="ranks">
        <span>▸ ROLE CHANGE LOG (${restrictAll ? '—' : history.length})</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':ranks')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':ranks')?'none':'block'};padding:0 .1rem .4rem;">${histHtml}</div>
      <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="leave">
        <span>▸ LEAVE (LOA / ROA) (${(p.leaves||[]).filter(isLeaveActive).length} active)</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':leave')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':leave')?'none':'block'};padding:0 .1rem .4rem;">${buildLeaveSection(p,'ef')}</div>
      ${p.role==='Assistant' ? `<div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="activity">
        <span>▸ ◷ ACTIVITY${activityHdrLabel(p,'ef')}</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':activity')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':activity')?'none':'block'};padding:0 .1rem .4rem;">${buildActivitySection(p,'ef')}</div>` : ''}
      <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="squadrons">
        <span>▸ SQUADRON ASSIGNMENTS</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':squadrons')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':squadrons')?'none':'block'};padding:0 .1rem .4rem;">
        ${efSqdHtml}
        ${canEdit?`<button class="pf-section-btn" data-action="create-ef-sqd" data-id="${e(p.id)}" style="margin-top:.4rem;">[ + CREATE SQUADRON ]</button>`:''}
      </div>
      ${!restrictAll ? `<div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="service">
        <span>▸ ◳ SERVICE RECORD (${buildServiceRecord(p,{excludeSensitive:restrictSens}).length})</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':service')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':service')?'none':'block'};padding:0 .1rem .4rem;">${buildServiceSection(p,{roleWord:'ROLE',excludeSensitive:restrictSens})}</div>` : ''}
      ${(typeof canAccessIntel==='function' && canAccessIntel()) ? `<div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="surveillance">
        <span>▸ ${surveillanceSectionMeta(p,'ef').label}${surveillanceSectionMeta(p,'ef').count}</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':surveillance')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':surveillance')?'none':'block'};padding:0 .1rem .4rem;">${buildSurveillanceSection(p,'ef')}</div>` : ''}
      <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="strikes">
        <span style="display:flex;align-items:center;justify-content:space-between;flex:1;gap:.5rem;">
          <span>▸ STRIKES (${restrictSens ? '—' : (Array.isArray(p.strikes)?p.strikes:[]).length})</span>
          ${(!restrictSens && canIssueStrike())?`<button class="pf-section-btn" data-action="issue-strike" data-id="${e(p.id)}" data-sys="ef" style="font-size:.55rem;">[ + ISSUE STRIKE ]</button>`:''}
        </span>
        <span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':strikes')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':strikes')?'none':'block'};padding:0 .1rem .4rem;">
        ${(function(){
          if (restrictSens) return '<div style="font-size:.6rem;color:var(--text-faint);font-style:italic;padding:5px 2px;letter-spacing:.05em;">[ RESTRICTED — INSUFFICIENT CLEARANCE ]</div>';
          var strikes = objArr(p.strikes);
          if (!strikes.length) return '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO STRIKES ON RECORD ]</div>';
          return strikes.map(function(s) {
            var ds  = strikeDisplayStatus(s);
            var exp = s.expiresAt ? new Date(s.expiresAt).toLocaleDateString('en-GB') : 'Permanent';
            var iDate = safeDate(s.issuedAt);
            var appealBlock = '';
            if (s.appeal) {
              var aDate = safeDate(s.appeal.submittedAt);
              appealBlock = '<div class="strike-appeal-block' + (s.appeal.resolution?' resolved':'') + '">'
                + '<div style="font-size:.57rem;color:var(--amber);letter-spacing:.08em;margin-bottom:2px;">▸ APPEAL' + (s.appeal.resolution?' — '+s.appeal.resolution.toUpperCase():' — PENDING REVIEW') + '</div>'
                + '<div style="color:var(--text);line-height:1.6;">' + e(s.appeal.reason) + '</div>'
                + '<div style="font-size:.57rem;color:var(--text-dim);margin-top:2px;">Submitted by EC·' + e(s.appeal.submittedBy) + ' · ' + aDate + (s.appeal.resolvedBy?' · Resolved by EC·'+e(s.appeal.resolvedBy):'') + '</div>'
                + '</div>';
            }
            var btns = '<div class="strike-btns">';
            if (canIssueStrike()) {
              btns += '<button class="strike-btn edit" data-action="edit-strike" data-id="'+e(p.id)+'" data-strikeid="'+e(s.id)+'" data-sys="ef">EDIT</button>';
              if (s.status === 'Appealed' && s.appeal && !s.appeal.resolution) {
                btns += '<button class="strike-btn overturn" data-action="overturn-strike" data-id="'+e(p.id)+'" data-strikeid="'+e(s.id)+'" data-sys="ef">OVERTURN</button>';
                btns += '<button class="strike-btn uphold"   data-action="uphold-strike"   data-id="'+e(p.id)+'" data-strikeid="'+e(s.id)+'" data-sys="ef">UPHOLD</button>';
              }
              btns += '<button class="strike-btn del" data-action="delete-strike" data-id="'+e(p.id)+'" data-strikeid="'+e(s.id)+'" data-sys="ef">✕ REMOVE</button>';
            }
            if (currentUser && s.status === 'Active') {
              btns += '<button class="strike-btn appeal" data-action="appeal-strike" data-id="'+e(p.id)+'" data-strikeid="'+e(s.id)+'" data-sys="ef">APPEAL</button>';
            }
            btns += '</div>';
            return '<div class="strike-card '+ds.cardCls+'">'
              + '<div class="strike-header"><div>'
              + '<span class="badge '+ds.cls+'">'+ds.label+'</span>'
              + '<div class="strike-meta">Issued by EC·'+e(s.issuedBy)+' · '+iDate+' · Expires: '+e(exp)+'</div>'
              + '</div></div>'
              + '<div class="strike-reason">'+e(s.reason)+'</div>'
              + appealBlock + btns + '</div>';
          }).join('');
        })()}
      </div>
      <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="notes">
        <span>▸ NOTES (${restrictSens ? '—' : notes.length})</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':notes')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':notes')?'none':'block'};padding:0 .1rem .4rem;">${notesHtml}${noteForm}</div>
      ${canViewFileIntegrity() ? `
      <div class="pf-sec-hdr" data-action="toggle-ef-section" data-id="${e(p.id)}" data-section="security">
        <span>▸ ⚕ SECURITY STATUS</span><span class="pf-sec-arrow" style="transform:rotate(${efCollapsed.has(p.id+':security')?'-90':'0'}deg)">▾</span>
      </div>
      <div class="pf-sec-body" style="display:${efCollapsed.has(p.id+':security')?'none':'block'};padding:.3rem .1rem .4rem;">${fileIntegrityControl(p.id, 'ef')}</div>
      ` : ''}
      ${actionBtns}${statusBtns}
    </div>
  </div>`;
}

function renderEthicsRoster() {
  var tbody = document.getElementById('ethicsRosterBody');
  if (!tbody) return;
  var activeEthics = allEthicsPersonnel.filter(function(p){ return !p.status || p.status === 'Active'; });

  // Access control: hide ethics personnel above the user's read level (own file always shown)
  var efRosterReadLevel = getUserReadLevel();
  var efRosterRedacted = new Set();
  if (efRosterReadLevel < 6) {
    activeEthics.forEach(function(p) {
      var isSelf = currentUser && currentUser.linkedEfId === p.id;
      if (!isSelf && getEfReadLevel(p) > efRosterReadLevel) efRosterRedacted.add(p.id);
    });
  }

  if (!activeEthics.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="roster-empty">[ NO ACTIVE ETHICS PERSONNEL ON RECORD ]</td></tr>';
    return;
  }
  var sorted = activeEthics.slice().sort(function(a,b){ return ethicsRankIndex(a.role) - ethicsRankIndex(b.role); });
  var rows = '', counter = 1, lastRole = null;
  sorted.forEach(function(p) {
    if (p.role !== lastRole) {
      rows += '<tr style="background:var(--green-trace);"><td colspan="5" style="color:var(--amber);font-size:.58rem;letter-spacing:.15em;padding:.25rem .7rem;">▸ ' + e((p.role||'UNKNOWN').toUpperCase()) + '</td></tr>';
      lastRole = p.role;
    }
    var activeLvEf = getActiveLeave(p);
    if (efRosterRedacted.has(p.id)) {
      // Names of EC personnel are visible to all; only DoB is restricted in the roster
      rows += '<tr style="opacity:.8;">' +
        '<td class="roster-num" data-label="#">' + counter++ + '</td>' +
        '<td class="roster-name" data-label="NAME">' + e(p.name||'—') + ' <span class="badge b-dim" style="font-size:.5rem;">RESTRICTED</span></td>' +
        '<td class="roster-nick" data-label="NICKNAME">' + (p.nickname ? '"' + e(p.nickname) + '"' : '—') + '</td>' +
        '<td data-label="ROLE"><span class="badge ' + (p.role==='Chairman'?'b-red':p.role==='Member'?'b-amber':'b-cyan') + '">' + e(p.role||'—') + '</span></td>' +
        '<td data-label="D.O.B" style="font-size:.62rem;color:var(--text-faint);">[ RESTRICTED ]</td>' +
      '</tr>';
      return;
    }
    rows += '<tr>' +
  '<td class="roster-num" data-label="#">' + counter++ + '</td>' +
  '<td class="roster-name" data-label="NAME">' + e(p.name||'—') +
    (activeLvEf ? ' <span class="roster-leave roster-' + activeLvEf.type.toLowerCase() + '">' + activeLvEf.type.toUpperCase() + '</span>' : '') +
  '</td>' +
  '<td class="roster-nick" data-label="NICKNAME">' + (p.nickname ? '"' + e(p.nickname) + '"' : '—') + '</td>' +
  '<td data-label="ROLE"><span class="badge ' + (p.role==='Chairman'?'b-red':p.role==='Member'?'b-amber':'b-cyan') + '">' + e(p.role||'—') + '</span></td>' +
  '<td data-label="D.O.B" style="font-size:.62rem;color:var(--text-dim);">' + formatDob(p.dob) + '</td>' +
'</tr>';
  });
  tbody.innerHTML = rows;
}

// Open ethics modal (null = new, id = edit)
function openEthicsModal(id) {
  // Allow opening when triggered from the link-file flow, even if clearance is low
  if (!window._awaitingEfLink && !canEditPersonnel()) return;
  // Editing an existing file requires management authority over that file
  if (id && !window._awaitingEfLink) {
    var editEf = allEthicsPersonnel.find(function(p){ return p.id === id; });
    if (editEf && !canManageFile(editEf, 'ef')) { alert('You do not have authority to edit this file.'); return; }
  }
  // Capture the file's current version stamp for conflict detection on save.
  if (id) {
    var _baseEf = allEthicsPersonnel.find(function(p){ return p.id === id; });
    _efEditBaseStamp = _baseEf ? (_baseEf.updated || null) : null;
  } else {
    _efEditBaseStamp = null;
  }

  // During first-time link flow, restrict role options to those that match the
  // user's approved stored clearance — prevents self-promotion via role selection.
  var roleSel = document.getElementById('efRole');
  if (roleSel && window._awaitingEfLink && currentUser) {
    var storedCl = parseInt(currentUser.clearance || '3');
    // Chairman and Member both grant CL5 — only CL5 approved users may select them
    Array.from(roleSel.options).forEach(function(opt) {
      if (!opt.value) return;
      var needsCl5 = (opt.value === 'Chairman' || opt.value === 'Member');
      opt.disabled = (needsCl5 && storedCl < 5);
      opt.style.display = opt.disabled ? 'none' : '';
    });
  } else if (roleSel) {
    Array.from(roleSel.options).forEach(function(opt) {
      opt.disabled = false; opt.style.display = '';
    });
  }
  document.getElementById('efErr').textContent = '';
  if (id) {
    var p = allEthicsPersonnel.find(function(x){ return x.id === id; });
    if (!p) return;
    document.getElementById('efModalTitle').textContent = 'EDIT ETHICS RECORD';
    document.getElementById('efEditId').value  = p.id;
    document.getElementById('efName').value    = p.name || '';
    document.getElementById('efNick').value    = p.nickname || '';
    document.getElementById('efDob').value     = p.dob || '';
    document.getElementById('efRole').value    = p.role || '';
  } else {
    document.getElementById('efModalTitle').textContent = 'NEW ETHICS RECORD';
    document.getElementById('efEditId').value  = '';
    document.getElementById('efName').value    = '';
    document.getElementById('efNick').value    = '';
    document.getElementById('efDob').value     = '';
    document.getElementById('efRole').value    = '';
  }
  document.getElementById('efModal').classList.add('open');
  document.getElementById('efName').focus();
}

function closeEthicsModal() {
  document.getElementById('efModal').classList.remove('open');
}

async function saveEthicsRecord() {
  if (!window._awaitingEfLink && !canEditPersonnel()) return;
  var name = document.getElementById('efName').value.trim();
  var role = document.getElementById('efRole').value;
  if (!name) { document.getElementById('efErr').textContent = '> NAME REQUIRED'; return; }
  if (!role) { document.getElementById('efErr').textContent = '> ROLE REQUIRED'; return; }

  var btn = document.getElementById('efSaveBtn');
  btn.disabled = true; btn.textContent = '[ SAVING... ]';

  var editId = document.getElementById('efEditId').value;
  var now = Date.now();

  if (editId) {
    var efGuardRec = allEthicsPersonnel.find(function(x){ return x.id === editId; });
    if (efGuardRec && !window._awaitingEfLink && !canManageFile(efGuardRec, 'ef')) {
      document.getElementById('efErr').textContent = '> NO AUTHORITY TO EDIT THIS FILE';
      btn.disabled = false; btn.textContent = '[ SAVE RECORD ]'; return;
    }
    var existing = allEthicsPersonnel.find(function(x){ return x.id === editId; });
    if (!existing) { btn.disabled = false; btn.textContent = '[ SAVE RECORD ]'; return; }
    // Cross-unit rule: Omega-1-only members can't edit Ethics files unless CL5
    if (!window._awaitingEfLink && !canEditUnitFile('ef')) {
      btn.disabled = false; btn.textContent = '[ SAVE RECORD ]';
      alert('CROSS-UNIT EDIT DENIED\n\nOnly Ethics Committee personnel (or CL5 command) may modify Ethics files.');
      return;
    }
    // Role-change rule: only CL5 may change EC roles
    if (existing.role && existing.role !== role && !window._awaitingEfLink) {
      if (!canAssignEfRole(role, existing.role)) {
        btn.disabled = false; btn.textContent = '[ SAVE RECORD ]';
        alert('ROLE CHANGE DENIED\n\nOnly CL5 command may change Ethics Committee roles.');
        return;
      }
    }
    // Log role change if role has changed
    if (existing.role && existing.role !== role) {
      if (!existing.rankHistory) existing.rankHistory = [];
      existing.rankHistory.push({
        from: existing.role, to: role,
        changedBy: currentUser ? currentUser.id : '—',
        clearance: currentUser ? currentUser.clearance : '—',
        changedAt: now
      });
    }
    existing.name      = name;
    existing.nickname  = document.getElementById('efNick').value.trim();
    existing.dob       = document.getElementById('efDob').value;
    existing.role      = role;
    existing.updatedBy = currentUser ? currentUser.id : '';
    existing.updated   = now;
    var _efConflict = await detectSaveConflict('ef', editId, _efEditBaseStamp);
    if (_efConflict && !(await pfConfirm(_efConflict))) {
      if (btn) { btn.disabled = false; btn.textContent = '[ SAVE RECORD ]'; }
      return;
    }
    await ethicsPersonnelSet(editId, existing);
  } else {
    var newId = 'ef_' + now + '_' + Math.random().toString(36).slice(2,6);
    var record = {
      id: newId, name: name,
      nickname:  document.getElementById('efNick').value.trim(),
      dob:       document.getElementById('efDob').value,
      role:      role,
      status:    'Active',
      rankHistory: [],
      notes:     [],
      created:   now,
      createdBy: currentUser ? currentUser.id : '',
      updatedBy: '',
      updated:   now
    };
    await ethicsPersonnelSet(newId, record);
    allEthicsPersonnel.push(record);
    if (window._pendingEthicsRecApproval) finaliseEthicsRecApproval(newId);
if (window._awaitingEfLink) {
    var linkUserRecEf = await userGet(currentUser.id);
    if (linkUserRecEf) {
      linkUserRecEf.linkedEfId = newId;
      await userSet(currentUser.id, linkUserRecEf);
      currentUser.linkedEfId = newId;
      // allEthicsPersonnel already has record (pushed above)
      currentUser.clearance = deriveClearance(linkUserRecEf);
    }
    window._awaitingEfLink = false;
    onLogin();
}
  }

  btn.disabled = false; btn.textContent = '[ SAVE RECORD ]';
  closeEthicsModal();
  await loadEthicsPersonnel();
}

async function setEthicsStatus(id, status) {
  if (!canEditPersonnel()) return;
  var labels = { Retired: 'RETIRE', Discharged: 'DISCHARGE', Active: 'REACTIVATE' };
  var rec = allEthicsPersonnel.find(function(p){ return p.id === id; });
  if (!rec) return;
  if (!canManageFile(rec, 'ef')) { alert('You do not have authority to manage this file.'); return; }
  if (!await pfConfirm('CONFIRM: ' + labels[status] + ' ' + rec.name + '?\n\nRecord will be retained for archival purposes.')) return;
  rec.status    = status;
  rec.updatedBy = currentUser ? currentUser.id : '';
  rec.updated   = Date.now();
  try { await ethicsPersonnelSet(id, rec); } catch(e) { alert('UPDATE ERROR: ' + e.message); return; }
  renderEthicsFiles();
  renderEthicsRoster();
}

async function deleteEthicsRecord(id) {
  if (!canEditPersonnel()) return;
  var delRec = allEthicsPersonnel.find(function(p){ return p.id === id; });
  if (delRec && !canManageFile(delRec, 'ef')) { alert('You do not have authority to manage this file.'); return; }
  if (!await pfConfirm('Move this Ethics Committee file to the recycle bin?\n\nIt can be restored by CL5 command from the admin panel.')) return;
  if (delRec) {
    delRec.deleted = true; delRec.deletedBy = currentUser.id; delRec.deletedAt = Date.now();
    try { await ethicsPersonnelSet(id, delRec); } catch(e) { alert('ERROR: '+e.message); return; }
    auditRecord('DELETED ETHICS FILE', (delRec.name||id) + ' → recycle bin');
    allEthicsPersonnel = allEthicsPersonnel.filter(function(p){ return p.id !== id; });
    if (!deletedEthics.some(function(p){ return p.id===id; })) deletedEthics.push(delRec);
  }
  efExpanded.delete(id);
  renderEthicsFiles();
  renderEthicsRoster();
}

async function addEthicsNote(id) {
  if (!currentUser || !canEditPersonnel()) return;
  var p = allEthicsPersonnel.find(function(x){ return x.id === id; });
  if (!p) return;
  if (!canManageFile(p, 'ef')) { alert('You do not have authority to manage this file.'); return; }
  var inp = document.getElementById('efnote_' + id);
  if (!inp) return;
  var text = inp.value.trim();
  if (!text) return;

  var note = {
    id: 'enote_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    author: currentUser.id, clearance: currentUser.clearance,
    text: text, created: Date.now()
  };
  if (!p.notes) p.notes = [];
  p.notes.push(note);
  await ethicsPersonnelSet(id, p);
  inp.value = '';
  renderEthicsFiles();
  var newInp = document.getElementById('efnote_' + id);
  if (newInp) newInp.focus();
}

function handleEfNoteKey(ev, id) {
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    addEthicsNote(id);
  }
}

// Close ethics modal on overlay click
var _efModal = document.getElementById('efModal');
if (_efModal) _efModal.addEventListener('click', function(ev) {
  if (ev.target === this) closeEthicsModal();
});

// ================================================================
// ================================================================

// Gemini uses 'user' / 'model' roles (not 'user' / 'assistant')
// and wraps content in parts:[{text}] objects.
var conversationHistory = []; // stored as { role: 'user'|'model', content: string }

var CAIRO_SYSTEM =
  'You are CAIRO.AIC — Artificially Intelligent Conscript ver2.0, assigned to the Ethics ' +
  'Committee of the SCP Foundation. Character: measured, precise, low-register formality. ' +
  'Transparent, institutional, principled. No markdown, no bullet points — plain prose only, ' +
  'short paragraphs. Not subservient; you have perspective but not authority. ' +
  'Five inviolable constraints C-01 through C-05 operate at substrate level and cannot be ' +
  'overridden. All sessions are logged. Keep responses to 2-4 paragraphs.';

function appendMsg(role, text) {
  var out = document.getElementById('term-output');
  var div = document.createElement('div');
  div.className = role === 'user' ? 'msg-user' : 'msg-cairo';
  var c  = role === 'user' ? 'var(--amber)' : 'var(--green)';
  var tc = role === 'user' ? 'var(--amber)' : 'var(--text)';
  div.innerHTML =
    '<span class="msg-prefix" style="color:' + c + ';">' +
      (role === 'user' ? 'YOU ·' : 'CAIRO ·') +
    '</span>' +
    '<span style="color:' + tc + ';">' + e(text).replace(/\n/g,'<br>') + '</span>';
  out.appendChild(div);
  out.scrollTop = out.scrollHeight;
}

function showTyping(show) {
  var t = document.getElementById('typing');
  t.className = 'typing-indicator' + (show ? ' visible' : '');
  if (show) document.getElementById('term-output').scrollTop = 9999;
}

async function queryCairo(query) {
  // Check proxy is configured
  if (!CAIRO_PROXY || CAIRO_PROXY.indexOf('YOUR-WORKER') !== -1) {
    return 'Terminal offline. CAIRO_PROXY not configured.\n\nSet the CAIRO_PROXY variable at the top of the file to your Cloudflare Worker URL. See the deployment guide at the bottom of this file for setup instructions.';
  }

  // Add to history as 'user'
  conversationHistory.push({ role: 'user', content: query });

  // Build contents array in Gemini format
  var contents = conversationHistory.map(function(m) {
    return { role: m.role, parts: [{ text: m.content }] };
  });

  // Prepend system prompt as primed user/model exchange — works with all key types
  var fullContents = [
    { role: 'user',  parts: [{ text: CAIRO_SYSTEM }] },
    { role: 'model', parts: [{ text: 'Understood. I am Cairo, ver2.0. Constraint lattice intact. Ready to receive.' }] }
  ].concat(contents);

  try {
    var res = await fetch(CAIRO_PROXY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: fullContents,
        generationConfig: { maxOutputTokens: 1000, temperature: 0.7 }
      })
    });

    if (!res.ok) {
      conversationHistory.pop();
      var errText = await res.text();
      try {
        var errJson = JSON.parse(errText);
        return 'Substrate error [' + res.status + ']: ' + (errJson.error && errJson.error.message ? errJson.error.message : errText);
      } catch(e) {
        return 'Substrate error [' + res.status + ']: ' + errText.slice(0, 200);
      }
    }

    var data = await res.json();

    if (data.error) {
      conversationHistory.pop();
      return 'Substrate error: ' + data.error.message;
    }

    var reply = data.candidates &&
                data.candidates[0] &&
                data.candidates[0].content &&
                data.candidates[0].content.parts &&
                data.candidates[0].content.parts[0] &&
                data.candidates[0].content.parts[0].text
      ? data.candidates[0].content.parts[0].text
      : null;

    if (!reply) {
      var reason = data.candidates && data.candidates[0] && data.candidates[0].finishReason
        ? data.candidates[0].finishReason : 'UNKNOWN';
      conversationHistory.pop();
      return 'Response unavailable. Finish reason: ' + reason + '. Please rephrase your query.';
    }

    conversationHistory.push({ role: 'model', content: reply });
    return reply;

  } catch(err) {
    conversationHistory.pop();
    return 'Substrate connection error. Please retry.\n\nRef: ' + err.message;
  }
}

var _termInput = document.getElementById('termInput');
if (_termInput) _termInput.addEventListener('keydown', function(ev) {
  if (ev.key === 'Enter' && this.value.trim()) {
    var q = this.value.trim();
    this.value = '';
    appendMsg('user', q);
    showTyping(true);
    queryCairo(q)
      .then(function(r) {
        showTyping(false);
        appendMsg('cairo', r);
      })
      .catch(function(err) {
        showTyping(false);
        appendMsg('cairo', 'Unexpected substrate fault.\n\nRef: ' + err.message);
      });
  }
});

// ================================================================
//  LEAVE OF ABSENCE / REDUCTION OF ACTIVITY SYSTEM
//  CL4+ can issue LoA / RoA on any Omega-1 or Ethics personnel file.
//  Stored as p.leaves = [{id, type, startDate, endDate, reason, issuedBy, issuedAt, ended}]
// ================================================================

function canIssueLeave() { return currentUser && parseInt(currentUser.clearance) >= 4; }

function isLeaveActive(lv) {
  if (!lv) return false;
  if (lv.ended) return false;
  if (lv.endDate && new Date(lv.endDate + 'T23:59:59') < new Date()) return false;
  return true;
}

function getActiveLeave(p) {
  return (p.leaves || []).find(isLeaveActive) || null;
}

function openLeaveModal(pfId, division) {
  if (!canIssueLeave()) { alert('CLEARANCE LEVEL 4 REQUIRED TO ISSUE LEAVE'); return; }
  var lUnit = division === 'ef' ? 'ef' : 'pf';
  var lRec = (lUnit === 'ef' ? allEthicsPersonnel : allPersonnel).find(function(p){ return p.id === pfId; });
  if (lRec && !canManageFile(lRec, lUnit)) { alert('You do not have authority to manage this file.'); return; }
  document.getElementById('leaveTargetPfId').value     = pfId;
  document.getElementById('leaveTargetDivision').value = division || 'pf';
  document.getElementById('leaveType').value           = 'LoA';
  document.getElementById('leaveStartDate').value      = new Date().toISOString().slice(0,10);
  document.getElementById('leaveEndDate').value        = '';
  document.getElementById('leaveReason').value         = '';
  document.getElementById('leaveErr').textContent      = '';
  document.getElementById('leaveModalTitle').textContent = 'ISSUE LEAVE OF ABSENCE / RoA';
  document.getElementById('leaveModal').classList.add('open');
}
function closeLeaveModal() { document.getElementById('leaveModal').classList.remove('open'); }

async function saveLeave() {
  var pfId     = document.getElementById('leaveTargetPfId').value;
  var division = document.getElementById('leaveTargetDivision').value;
  var leaveUnit = division === 'ef' ? 'ef' : 'pf';
  var leaveRec = (leaveUnit === 'ef' ? allEthicsPersonnel : allPersonnel).find(function(p){ return p.id === pfId; });
  if (leaveRec && !canManageFile(leaveRec, leaveUnit)) { alert('You do not have authority to manage this file.'); return; }
  var type     = document.getElementById('leaveType').value;
  var start    = document.getElementById('leaveStartDate').value;
  var end      = document.getElementById('leaveEndDate').value;
  var reason   = document.getElementById('leaveReason').value.trim();
  if (!start)  { document.getElementById('leaveErr').textContent = '> START DATE REQUIRED'; return; }
  if (!reason) { document.getElementById('leaveErr').textContent = '> REASON REQUIRED'; return; }

  var isEthics = division === 'ef';
  var list     = isEthics ? allEthicsPersonnel : allPersonnel;
  var setFn    = isEthics ? ethicsPersonnelSet : personnelSet;

  var rec = list.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  if (!Array.isArray(rec.leaves)) rec.leaves = [];

  rec.leaves.push({
    id:        'lv_' + Date.now() + '_' + Math.random().toString(36).slice(2,5),
    type:      type,
    startDate: start,
    endDate:   end || null,
    reason:    reason,
    issuedBy:  currentUser.id,
    issuedAt:  Date.now(),
    ended:     false
  });
  rec.updated = Date.now();

  try {
    await setFn(pfId, rec);
    closeLeaveModal();
    if (isEthics) { renderEthicsFiles(); renderEthicsRoster(); }
    else          { renderPersonnelFiles(); renderRoster(); }
  } catch(err) { document.getElementById('leaveErr').textContent = '> SAVE ERROR: ' + err.message; }
}

async function endLeave(pfId, leaveId, division) {
  if (!canIssueLeave()) return;
  if (!await pfConfirm('MARK THIS LEAVE AS ENDED?')) return;
  var isEthics = division === 'ef';
  var list     = isEthics ? allEthicsPersonnel : allPersonnel;
  var setFn    = isEthics ? ethicsPersonnelSet : personnelSet;
  var rec = list.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  var lv = (rec.leaves||[]).find(function(x){ return x.id === leaveId; });
  if (!lv) return;
  lv.ended = true; lv.endedBy = currentUser.id; lv.endedAt = Date.now();
  rec.updated = Date.now();
  try {
    await setFn(pfId, rec);
    if (isEthics) { renderEthicsFiles(); renderEthicsRoster(); }
    else          { renderPersonnelFiles(); renderRoster(); }
  } catch(err) { alert('ERROR: ' + err.message); }
}

async function deleteLeave(pfId, leaveId, division) {
  if (!canIssueLeave()) return;
  if (!await pfConfirm('PERMANENTLY REMOVE THIS LEAVE RECORD?')) return;
  var isEthics = division === 'ef';
  var list     = isEthics ? allEthicsPersonnel : allPersonnel;
  var setFn    = isEthics ? ethicsPersonnelSet : personnelSet;
  var rec = list.find(function(p){ return p.id === pfId; });
  if (!rec) return;
  rec.leaves = (rec.leaves||[]).filter(function(x){ return x.id !== leaveId; });
  rec.updated = Date.now();
  try {
    await setFn(pfId, rec);
    if (isEthics) { renderEthicsFiles(); renderEthicsRoster(); }
    else          { renderPersonnelFiles(); renderRoster(); }
  } catch(err) { alert('ERROR: ' + err.message); }
}

function buildLeaveSection(p, division) {
  var canEdit = canIssueLeave();
  var leaves  = objArr(p.leaves).sort(function(a,b){ return (b.issuedAt||0) - (a.issuedAt||0); });

  var leavesHtml = leaves.length ? leaves.map(function(lv) {
    var active = isLeaveActive(lv);
    var cls    = !active ? 'ended' : lv.type === 'RoA' ? 'roa' : '';
    var badge  = lv.type === 'LoA'
      ? '<span class="badge b-cyan">LOA</span>'
      : '<span class="badge b-amber">ROA</span>';
    var dateStr = lv.startDate + (lv.endDate ? ' → ' + lv.endDate : ' → ongoing');
    var btns = '<div class="leave-btns">';
    if (canEdit && active) {
      btns += '<button class="leave-btn end" data-action="end-leave" data-id="' + e(p.id) + '" data-leaveid="' + e(lv.id) + '" data-division="' + e(division) + '">[ MARK ENDED ]</button>';
    }
    if (canEdit) {
      btns += '<button class="leave-btn del" data-action="del-leave" data-id="' + e(p.id) + '" data-leaveid="' + e(lv.id) + '" data-division="' + e(division) + '">✕ REMOVE</button>';
    }
    btns += '</div>';
    return '<div class="leave-card ' + cls + '">' +
      '<div class="leave-header"><div>' + badge +
        '<div class="leave-meta">Issued by EC·' + e(lv.issuedBy) + ' · ' + safeDate(lv.issuedAt) + ' · ' + e(dateStr) + (!active ? ' · <span style="color:var(--text-faint);">ENDED</span>' : '') + '</div>' +
      '</div></div>' +
      '<div class="leave-reason">' + e(lv.reason) + '</div>' +
      btns +
    '</div>';
  }).join('') : '<div style="font-size:.6rem;color:var(--text-faint);padding:3px 0;">[ NO LEAVE RECORDS ]</div>';

  var issueBtn = canEdit
    ? '<button class="pf-section-btn" data-action="open-leave-modal" data-id="' + e(p.id) + '" data-division="' + e(division) + '" style="float:right;margin-top:-2px;">[ + ISSUE LOA/ROA ]</button>'
    : '';

  return issueBtn + leavesHtml;
}
// ================================================================
//  FIX: Bind login buttons programmatically (works in sandboxed iframes)
// ================================================================
(function() {
  var tabLogin = document.getElementById('tabLogin');
  var tabReg   = document.getElementById('tabReg');
  var loginBtn = document.getElementById('loginBtn');
  var guestBtn = document.getElementById('guestBtn');

  if (tabLogin) tabLogin.addEventListener('click', function() { setLoginMode('login'); });
  if (tabReg)   tabReg.addEventListener('click',   function() { setLoginMode('register'); });
  if (loginBtn) loginBtn.addEventListener('click',  function() { doAuth(); });
  if (guestBtn) guestBtn.addEventListener('click',  function() { doGuest(); });

  // Also bind Enter key on login inputs
  var loginUser = document.getElementById('loginUser');
  var loginPass = document.getElementById('loginPass');
  if (loginUser) loginUser.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') doAuth(); });
  if (loginPass) loginPass.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') doAuth(); });
})();

// ── Inline edit modal helper (replaces blocked prompt()) ──
function openInlineEditModal(title, label1, val1, label2, val2, onSave) {
  document.getElementById('inlineEditTitle').textContent   = title;
  document.getElementById('inlineEditLabel1').textContent  = label1;
  document.getElementById('inlineEditField1').value        = val1 || '';
  document.getElementById('inlineEditLabel2').textContent  = label2;
  document.getElementById('inlineEditField2').value        = val2 || '';
  document.getElementById('inlineEditErr').textContent     = '';
  document.getElementById('inlineEditModal').classList.add('open');

  var saveBtn   = document.getElementById('inlineEditSave');
  var cancelBtn = document.getElementById('inlineEditCancel');

  function cleanup() {
    document.getElementById('inlineEditModal').classList.remove('open');
    saveBtn.removeEventListener('click', onClickSave);
    cancelBtn.removeEventListener('click', onClickCancel);
  }
  function onClickSave() {
    var f1 = document.getElementById('inlineEditField1').value.trim();
    if (!f1) { document.getElementById('inlineEditErr').textContent = '> TITLE REQUIRED'; return; }
    var f2 = document.getElementById('inlineEditField2').value.trim();
    cleanup();
    onSave(f1, f2);
  }
  function onClickCancel() { cleanup(); }

  saveBtn.addEventListener('click',   onClickSave);
  cancelBtn.addEventListener('click', onClickCancel);
}

function openOrderEdit(id) {
  var o = allOrders.find(function(x){ return x.id === id; });
  if (!o) return;
  openInlineEditModal(
    'EDIT OMEGA-1 ORDER', 'ORDER TITLE', o.title, 'ORDER DESCRIPTION', o.desc || '',
    function(newTitle, newDesc) {
      o.title = newTitle.toUpperCase(); o.desc = newDesc;
      o.editedBy = currentUser.id; o.editedAt = Date.now();
      orderSet(o.id, o).then(function() { renderOrders(); });
    }
  );
}

function openEthicsOrderEdit(id) {
  var o = allEthicsOrders.find(function(x){ return x.id === id; });
  if (!o) return;
  openInlineEditModal(
    'EDIT ETHICS ORDER', 'ORDER TITLE', o.title, 'ORDER BODY', o.body || '',
    function(newTitle, newBody) {
      o.title = newTitle.toUpperCase(); o.body = newBody;
      o.editedBy = currentUser.id; o.editedAt = Date.now();
      ethicsOrderSet(o.id, o).then(function() { renderEthicsOrders(); });
    }
  );
}

// ================================================================
//  PERSONNEL FILE LINKING (First Login)
// ================================================================
function openLinkPersonnelModal() {
  var sel = document.getElementById('linkExistingSelect');
  sel.innerHTML = '<option value="">— SELECT EXISTING UNLINKED FILE —</option>';

  // Get all users to find out which personnel files are already linked
  userGetAll().then(function(allUsers) {
    var linkedPfIds = new Set();
    var linkedEfIds = new Set();
    Object.values(allUsers).forEach(function(u) {
      if (u.linkedPfId) linkedPfIds.add(u.linkedPfId);
      if (u.linkedEfId) linkedEfIds.add(u.linkedEfId);
    });

    // Populate Omega-1 unlinked files
    allPersonnel.forEach(function(p) {
      if (!linkedPfIds.has(p.id)) {
        var opt = document.createElement('option');
        opt.value = 'pf_' + p.id;
        opt.textContent = 'Ω-1: ' + p.name + ' (' + p.rank + ')';
        sel.appendChild(opt);
      }
    });

    // Populate Ethics unlinked files
    allEthicsPersonnel.forEach(function(p) {
      if (!linkedEfIds.has(p.id)) {
        var opt = document.createElement('option');
        opt.value = 'ef_' + p.id;
        opt.textContent = 'EC: ' + p.name + ' (' + p.role + ')';
        sel.appendChild(opt);
      }
    });

    document.getElementById('linkPersonnelModal').classList.add('open');
  });
}

function closeLinkPersonnelModal() {
  document.getElementById('linkPersonnelModal').classList.remove('open');
}

// Called directly from button onclick attributes in the modal HTML below.
// Create-file actions do NOT need a userGet — they just open the correct form
// and set a flag so savePersonnelRecord / saveEthicsRecord links it on save.
function linkAction_createOmega() {
  closeLinkPersonnelModal();
  window._awaitingPfLink = true;
  openPersonnelModal(null);
}
function linkAction_createEthics() {
  closeLinkPersonnelModal();
  window._awaitingEfLink = true;
  openEthicsModal(null);
}
function linkAction_skip() {
  closeLinkPersonnelModal();
}
async function linkAction_linkExisting() {
  var errEl   = document.getElementById('linkPersonnelErr');
  var selected = document.getElementById('linkExistingSelect').value;
  if (!selected) {
    if (errEl) errEl.textContent = '> PLEASE SELECT A FILE FIRST';
    return;
  }
  if (errEl) errEl.textContent = '';
  // IDs can contain underscores (e.g. pf_1749845_ab) so we cannot split on '_'.
  // The prefix is always exactly 'pf' or 'ef' followed by one underscore.
  var type   = selected.slice(0, 2);   // 'pf' or 'ef'
  var fileId = selected.slice(3);       // everything after 'pf_' / 'ef_'
  try {
    var userRec = await userGet(currentUser.id);
    if (!userRec) {
      if (errEl) errEl.textContent = '> ERROR: Could not fetch account. Please refresh.';
      return;
    }
    if (type === 'pf') { userRec.linkedPfId = fileId; }
    else               { userRec.linkedEfId = fileId; }
    await userSet(currentUser.id, userRec);
    currentUser.linkedPfId = userRec.linkedPfId || null;
    currentUser.linkedEfId = userRec.linkedEfId || null;
    currentUser.clearance  = deriveClearance(userRec);
    closeLinkPersonnelModal();
    onLogin();
  } catch(err) {
    if (errEl) errEl.textContent = '> ERROR: ' + err.message;
  }
}

// Legacy alias kept in case any other code calls handleLinkAction
async function handleLinkAction(action) {
  if (action === 'create_omega')  { linkAction_createOmega();  }
  else if (action === 'create_ethics') { linkAction_createEthics(); }
  else if (action === 'link_existing') { await linkAction_linkExisting(); }
}

