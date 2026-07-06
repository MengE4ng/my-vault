const enc = new TextEncoder();
    const dec = new TextDecoder();
    const ITER = 250000;
    let mode = 'encrypt';

    const $ = id => document.getElementById(id);

    /* ---------- byte / base64 helpers ---------- */
    function bytesToB64(bytes) {
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin);
    }
    function b64ToBytes(b64) {
      const bin = atob(b64.trim());
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    function bytesToHex(bytes) {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /* ---------- hieroglyph encoding (1 byte -> 1 glyph, bijective) ---------- */
    const GLYPH_BASE = 0x13000;              // Egyptian Hieroglyphs block start
    const GLYPH_POOL = [];
    for (let i = 0; i < 256; i++) GLYPH_POOL.push(String.fromCodePoint(GLYPH_BASE + i));
    const randGlyph = () => GLYPH_POOL[(Math.random() * 256) | 0];

    function bytesToGlyphs(bytes) {
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += GLYPH_POOL[bytes[i]];
      return s;
    }
    function glyphsToBytes(str) {
      const chars = Array.from(str.trim().replace(/\s+/g, '')); // split by code point
      const out = new Uint8Array(chars.length);
      for (let i = 0; i < chars.length; i++) {
        const v = chars[i].codePointAt(0) - GLYPH_BASE;
        if (v < 0 || v > 255) throw new Error('not a valid glyph');
        out[i] = v;
      }
      return out;
    }

    /* ---------- reversible secret <-> hieroglyphs ---------- */
    function secretToGlyphs(secret) {
      return bytesToGlyphs(enc.encode(secret));   // UTF-8 bytes -> glyphs
    }
    function glyphsToSecret(glyphStr) {
      return dec.decode(glyphsToBytes(glyphStr)); // glyphs -> UTF-8 bytes -> string
    }
    function isGlyphString(s) {
      const t = s.trim();
      if (!t) return false;
      for (const ch of t) {
        const cp = ch.codePointAt(0);
        if (cp < GLYPH_BASE || cp > GLYPH_BASE + 255) return false;
      }
      return true;
    }
    // Resolve whatever is in the field to the real secret (decode if obfuscated)
    function resolveSecret(raw) {
      return isGlyphString(raw) ? glyphsToSecret(raw) : raw;
    }

    /* ---------- key derivation ---------- */
    async function importBase(secret) {
      return crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey', 'deriveBits']);
    }
    async function deriveAesKey(base, salt) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
      );
    }

    /* ---------- encrypt / decrypt ---------- */
    async function encryptText(plain, secret) {
      const base = await importBase(secret);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveAesKey(base, salt);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));

      const packed = new Uint8Array(salt.length + iv.length + ct.length);
      packed.set(salt, 0);
      packed.set(iv, salt.length);
      packed.set(ct, salt.length + iv.length);

      return bytesToGlyphs(packed);
    }

    async function decryptText(blob, secret) {
      const packed = glyphsToBytes(blob);
      if (packed.length < 29) throw new Error('too short');
      const salt = packed.slice(0, 16);
      const iv = packed.slice(16, 28);
      const ct = packed.slice(28);
      const base = await importBase(secret);
      const key = await deriveAesKey(base, salt);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      return dec.decode(pt);
    }

    /* ---------- signature animation: scramble-settle the obfuscated key ---------- */
    function animateGlyphs(target) {
      const el = $('glyphs');
      el.classList.remove('idle');
      const chars = Array.from(target);            // one entry per glyph (handles surrogate pairs)
      const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduce) { el.textContent = target; return; }
      const total = chars.length;
      let frame = 0;
      const settleAt = i => Math.floor(i * 0.6);
      clearInterval(el._anim);
      el._anim = setInterval(() => {
        let s = '';
        for (let i = 0; i < total; i++) {
          s += (frame >= settleAt(i)) ? chars[i] : randGlyph();
        }
        el.textContent = s;
        frame++;
        if (frame > settleAt(total) + 2) { clearInterval(el._anim); el.textContent = target; }
      }, 28);
    }

    /* ---------- output reveal ---------- */
    function revealOutput(text) {
      const el = $('output');
      const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduce || mode === 'decrypt') { el.value = text; return; }
      const chars = Array.from(text);              // encrypt output is glyphs
      let frame = 0;
      clearInterval(el._anim);
      el._anim = setInterval(() => {
        let s = '';
        for (let i = 0; i < chars.length; i++) {
          s += (Math.floor(i * 0.5) <= frame) ? chars[i] : randGlyph();
        }
        el.value = s;
        frame++;
        if (Math.floor(chars.length * 0.5) <= frame) { clearInterval(el._anim); el.value = text; }
      }, 16);
    }

    /* ---------- run ---------- */
    async function run() {
      const input = $('input').value;
      const raw = $('secret').value;
      const status = $('status');
      status.className = 'status';
      status.textContent = '';

      if (!raw) { status.textContent = 'enter a secret key'; status.className = 'status err'; return; }
      if (!input) { status.textContent = 'nothing to ' + mode; status.className = 'status err'; return; }

      // If the field holds an obfuscated (hieroglyph) key, decode it back to the real secret.
      let secret;
      try {
        secret = resolveSecret(raw);
      } catch (e) {
        status.textContent = 'that obfuscated key is malformed';
        status.className = 'status err';
        return;
      }
      if (!secret) { status.textContent = 'decoded key is empty'; status.className = 'status err'; return; }

      $('go').disabled = true;
      status.textContent = 'working…';
      try {
        const out = mode === 'encrypt' ? await encryptText(input, secret) : await decryptText(input, secret);
        animateGlyphs(secretToGlyphs(secret));   // show the reversible obfuscated key
        revealOutput(out);
        $('lock').textContent = '🔓';
        setTimeout(() => { $('lock').textContent = '🔒'; }, 900);
        status.textContent = mode === 'encrypt' ? 'encrypted ✓' : 'decrypted ✓';
        status.className = 'status ok';
      } catch (e) {
        $('output').value = '';
        status.textContent = mode === 'encrypt' ? 'could not encrypt' : 'wrong secret or corrupted text';
        status.className = 'status err';
      } finally {
        $('go').disabled = false;
      }
    }

    /* live-update the obfuscated-key readout as the secret is typed */
    function refreshVault() {
      const raw = $('secret').value;
      const el = $('glyphs');
      if (!raw) {
        el.textContent = '— type a secret to obfuscate it —';
        el.classList.add('idle');
        return;
      }
      el.classList.remove('idle');
      try {
        // If they've pasted an obfuscated key, echo it; otherwise obfuscate the plain secret.
        el.textContent = isGlyphString(raw) ? raw.trim() : secretToGlyphs(raw);
      } catch (e) {
        el.textContent = raw;
      }
    }

    /* ---------- ui plumbing ---------- */
    function setMode(m) {
      mode = m;
      const isEnc = m === 'encrypt';
      $('tab-enc').setAttribute('aria-selected', isEnc);
      $('tab-dec').setAttribute('aria-selected', !isEnc);
      $('inputLabel').textContent = isEnc ? 'Plain text' : 'Ciphertext';
      $('inputHint').textContent = isEnc ? 'what you want to hide' : 'paste the hieroglyphs';
      $('outputLabel').textContent = isEnc ? 'Ciphertext' : 'Plain text';
      $('go').textContent = isEnc ? 'Encrypt' : 'Decrypt';
      $('output').classList.toggle('cipher', isEnc);
      $('input').value = ''; $('output').value = '';
      $('input').placeholder = isEnc ? 'Type or paste your message…' : 'Paste the hieroglyphs…';
      $('output').placeholder = isEnc ? 'Result appears here…' : 'Decrypted message appears here…';
      refreshVault();
      $('status').textContent = ''; $('status').className = 'status';
    }
    function toggleReveal() {
      const s = $('secret'), b = $('reveal');
      const show = s.type === 'password';
      s.type = show ? 'text' : 'password';
      b.textContent = show ? 'hide' : 'show';
    }
    function clearAll() {
      $('input').value = ''; $('output').value = ''; $('secret').value = '';
      refreshVault();
      $('status').textContent = ''; $('status').className = 'status';
    }
    async function copyOut() {
      const v = $('output').value;
      if (!v) return;
      try { await navigator.clipboard.writeText(v); flash('copied ✓'); }
      catch { $('output').select(); document.execCommand('copy'); flash('copied ✓'); }
    }
    // copy the obfuscated secret
    async function copyKey() {
      const raw = $('secret').value;
      if (!raw) { flashErr('no secret yet'); return; }
      let g;
      try { g = isGlyphString(raw) ? raw.trim() : secretToGlyphs(raw); }
      catch { flashErr('cannot obfuscate'); return; }
      try { await navigator.clipboard.writeText(g); flash('key copied ✓'); }
      catch { flashErr('copy failed'); }
    }
    // drop the obfuscated secret straight into the field, ready to decrypt with
    function useKey() {
      const raw = $('secret').value;
      if (!raw) { flashErr('no secret yet'); return; }
      if (isGlyphString(raw)) { flash('already obfuscated'); return; }
      let g;
      try { g = secretToGlyphs(raw); }
      catch { flashErr('cannot obfuscate'); return; }
      const s = $('secret');
      s.value = g;
      s.type = 'text';                 // glyphs are safe to show; the real secret stays hidden
      $('reveal').textContent = 'hide';
      refreshVault();
      flash('field now holds the obfuscated key');
    }
    function flash(msg) {
      const s = $('status'); s.textContent = msg; s.className = 'status ok';
    }
    function flashErr(msg) {
      const s = $('status'); s.textContent = msg; s.className = 'status err';
    }

    /* live obfuscation as you type + shortcuts */
    document.getElementById('secret').addEventListener('input', refreshVault);
    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run();
    });

    /* guard: crypto must exist */
    if (!window.crypto || !crypto.subtle) {
      document.addEventListener('DOMContentLoaded', () => {
        $('status').textContent = 'this browser has no Web Crypto — open over https:// or file://';
        $('status').className = 'status err';
        $('go').disabled = true;
      });
    }

    /* ============================================================
       SAVED MESSAGES
       Only the ciphertext (already AES-GCM encrypted) is ever sent to
       Supabase — never the secret, never the plaintext. Saving is an
       explicit action the person takes, not automatic.
       ============================================================ */

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    async function saveCurrentCipher() {
      const status = $('status');
      if (mode !== 'encrypt') {
        status.textContent = 'switch to encrypt to save ciphertext';
        status.className = 'status err';
        return;
      }
      const ciphertext = $('output').value;
      if (!ciphertext) {
        status.textContent = 'nothing to save yet — encrypt something first';
        status.className = 'status err';
        return;
      }
      const label = $('saveLabel').value.trim();
      const saveBtn = $('saveBtn');
      saveBtn.disabled = true;
      try {
        const { data: { user } } = await supabaseClient.auth.getUser();
        if (!user) { status.textContent = 'sign in required to save'; status.className = 'status err'; return; }
        const { error } = await supabaseClient
          .from('saved_ciphers')
          .insert({ user_id: user.id, label: label || null, ciphertext });
        if (error) throw error;
        $('saveLabel').value = '';
        status.textContent = 'saved to your vault ✓';
        status.className = 'status ok';
        await loadSavedList();
      } catch (e) {
        status.textContent = 'could not save: ' + (e.message || 'unknown error');
        status.className = 'status err';
      } finally {
        saveBtn.disabled = false;
      }
    }

    async function loadSavedList() {
      const container = $('savedList');
      if (!container) return;
      try {
        const { data: { user } } = await supabaseClient.auth.getUser();
        if (!user) return;
        const { data, error } = await supabaseClient
          .from('saved_ciphers')
          .select('id, label, ciphertext, created_at')
          .order('created_at', { ascending: false });
        if (error) throw error;

        container.innerHTML = '';
        if (!data || data.length === 0) {
          container.innerHTML = '<div class="saved-empty">no saved messages yet</div>';
          return;
        }
        for (const row of data) {
          const item = document.createElement('div');
          item.className = 'saved-item';
          const date = new Date(row.created_at).toLocaleDateString(undefined, {
            year: 'numeric', month: 'short', day: 'numeric'
          });
          item.innerHTML = `
            <div class="saved-item-main">
              <span class="saved-item-label">${escapeHtml(row.label || 'untitled')}</span>
              <span class="saved-item-date">${date}</span>
            </div>
            <div class="saved-item-actions">
              <button class="mini" type="button">load ↑</button>
              <button class="mini danger" type="button">delete</button>
            </div>`;
          const [loadBtn, delBtn] = item.querySelectorAll('button');
          loadBtn.addEventListener('click', () => loadSavedCipher(row.ciphertext));
          delBtn.addEventListener('click', () => deleteSavedCipher(row.id));
          container.appendChild(item);
        }
      } catch (e) {
        container.innerHTML = '<div class="saved-empty">could not load saved messages</div>';
      }
    }

    function loadSavedCipher(ciphertext) {
      setMode('decrypt');
      $('input').value = ciphertext;
      flash('loaded — enter your secret and decrypt');
    }

    async function deleteSavedCipher(id) {
      try {
        const { error } = await supabaseClient.from('saved_ciphers').delete().eq('id', id);
        if (error) throw error;
        await loadSavedList();
      } catch (e) {
        flashErr('could not delete: ' + (e.message || 'unknown error'));
      }
    }