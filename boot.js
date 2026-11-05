/* boot.js — VULNERATOR-AI terminal boot sequence + ambient audio
 * Unholy Pentest Division · 2026
 *
 * SFX policy:
 *   • Sequence auto-starts immediately (no standby screen)
 *   • First mousedown on the boot screen → Web Audio init + fan + POST beep
 *   • Subsequent typewriter chars get clicks; each [OK] gets a disk-seek sound
 *   • If never clicked → sequence plays silently; music still starts on dismiss
 *
 * After dismiss:
 *   • TV-off animation → hero image distortion system activates (same glitch
 *     family as the boot screen: displacement filter + noise canvas)
 */
(() => {
  'use strict';

  // Skip boot entirely for search engine crawlers — preserves SEO/LCP
  if (/bot|crawl|spider|google|bing|slurp|duckduck|baidu|yandex/i.test(navigator.userAgent)) {
    const b = document.getElementById('boot');
    if (b) b.style.display = 'none';
    document.body.style.overflow = '';
    if (window.initPostBoot) window.initPostBoot(document.getElementById('site-audio'));
    return;
  }

  /* ── Boot lines ──────────────────────────────────────────────── */
  const LINES = [
    // ── Hardware ─────────────────────────────────────────────────
    { t: 'VULNERATOR-AI SYSTEMS  ·  BIOS v2.04.1',                   c: 'd', p: 20  },
    { t: 'POST: RAM SCAN ████████████████████ 65536 KB — CLEAN',      c: 'd', p: 40  },
    { t: '',                                                                   p: 50  },
    // ── Threat detection ─────────────────────────────────────────
    { t: '⚠  INTRUSION DETECTED  ·  SRC 172.16.8.14:4444',                   p: 120 },
    { t: '   COUNTERMEASURES: ACTIVE',                                         p: 40  },
    { t: '   ORIGIN TRACE: REDIRECTED → /dev/null',           ok: true,       p: 140 },
    { t: '',                                                                   p: 40  },
    // ── Core modules ─────────────────────────────────────────────
    { t: '▸ Mounting encrypted volumes',               ok: true,              p: 80  },
    { t: '▸ Loading kernel modules',                   ok: true,              p: 60  },
    { t: '▸ Initialising network stack',               ok: true,              p: 80  },
    { t: '',                                                                   p: 40  },
    { t: '▸ Establishing secure tunnel',                                       p: 30  },
    { t: '  ├─ TLS 1.3 handshake',                     ok: true,              p: 40  },
    { t: '  ├─ Certificate validation',                 ok: true,              p: 30  },
    { t: '  └─ AES-256-GCM channel encrypted',         ok: true,              p: 120 },
    { t: '',                                                                   p: 40  },
    { t: '▸ Loading VULNERATOR-AI core',                                       p: 30  },
    { t: '  ├─ OODA engine  ·  Mistral Large 4.0',     ok: true,              p: 60  },
    { t: '  ├─ kali-mcp  →  Kali container',           ok: true,              p: 140 },
    { t: '  ├─ playwright-mcp  →  Chromium',           ok: true,              p: 90  },
    { t: '  ├─ caido  →  web-security toolkit',        ok: true,              p: 90  },
    { t: '  └─ Hermes LLM  →  online',                 ok: true,              p: 200 },
    { t: '',                                                                   p: 60  },
    // ── Authorization ────────────────────────────────────────────
    { t: '  SCOPE · AUTHORIZED TARGETS ONLY',                                 p: 40  },
    { t: '  OPERATOR CLEARANCE  ·  ████████████  ·  VERIFIED', ok: true,      p: 140 },
    { t: '',                                                                   p: 80  },
    // ── Armed ────────────────────────────────────────────────────
    { t: '  ██  TARGET ACQUIRED  ·  KALI UNLEASHED  ██',       c: 'h', p: 120 },
    { t: '',                                                                   p: 60  },
  ];

  const CHAR_MS = 5;

  /* ── DOM refs ─────────────────────────────────────────────────── */
  const boot   = document.getElementById('boot');
  const out    = document.getElementById('boot-output');
  const prompt = document.getElementById('boot-prompt');
  const audio  = document.getElementById('site-audio');
  const mute   = document.getElementById('audio-mute');
  const ctrl   = document.getElementById('audio-ctrl');
  const btTurb = document.getElementById('bt-turb');
  const btDisp = document.getElementById('bt-disp');

  // Inject CRT sweep line into the screen area
  const sweep = document.createElement('div');
  sweep.className = 'crt-sweep';
  document.querySelector('.boot__inner').prepend(sweep);

  let dismissed = false;
  let dispRaf   = null;

  /* ═══════════════════════════════════════════════════════════════
     AUDIO ENGINE — Web Audio API, synthesised procedurally
  ═══════════════════════════════════════════════════════════════ */
  const sfx = (() => {
    let ctx    = null;
    let active = false;

    function init() {
      if (ctx) return;
      try { ctx = new (window.AudioContext || window.webkitAudioContext)(); active = true; }
      catch (e) { active = false; return; }

      // Try to start immediately — works if browser has already granted activation
      ctx.resume().catch(() => {});

      // Fall back: resume on the very first interaction (mousemove counts)
      const resume = () => ctx.resume().catch(() => {});
      ['pointerdown', 'pointermove', 'keydown', 'touchstart'].forEach(evt =>
        document.addEventListener(evt, resume, { once: true, passive: true })
      );
    }

    function noise(dur) {
      const n   = Math.ceil(ctx.sampleRate * dur);
      const buf = ctx.createBuffer(1, n, ctx.sampleRate);
      const d   = buf.getChannelData(0);
      for (let i = 0; i < n; i++) d[i] = Math.random() * 2 - 1;
      return buf;
    }

    return {
      init,
      isActive() { return active; },

      fanSpinUp() {
        if (!active) return;
        const dur = 1.9, src = ctx.createBufferSource();
        src.buffer = noise(dur);
        const lp = ctx.createBiquadFilter();
        lp.type = 'lowpass';
        lp.frequency.setValueAtTime(70, ctx.currentTime);
        lp.frequency.exponentialRampToValueAtTime(1600, ctx.currentTime + dur * 0.55);
        lp.frequency.linearRampToValueAtTime(1300, ctx.currentTime + dur);
        const hp = ctx.createBiquadFilter();
        hp.type = 'highpass'; hp.frequency.value = 55;
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.001, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.16, ctx.currentTime + 0.6);
        g.gain.linearRampToValueAtTime(0.09, ctx.currentTime + dur);
        src.connect(lp); lp.connect(hp); hp.connect(g); g.connect(ctx.destination);
        src.start();
      },

      postBeep() {
        if (!active) return;
        const osc = ctx.createOscillator(), g = ctx.createGain();
        osc.type = 'square'; osc.frequency.value = 880;
        g.gain.setValueAtTime(0.06, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.065);
        osc.connect(g); g.connect(ctx.destination);
        osc.start(); osc.stop(ctx.currentTime + 0.065);
      },

      typeClick() {
        if (!active) return;
        const dur = 0.022, src = ctx.createBufferSource();
        src.buffer = noise(dur);
        const f = ctx.createBiquadFilter();
        f.type = 'bandpass'; f.frequency.value = 3400; f.Q.value = 1.0;
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.030, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
        src.connect(f); f.connect(g); g.connect(ctx.destination);
        src.start();
      },

      diskSeek() {
        if (!active) return;
        const dur = 0.08, src = ctx.createBufferSource();
        src.buffer = noise(dur);
        const f = ctx.createBiquadFilter();
        f.type = 'bandpass';
        f.frequency.setValueAtTime(300, ctx.currentTime);
        f.frequency.exponentialRampToValueAtTime(3800, ctx.currentTime + dur * 0.3);
        f.frequency.exponentialRampToValueAtTime(420,  ctx.currentTime + dur);
        f.Q.value = 2.8;
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.16, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
        src.connect(f); f.connect(g); g.connect(ctx.destination);
        src.start();
      },

      readyChime() {
        if (!active) return;
        [[440, 0, 0.09], [880, 0.14, 0.07]].forEach(([freq, delay, vol]) => {
          const osc = ctx.createOscillator(), g = ctx.createGain();
          osc.type = 'sine'; osc.frequency.value = freq;
          g.gain.setValueAtTime(0, ctx.currentTime + delay);
          g.gain.linearRampToValueAtTime(vol, ctx.currentTime + delay + 0.01);
          g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + delay + 0.18);
          osc.connect(g); g.connect(ctx.destination);
          osc.start(ctx.currentTime + delay);
          osc.stop(ctx.currentTime + delay + 0.2);
        });
      },
    };
  })();

  /* ═══════════════════════════════════════════════════════════════
     NOISE CANVAS — TV static on the boot screen
  ═══════════════════════════════════════════════════════════════ */
  const nc   = document.createElement('canvas');
  nc.className = 'boot__noise';
  nc.width = 220; nc.height = 165;
  boot.appendChild(nc);
  const nctx = nc.getContext('2d');
  let noiseI = 0.030, noiseO = 0.06, _lastNoise = 0;

  (function noiseLoop(ts) {
    if (dismissed) return;
    requestAnimationFrame(noiseLoop);
    if (ts - _lastNoise < 28) return;
    _lastNoise = ts;
    const img = nctx.createImageData(220, 165);
    const d = img.data;
    for (let i = 0; i < d.length; i += 4) {
      if (Math.random() < noiseI) {
        const v = (Math.random() * 180 + 75) | 0;
        d[i] = v; d[i+1] = v; d[i+2] = v;
        d[i+3] = (Math.random() * 160 + 60) | 0;
      }
    }
    nctx.putImageData(img, 0, 0);
    nc.style.opacity = noiseO;
  })(0);

  /* ═══════════════════════════════════════════════════════════════
     SVG DISPLACEMENT — boot screen
  ═══════════════════════════════════════════════════════════════ */
  function animateDisp(duration, maxScale) {
    if (!btDisp || !btTurb) return;
    cancelAnimationFrame(dispRaf);
    const t0 = performance.now();
    (function frame(now) {
      const dt = now - t0;
      if (dt >= duration) { btDisp.setAttribute('scale', '0'); return; }
      const env = Math.pow(Math.sin((dt / duration) * Math.PI), 0.65);
      btDisp.setAttribute('scale', (maxScale * env * (0.78 + Math.random() * 0.44)).toFixed(1));
      btTurb.setAttribute('seed', (Math.random() * 999 | 0));
      dispRaf = requestAnimationFrame(frame);
    })(t0);
  }

  /* ═══════════════════════════════════════════════════════════════
     FLASH OVERLAY
  ═══════════════════════════════════════════════════════════════ */
  function flashOverlay(steps) {
    const fl = document.createElement('div');
    fl.style.cssText = 'position:absolute;inset:0;z-index:15;pointer-events:none;';
    boot.appendChild(fl);
    const total = steps[steps.length - 1][1] + 80;
    steps.forEach(([c, d]) => setTimeout(() => { fl.style.background = c; }, d));
    setTimeout(() => fl.remove(), total);
  }

  /* ═══════════════════════════════════════════════════════════════
     GLITCH TIERS — boot screen
  ═══════════════════════════════════════════════════════════════ */
  function glitchMinor() {
    boot.classList.add('boot--chroma');
    animateDisp(220, 11);
    setTimeout(() => boot.classList.remove('boot--chroma'), 240);
  }
  function glitchMajor() {
    noiseI = 0.22; noiseO = 0.30;
    boot.classList.add('boot--chroma', 'boot--flicker', 'boot--jitter');
    animateDisp(500, 32);
    setTimeout(() => boot.classList.remove('boot--flicker', 'boot--jitter'), 220);
    setTimeout(() => { noiseI = 0.030; noiseO = 0.06; boot.classList.remove('boot--chroma'); }, 480);
  }
  function glitchCatastrophic() {
    noiseI = 0.55; noiseO = 0.60;
    boot.classList.add('boot--chroma', 'boot--flicker', 'boot--jitter');
    animateDisp(750, 56);
    flashOverlay([
      ['rgba(210,210,210,0.18)',   0],
      ['rgba(255,255,255,0.65)',  55],
      ['rgba(200,0,0,0.32)',     120],
      ['rgba(255,255,255,0.52)', 180],
      ['rgba(0,60,200,0.22)',    250],
      ['rgba(255,255,255,0.38)', 320],
      ['transparent',            400],
    ]);
    setTimeout(() => { noiseI = 0.30; noiseO = 0.38; boot.classList.remove('boot--flicker', 'boot--jitter'); }, 260);
    setTimeout(() => { noiseI = 0.10; noiseO = 0.14; }, 480);
    setTimeout(() => { noiseI = 0.030; noiseO = 0.06; boot.classList.remove('boot--chroma'); }, 720);
  }

  (function sched() {
    if (dismissed) return;
    const r = Math.random();
    let fn, delay;
    if (r < 0.50)      { fn = glitchMinor;       delay = 1600 + Math.random() * 2400; }
    else if (r < 0.85) { fn = glitchMajor;        delay = 2800 + Math.random() * 4200; }
    else               { fn = glitchCatastrophic; delay = 5000 + Math.random() * 9000; }
    setTimeout(() => { if (!dismissed) { fn(); sched(); } }, delay);
  })();

  /* ═══════════════════════════════════════════════════════════════
     TYPEWRITER — with SFX integration
  ═══════════════════════════════════════════════════════════════ */
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let typeCounter = 0;

  async function typeLine(text, cls, showOk) {
    const el = document.createElement('div');
    el.className = 'bl' + (cls ? ' bl--' + cls : '') + ' bl--new bl--typing';
    out.appendChild(el);
    el.scrollIntoView({ block: 'nearest' });
    setTimeout(() => el.classList.remove('bl--new'), 120);

    let clickAt = 3 + Math.floor(Math.random() * 3);
    for (let i = 0; i <= text.length; i++) {
      if (dismissed) { el.textContent = text; break; }
      el.textContent = text.slice(0, i);
      if (++typeCounter % clickAt === 0) {
        sfx.typeClick();
        clickAt = 3 + Math.floor(Math.random() * 3);
      }
      await sleep(CHAR_MS + Math.random() * 8 - 4);
    }

    el.classList.remove('bl--typing');

    if (showOk) {
      const sp = document.createElement('span');
      sp.style.cssText = 'color:#5ab870;margin-left:0.4em';
      el.appendChild(sp);

      // Spinner frames
      const FRAMES = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
      let fi = 0;
      sp.textContent = FRAMES[0];
      const spin = setInterval(() => { sp.textContent = FRAMES[fi++ % FRAMES.length]; }, 55);

      await sleep(380 + Math.random() * 340);
      clearInterval(spin);
      sp.textContent = '[OK]';
      sp.className = 'bl__ok';
      sfx.diskSeek();
    }

    el.scrollIntoView({ block: 'nearest' });
    if (cls === 'h') setTimeout(() => sfx.readyChime(), 100);
  }

  async function runBoot() {
    // Init audio immediately — tries ctx.resume() + adds broad interaction listeners
    // so sounds start as soon as the user moves the mouse, presses a key, etc.
    sfx.init();
    sfx.fanSpinUp();
    setTimeout(() => sfx.postBeep(), 520);

    for (const line of LINES) {
      await sleep(line.p ?? 60);
      if (dismissed) break;
      if (!line.t) {
        const sp = document.createElement('div');
        sp.className = 'bl bl--sp';
        out.appendChild(sp);
      } else {
        await typeLine(line.t, line.c, line.ok);
      }
    }
    showPrompt();
  }

  function showPrompt() {
    // Blinking cursor on last text line
    const lines = out.querySelectorAll('.bl');
    const last = lines[lines.length - 1];
    if (last) last.classList.add('bl--cursor');

    prompt.style.display = 'block';
    prompt.scrollIntoView({ block: 'nearest' });
  }

  /* ═══════════════════════════════════════════════════════════════
     HERO DISTORTION — same glitch family, applied to the hero
     background image after the boot screen dismisses.
  ═══════════════════════════════════════════════════════════════ */
  function initHeroGlitch() {
    const heroEl  = document.querySelector('.hero');
    const heroBg  = document.querySelector('.hero__bg');
    if (!heroEl || !heroBg) return;

    const hgTurb = document.getElementById('hg-turb');
    const hgDisp = document.getElementById('hg-disp');

    /* Apply SVG displacement filter to the background image */
    heroBg.style.filter = 'url(#hero-glitch-filter)';

    /* Noise canvas — inserted between overlay and content */
    const hnc = document.createElement('canvas');
    hnc.className = 'hero__noise';
    hnc.width = 220; hnc.height = 165;
    const heroContent = heroEl.querySelector('.hero__content');
    heroEl.insertBefore(hnc, heroContent);
    const hnctx = hnc.getContext('2d');

    let hni = 0, hno = 0, _hLast = 0;

    (function hNoiseLoop(ts) {
      requestAnimationFrame(hNoiseLoop);
      if (ts - _hLast < 28) return;
      _hLast = ts;
      if (hni < 0.002) { hnc.style.opacity = 0; return; }
      const img = hnctx.createImageData(220, 165);
      const d = img.data;
      for (let i = 0; i < d.length; i += 4) {
        if (Math.random() < hni) {
          const v = (Math.random() * 180 + 75) | 0;
          d[i] = v; d[i+1] = v; d[i+2] = v;
          d[i+3] = (Math.random() * 160 + 60) | 0;
        }
      }
      hnctx.putImageData(img, 0, 0);
      hnc.style.opacity = hno;
    })(0);

    /* SVG displacement animation for the hero */
    let hRaf = null;
    function hAnimateDisp(duration, maxScale) {
      if (!hgDisp || !hgTurb) return;
      cancelAnimationFrame(hRaf);
      const t0 = performance.now();
      (function frame(now) {
        const dt = now - t0;
        if (dt >= duration) { hgDisp.setAttribute('scale', '0'); return; }
        const env = Math.pow(Math.sin((dt / duration) * Math.PI), 0.65);
        hgDisp.setAttribute('scale', (maxScale * env * (0.78 + Math.random() * 0.44)).toFixed(1));
        hgTurb.setAttribute('seed', (Math.random() * 999 | 0));
        hRaf = requestAnimationFrame(frame);
      })(t0);
    }

    /* Hero glitch tiers — slightly less frequent than boot screen */
    function hGlitchMinor() {
      heroEl.classList.add('hero--chroma');
      hAnimateDisp(280, 14);
      setTimeout(() => heroEl.classList.remove('hero--chroma'), 300);
    }
    function hGlitchMajor() {
      hni = 0.25; hno = 0.32;
      heroEl.classList.add('hero--chroma', 'hero--flicker');
      hAnimateDisp(560, 36);
      setTimeout(() => heroEl.classList.remove('hero--flicker'), 240);
      setTimeout(() => { hni = 0; hno = 0; heroEl.classList.remove('hero--chroma'); }, 540);
    }
    function hGlitchCatastrophic() {
      hni = 0.52; hno = 0.58;
      heroEl.classList.add('hero--chroma', 'hero--flicker');
      hAnimateDisp(760, 55);
      setTimeout(() => { hni = 0.22; hno = 0.28; heroEl.classList.remove('hero--flicker'); }, 280);
      setTimeout(() => { hni = 0.06; hno = 0.08; }, 480);
      setTimeout(() => { hni = 0; hno = 0; heroEl.classList.remove('hero--chroma'); }, 720);
    }

    (function hSched() {
      const r = Math.random();
      let fn, delay;
      if (r < 0.50)      { fn = hGlitchMinor;       delay = 3500 + Math.random() * 5000; }
      else if (r < 0.85) { fn = hGlitchMajor;        delay = 5000 + Math.random() * 7000; }
      else               { fn = hGlitchCatastrophic; delay = 9000 + Math.random() * 14000; }
      setTimeout(() => { fn(); hSched(); }, delay);
    })();
  }

  /* ═══════════════════════════════════════════════════════════════
     SYSTEM STATUS BAR
  ═══════════════════════════════════════════════════════════════ */
  function initSysBar() {
    const ITEMS = [
      'OODA-LOOP: ACTIVE', 'HERMES-LLM: ONLINE',
      'KALI-MCP ▸ :8900', 'PLAYWRIGHT ▸ :8931', 'CAIDO ▸ :8080',
      'ENC: AES-256-GCM', 'TLS: 1.3',
      '0xDEADBEEF', '0xCAFEBABE', '0x48455246',
      'TUNNEL: ACTIVE', 'FINDINGS: CLASSIFIED', 'TARGET: CONFIRMED',
      '<span id="sysbar-uptime">UPTIME: 00:00:00</span>',
    ];
    const bar   = document.createElement('div');
    bar.id = 'sys-bar'; bar.setAttribute('aria-hidden', 'true');
    const track = document.createElement('div');
    track.id = 'sys-bar-track';
    const html = ITEMS.map(t => `<span class="si">${t}</span><span class="si__sep">◆</span>`).join('');
    track.innerHTML = html + html;
    bar.appendChild(track);
    document.body.prepend(bar);
    document.body.classList.add('has-sysbar');

    let sec = 0;
    setInterval(() => {
      sec++;
      const ut = document.getElementById('sysbar-uptime');
      if (!ut) return;
      ut.textContent = `UPTIME: ${
        String(Math.floor(sec / 3600)).padStart(2,'0')}:${
        String(Math.floor((sec % 3600) / 60)).padStart(2,'0')}:${
        String(sec % 60).padStart(2,'0')}`;
    }, 1000);

    (function barGlitch() {
      setTimeout(() => {
        const spans = track.querySelectorAll('.si');
        if (spans.length) {
          const idx = Math.floor(Math.random() * spans.length);
          spans[idx].classList.add('si--g');
          setTimeout(() => spans[idx].classList.remove('si--g'), 220);
        }
        barGlitch();
      }, 2000 + Math.random() * 3800);
    })();

    requestAnimationFrame(() => bar.classList.add('sys-bar--on'));
  }

  /* ═══════════════════════════════════════════════════════════════
     MUTE BUTTON
  ═══════════════════════════════════════════════════════════════ */
  const ICON_SPK  = `<svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>`;
  const ICON_MUTE = `<svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true"><path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/></svg>`;

  function updateMuteUI() {
    if (!mute || !audio) return;
    const m = audio.muted;
    mute.innerHTML = m ? ICON_MUTE : ICON_SPK;
    mute.setAttribute('aria-label', m ? 'Unmute audio' : 'Mute audio');
    mute.classList.toggle('muted', m);
  }
  if (mute && audio) mute.addEventListener('click', () => { audio.muted = !audio.muted; updateMuteUI(); });

  /* ═══════════════════════════════════════════════════════════════
     DISMISS
  ═══════════════════════════════════════════════════════════════ */
  function dismiss() {
    if (dismissed) return;
    dismissed = true;
    cancelAnimationFrame(dispRaf);

    if (audio) { audio.volume = 0.4; audio.play().catch(() => {}); }
    if (ctrl)  { ctrl.style.display = 'flex'; updateMuteUI(); }

    initSysBar();
    initHeroGlitch();
    if (window.initPostBoot) window.initPostBoot(audio);

    boot.classList.add('boot--exit');
    boot.addEventListener('animationend', () => {
      boot.remove();
      document.body.style.overflow = '';
    }, { once: true });
  }

  /* ── Wire events + start ─────────────────────────────────────── */
  boot.addEventListener('click', dismiss);
  window.addEventListener('keydown', function h(e) {
    if (['Enter', ' ', 'Escape'].includes(e.key)) {
      window.removeEventListener('keydown', h); dismiss();
    }
  });

  document.body.style.overflow = 'hidden';
  runBoot();
})();
