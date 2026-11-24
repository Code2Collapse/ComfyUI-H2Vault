// H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-24, PART 3 "preview system", L9.342): the vault's image viewer,
// video player and large view (lightbox). DOM only; every number comes from the pure ./_h2v_player_core.js.
//
// Video player - how it works:
//  * The <video> element streams the output file by URL (core's /view answers HTTP range requests): the file is never
//    read into memory by script. No `controls` attribute: the controls below are the player.
//  * Frame stepping uses the clip's own frame rate: Video Helper Suite reports it (`frame_rate`); otherwise it is
//    measured while the clip plays with requestVideoFrameCallback (presented frames vs media time), and until then
//    30 fps is assumed and said so on screen. A step seeks to the MIDDLE of the target frame (a seek to an exact
//    boundary can show the previous frame).
//  * Reverse playback: native negative playbackRate is not supported by Chrome or Firefox, so the element stays paused
//    and a requestAnimationFrame loop seeks backwards one frame position at a time (reverseTarget: wall clock since the
//    anchor x speed, snapped to a frame). Only one seek is in flight: a tick is skipped while the element is still
//    seeking, so slow decoders drop frames instead of queueing seeks. Looping wraps to the end.
//  * One seek in flight for the seek bar too: a pending target is applied on `seeked`.
//  * destroy() pauses, stops every loop / callback, removes the source and calls load() so the browser releases the
//    stream and the decoder.
import {
  FPS_FALLBACK, SPEEDS, centered, clampTime, estimateFps, fitScale, formatTime, frameAt, frameCount, reverseTarget,
  stepFrame, zoomAt,
} from "./_h2v_player_core.js";
import { playability } from "./_h2v_previews_core.js";

const CSS_ID = "h2v-player-css";

function el(tag, attrs = {}, kids = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null) continue;
    if (k === "text") e.textContent = v;
    else if (k === "style") Object.assign(e.style, v);
    else e.setAttribute(k, v);
  }
  for (const c of kids) if (c) e.append(c);
  return e;
}

// symbols as text, not as coloured emoji (variation selector 15 after arrows / media symbols)
const glyph = (s) => String(s).replace(/([←-⯿])(?!︎)/gu, "$1︎");

function btn(text, label, onClick, { toggle = false } = {}) {
  const b = el("button", { type: "button", class: "h2v-pl__btn", "aria-label": label, title: label, text: glyph(text) });
  if (toggle) b.setAttribute("aria-pressed", "false");
  b.addEventListener("click", (e) => { e.stopPropagation(); onClick(e); });
  return b;
}

const press = (b, on) => b.setAttribute("aria-pressed", on ? "true" : "false");
const stop = (e) => e.stopPropagation();

export function ensurePlayerStyles() {
  if (document.getElementById(CSS_ID)) return;
  const css = `
.h2v-pl{box-sizing:border-box;width:100%;color:var(--input-text,#ddd);font:12px/1.35 system-ui,sans-serif}
.h2v-pl *{box-sizing:border-box}
.h2v-pl__btn{min-width:26px;height:26px;padding:0 6px;border-radius:6px;border:1px solid var(--border-color,#444);
  background:var(--comfy-menu-bg,#2a2a30);color:inherit;font:inherit;cursor:pointer;line-height:1}
.h2v-pl__btn:hover{background:rgba(127,127,127,.25)}
.h2v-pl__btn[aria-pressed="true"]{background:rgba(80,140,255,.35);border-color:rgba(120,170,255,.8)}
.h2v-pl__btn:disabled{opacity:.45;cursor:default}
.h2v-pl :focus-visible{outline:2px solid #6aa0ff;outline-offset:1px}
.h2v-pl__bar{display:flex;flex-wrap:wrap;align-items:center;gap:4px;margin-top:4px}
.h2v-pl__sp{flex:1 1 auto}
.h2v-pl__ro{opacity:.85;white-space:nowrap;font-variant-numeric:tabular-nums}
.h2v-pl__dim{opacity:.6}
.h2v-pl__stage{position:relative;width:100%;background:#000;border-radius:6px;overflow:hidden}
.h2v-pl__stage video{display:block;width:100%;height:100%;object-fit:contain;background:#000}
.h2v-pl__over{position:absolute;inset:0;display:flex;flex-direction:column;gap:6px;align-items:center;justify-content:center;padding:10px;
  text-align:center;background:rgba(0,0,0,.55);color:#eee;pointer-events:none}
.h2v-pl__over[hidden]{display:none}
.h2v-pl__over a{pointer-events:auto;color:#9cc2ff}
.h2v-pl__warn{margin-top:3px;color:#f0c060}
.h2v-pl__seek{width:100%;margin:4px 0 0;accent-color:#6aa0ff}
.h2v-pl__vol{width:64px;accent-color:#6aa0ff}
.h2v-pl select{height:26px;border-radius:6px;background:var(--comfy-menu-bg,#2a2a30);color:inherit;
  border:1px solid var(--border-color,#444);font:inherit}
.h2v-pl--fs{background:#000;display:flex;flex-direction:column;padding:8px}
.h2v-pl--fs .h2v-pl__stage{flex:1 1 auto;height:auto!important}
.h2v-pl__img{position:relative;width:100%;background:#000;border-radius:6px;overflow:hidden;cursor:grab;
  touch-action:none}
.h2v-pl__img.is-drag{cursor:grabbing}
.h2v-pl__img img{position:absolute;left:0;top:0;transform-origin:0 0;max-width:none;max-height:none;
  user-select:none;-webkit-user-drag:none}
.h2v-pl__badge{padding:1px 6px;border-radius:999px;background:rgba(80,140,255,.3)}
.h2v-lb{position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.88);display:flex;flex-direction:column;
  padding:12px 16px;color:#eee;font:13px/1.4 system-ui,sans-serif}
.h2v-lb__head{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.h2v-lb__title{flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.h2v-lb__body{flex:1 1 auto;min-height:0}`;
  document.head.append(el("style", { id: CSS_ID, text: css }));
}

// ── image viewer ───────────────────────────────────────────────────────────────────────────────────────────────
/** {el, destroy()} - an image with fit / 1:1 / zoom (buttons, keys, wheel when focused) and drag to pan. */
export function createImageViewer(entry, { height = 300, onLarge = null, original = true } = {}) {
  ensurePlayerStyles();
  const img = el("img", { alt: entry.label || "Preview image", draggable: "false" });
  const box = el("div", { class: "h2v-pl__img", tabindex: "0", role: "img", "data-capture-wheel": "true",
    "aria-label": `${entry.label || "Preview"} - image. Plus and minus zoom, 0 fits, arrows pan.`,
    style: { height: `${height}px` } }, [img]);
  const over = el("div", { class: "h2v-pl__over", text: "Loading image..." });
  box.append(over);
  const zoomTxt = el("span", { class: "h2v-pl__ro", text: "" });
  const sizeTxt = el("span", { class: "h2v-pl__ro h2v-pl__dim", text: "" });
  let view = { scale: 1, x: 0, y: 0 }, userZoom = false, nw = 0, nh = 0;

  const apply = () => {
    img.style.transform = `translate(${view.x}px, ${view.y}px) scale(${view.scale})`;
    img.style.imageRendering = view.scale >= 3 ? "pixelated" : "auto";
    zoomTxt.textContent = `${Math.round(view.scale * 100)}%`;
  };
  const dims = () => [box.clientWidth || 1, box.clientHeight || height];
  const fit = () => {
    const [bw, bh] = dims();
    view = centered(nw, nh, bw, bh, fitScale(nw, nh, bw, bh));
    userZoom = false;
    apply();
  };
  const actual = () => {
    const [bw, bh] = dims();
    view = centered(nw, nh, bw, bh, 1);
    userZoom = true;
    apply();
  };
  const zoomBy = (f, px, py) => {
    const [bw, bh] = dims();
    view = zoomAt(view, f, px ?? bw / 2, py ?? bh / 2);
    userZoom = true;
    apply();
  };
  img.addEventListener("load", () => {
    nw = img.naturalWidth; nh = img.naturalHeight;
    sizeTxt.textContent = `${nw} x ${nh}`;
    over.hidden = true;
    fit();
  });
  img.addEventListener("error", () => {
    over.hidden = false;
    over.textContent = "This image could not be loaded.";
  });
  img.src = entry.url;

  const onWheel = (e) => {
    if (document.activeElement !== box && !e.ctrlKey) return;      // a wheel passing over the node still zooms the canvas
    e.preventDefault();
    e.stopPropagation();
    const r = box.getBoundingClientRect();
    zoomBy(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
  };
  box.addEventListener("wheel", onWheel, { passive: false });
  let drag = null;
  box.addEventListener("pointerdown", (e) => {
    e.stopPropagation();
    box.focus({ preventScroll: true });
    if (e.button !== 0) return;
    drag = { id: e.pointerId, x: e.clientX - view.x, y: e.clientY - view.y };
    box.setPointerCapture?.(e.pointerId);
    box.classList.add("is-drag");
  });
  box.addEventListener("pointermove", (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    view = { ...view, x: e.clientX - drag.x, y: e.clientY - drag.y };
    userZoom = true;
    apply();
  });
  const endDrag = (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    drag = null;
    box.classList.remove("is-drag");
  };
  box.addEventListener("pointerup", endDrag);
  box.addEventListener("pointercancel", endDrag);
  box.addEventListener("dblclick", (e) => { e.stopPropagation(); if (userZoom) fit(); else actual(); });
  box.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;              // browser / app shortcuts stay theirs
    const k = e.key;
    let done = true;
    if (k === "+" || k === "=") zoomBy(1.25);
    else if (k === "-" || k === "_") zoomBy(1 / 1.25);
    else if (k === "0") fit();
    else if (k === "1") actual();
    else if (k === "ArrowLeft") { view = { ...view, x: view.x + 40 }; userZoom = true; apply(); }
    else if (k === "ArrowRight") { view = { ...view, x: view.x - 40 }; userZoom = true; apply(); }
    else if (k === "ArrowUp") { view = { ...view, y: view.y + 40 }; userZoom = true; apply(); }
    else if (k === "ArrowDown") { view = { ...view, y: view.y - 40 }; userZoom = true; apply(); }
    else done = false;
    if (done) { e.preventDefault(); e.stopPropagation(); }
  });
  let ro = null;
  if (typeof ResizeObserver === "function") {
    ro = new ResizeObserver(() => { if (nw && !userZoom) fit(); });
    ro.observe(box);
  }

  const bar = el("div", { class: "h2v-pl__bar" }, [
    btn("Fit", "Fit the image to the view", fit),
    btn("1:1", "Actual size (one image pixel per screen pixel)", actual),
    btn("−", "Zoom out", () => zoomBy(1 / 1.25)),
    btn("+", "Zoom in", () => zoomBy(1.25)),
    zoomTxt, sizeTxt,
    entry.animated ? el("span", { class: "h2v-pl__badge", text: "animated" }) : null,
    el("span", { class: "h2v-pl__sp" }),
    onLarge ? btn("⤢ Large view", "Open a large view", () => onLarge()) : null,
    original && entry.url && !String(entry.url).startsWith("blob:")
      ? el("a", { class: "h2v-pl__btn", href: entry.url, target: "_blank", rel: "noopener noreferrer",
        title: "Open the original file in a new tab", "aria-label": "Open the original file in a new tab",
        style: { display: "inline-flex", alignItems: "center", textDecoration: "none" }, text: "Original" })
      : null,
  ]);
  const root = el("div", { class: "h2v-pl" }, [box, bar]);
  for (const ev of ["pointerdown", "mousedown"]) bar.addEventListener(ev, stop);
  return {
    el: root,
    fit,
    destroy() {
      ro?.disconnect();
      img.removeAttribute("src");
      root.remove();
    },
  };
}

// ── video player ───────────────────────────────────────────────────────────────────────────────────────────────
function errorText(code, entry) {
  const what = entry.format || entry.mime || (String(entry.name || "").split(".").pop() || "unknown").toUpperCase();
  if (code === 4) return `This browser cannot play this video format (${what}). The file is in your output folder as ` +
    `${entry.name || "the saved file"}.`;
  if (code === 3) return "The video data could not be decoded (damaged file or a codec this browser does not support).";
  if (code === 2) return "The video could not be loaded (network error).";
  return "The video could not be played.";
}

const fileSafe = (s) => String(s || "preview").replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 40) || "preview";

/** {el, destroy(), snapshot()} - a real player for one video output. `state` = its saved state (createViewer). */
export function createVideoPlayer(entry, state, { height = 300, onInspect = null, onState = null } = {}) {
  ensurePlayerStyles();
  const st = { time: 0, paused: false, rate: 1, loop: true, muted: true, volume: 1, ...(state || {}) };
  const video = el("video", { preload: "metadata", playsinline: "" });
  video.playsInline = true;
  video.muted = !!st.muted;
  video.volume = Math.min(1, Math.max(0, Number(st.volume) || 0));
  video.loop = !!st.loop;
  const over = el("div", { class: "h2v-pl__over", role: "status", "aria-live": "polite", text: "Loading video..." });
  const stage = el("div", { class: "h2v-pl__stage", style: { height: `${height}px` } }, [video, over]);
  const warn = el("div", { class: "h2v-pl__warn", hidden: "" });

  let fps = entry.fps || null, measured = false, samples = [], vfcId = null;
  let reverse = null, raf = 0, pendingSeek = null, destroyed = false, scrubbing = false;
  const curFps = () => fps || FPS_FALLBACK;
  const dur = () => video.duration;

  const seek = el("input", { type: "range", class: "h2v-pl__seek", min: "0", max: "0", step: "any", value: "0",
    "aria-label": "Seek" });
  const timeTxt = el("span", { class: "h2v-pl__ro", text: "0:00.00 / --:--" });
  const frameTxt = el("span", { class: "h2v-pl__ro", text: "Frame - / -" });
  const fpsTxt = el("span", { class: "h2v-pl__ro h2v-pl__dim", text: "" });

  const showFps = () => {
    fpsTxt.textContent = !fps ? `fps unknown, assuming ${FPS_FALLBACK}` : measured ? `~${fps} fps (measured)` : `${fps} fps`;
  };
  const refresh = () => {
    const t = video.currentTime, d = dur();
    if (!scrubbing) seek.value = String(t);
    seek.setAttribute("aria-valuetext", `${formatTime(t)} of ${formatTime(d)}`);
    timeTxt.textContent = `${formatTime(t)} / ${formatTime(d)}`;
    const n = frameCount(d, curFps());
    const shown = frameAt(t, curFps()) + 1;                      // at the very end t = duration: the last frame
    frameTxt.textContent = `Frame ${n ? Math.min(shown, n) : shown} / ${n ?? "?"}`;
    playBtn.textContent = glyph(video.paused || reverse ? "▶" : "❚❚");
    playBtn.setAttribute("aria-label", video.paused || reverse ? "Play" : "Pause");
    playBtn.title = playBtn.getAttribute("aria-label");
    press(revBtn, !!reverse);
    press(loopBtn, video.loop);
    press(muteBtn, video.muted);
    muteBtn.textContent = video.muted || video.volume === 0 ? "🔇" : "🔊";
    vol.value = String(video.muted ? 0 : video.volume);
  };
  const setTime = (t) => {
    const target = clampTime(t, dur());
    if (video.seeking) { pendingSeek = target; return; }
    pendingSeek = null;
    try { video.currentTime = target; } catch (_) { /* not seekable yet */ }
    refresh();
  };

  // reverse playback (see the header)
  const stopReverse = () => {
    if (!reverse) return;
    reverse = null;
    cancelAnimationFrame(raf);
    raf = 0;
    refresh();
  };
  const tick = () => {
    if (!reverse || destroyed) return;
    raf = requestAnimationFrame(tick);
    if (video.seeking) return;
    const r = reverseTarget({ ...reverse, now: performance.now(), speed: Number(speedSel.value) || 1, fps: curFps(),
      duration: dur(), loop: video.loop });
    if (r.wrapped) Object.assign(reverse, { anchorTime: r.time, anchorWall: performance.now() });
    if (frameAt(r.time, curFps()) !== frameAt(video.currentTime, curFps())) {
      try { video.currentTime = r.time; } catch (_) { /* ignore */ }
    }
    if (r.ended) stopReverse();
    refresh();
  };
  const startReverse = () => {
    video.pause();
    reverse = { anchorTime: video.currentTime > 0 ? video.currentTime : (Number.isFinite(dur()) ? dur() : 0),
      anchorWall: performance.now() };
    raf = requestAnimationFrame(tick);
    refresh();
  };

  const play = () => {
    stopReverse();
    if (Number.isFinite(dur()) && video.currentTime >= dur() - 1e-3 && !video.loop) setTime(0);
    const p = video.play();
    if (p && typeof p.catch === "function") {
      p.catch(() => {                                      // autoplay with sound refused: play muted
        if (!video.muted) { video.muted = true; video.play().catch(() => {}); refresh(); }
      });
    }
    watchFrames();
  };
  const pause = () => { stopReverse(); video.pause(); refresh(); };
  const toggle = () => (video.paused || reverse ? play() : pause());
  const step = (dir) => { pause(); setTime(stepFrame(video.currentTime, curFps(), dur(), dir)); };
  const jump = (sec) => { const was = reverse; stopReverse(); setTime(video.currentTime + sec); if (was) startReverse(); };

  // fps measurement while playing (requestVideoFrameCallback)
  function watchFrames() {
    if (fps && !measured && entry.fps) return;
    if (typeof video.requestVideoFrameCallback !== "function" || vfcId !== null || measured) return;
    const cb = (_now, meta) => {
      vfcId = null;
      if (destroyed) return;
      // only at normal speed: faster than the screen refreshes, frames are skipped and the rate would read too low
      if (video.playbackRate === 1) samples.push({ mediaTime: meta.mediaTime, presentedFrames: meta.presentedFrames });
      else samples = [];
      if (samples.length > 40) samples = samples.slice(-40);
      const f = estimateFps(samples);
      if (f && samples.length >= 12) { fps = f; measured = true; showFps(); refresh(); return; }
      if (!video.paused) vfcId = video.requestVideoFrameCallback(cb);
    };
    vfcId = video.requestVideoFrameCallback(cb);
  }

  const backBtn = btn("⏪", "Back 1 second (Shift+Left)", () => jump(-1));
  const prevBtn = btn("⏮", "Previous frame (Left or ,)", () => step(-1));
  const revBtn = btn("◀", "Play in reverse (J)", () => (reverse ? stopReverse() : startReverse()), { toggle: true });
  const playBtn = btn("▶", "Play", toggle);
  const nextBtn = btn("⏭", "Next frame (Right or .)", () => step(+1));
  const fwdBtn = btn("⏩", "Forward 1 second (Shift+Right)", () => jump(+1));
  const loopBtn = btn("⟳", "Loop (L)", () => { video.loop = !video.loop; refresh(); }, { toggle: true });
  const speedSel = el("select", { "aria-label": "Playback speed", title: "Playback speed" },
    SPEEDS.map((s) => el("option", { value: String(s), text: `${s}x` })));
  speedSel.value = String(SPEEDS.includes(Number(st.rate)) ? Number(st.rate) : 1);
  video.playbackRate = Number(speedSel.value);
  speedSel.addEventListener("change", () => {
    video.playbackRate = Number(speedSel.value);
    if (reverse) Object.assign(reverse, { anchorTime: video.currentTime, anchorWall: performance.now() });
  });
  const muteBtn = btn("🔇", "Mute (M)", () => { video.muted = !video.muted; if (!video.muted && video.volume === 0) video.volume = 1; refresh(); }, { toggle: true });
  const vol = el("input", { type: "range", class: "h2v-pl__vol", min: "0", max: "1", step: "0.05",
    "aria-label": "Volume", title: "Volume" });
  vol.addEventListener("input", () => { video.volume = Number(vol.value); video.muted = video.volume === 0; refresh(); });
  const grab = () => {
    if (!video.videoWidth) return null;
    const c = document.createElement("canvas");
    c.width = video.videoWidth; c.height = video.videoHeight;
    c.getContext("2d").drawImage(video, 0, 0);
    return c;
  };
  const frameNo = () => {
    const n = frameCount(dur(), curFps()), f = frameAt(video.currentTime, curFps()) + 1;
    return n ? Math.min(f, n) : f;
  };
  const inspectBtn = btn("🔍", "Inspect this frame in a large view", () => {
    pause();
    const c = grab();
    if (!c || !onInspect) return;
    // the large view lives on the page: it would open hidden behind a fullscreen player
    if (document.fullscreenElement === root) document.exitFullscreen?.()?.catch?.(() => {});
    const title = `${entry.label || "Video"} - frame ${frameNo()} at ${formatTime(video.currentTime)}`;
    c.toBlob((b) => { if (b) onInspect({ url: URL.createObjectURL(b), title, name: `frame_${frameNo()}.png`, revoke: true }); },
      "image/png");
  });
  const saveBtn = btn("⬇ Frame", "Save this frame as a PNG", () => {
    pause();
    const c = grab();
    if (!c) return;
    const n = frameNo();
    c.toBlob((b) => {
      if (!b) return;
      const url = URL.createObjectURL(b);
      const a = el("a", { href: url, download: `${fileSafe(entry.label)}_frame_${n}.png` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    }, "image/png");
  });
  const root = el("div", { class: "h2v-pl", tabindex: "0", role: "group", "aria-label": `Video player: ${entry.label}` });
  const fsBtn = btn("⛶", "Fullscreen (F)", () => {
    if (document.fullscreenElement === root) document.exitFullscreen?.();
    else (root.requestFullscreen?.() ?? root.webkitRequestFullscreen?.())?.catch?.(() => {});
  });
  const onFs = () => { root.classList.toggle("h2v-pl--fs", document.fullscreenElement === root); };
  document.addEventListener("fullscreenchange", onFs);

  // seek bar: live while dragging, one seek in flight
  seek.addEventListener("pointerdown", (e) => { e.stopPropagation(); scrubbing = true; stopReverse(); });
  seek.addEventListener("input", () => setTime(Number(seek.value)));
  const endScrub = () => { scrubbing = false; refresh(); };
  seek.addEventListener("pointerup", endScrub);
  seek.addEventListener("change", endScrub);

  const vListeners = {
    loadedmetadata: () => {
      seek.max = String(Number.isFinite(dur()) ? dur() : 0);
      if (st.time > 0) setTime(st.time);
      refresh();
    },
    loadeddata: () => { over.hidden = true; refresh(); },
    waiting: () => { if (!video.error) { over.hidden = false; over.textContent = "Buffering..."; } },
    playing: () => { over.hidden = true; watchFrames(); refresh(); },
    canplay: () => { if (!video.error) over.hidden = true; },
    seeked: () => {
      if (!video.error) over.hidden = true;
      if (pendingSeek !== null) { const t = pendingSeek; pendingSeek = null; setTime(t); }
      refresh();
    },
    timeupdate: refresh,
    pause: refresh,
    play: refresh,
    ratechange: refresh,
    volumechange: refresh,
    ended: refresh,
    error: () => {
      stopReverse();
      over.hidden = false;
      over.replaceChildren(el("span", { text: errorText(video.error?.code, entry) + " " }));
      if (entry.url) over.append(el("a", { href: entry.url, target: "_blank", rel: "noopener noreferrer", text: "Open the file" }));
    },
  };
  for (const [k, fn] of Object.entries(vListeners)) video.addEventListener(k, fn);

  if (entry.mime && playability(entry.mime, (m) => video.canPlayType(m)) === "no") {
    warn.hidden = false;
    warn.textContent = `Your browser reports it may not play ${entry.mime.split(";")[0]} files - trying anyway.`;
  }

  root.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;              // browser / app shortcuts stay theirs
    const k = e.key;
    const tag = e.target?.tagName;
    // the speed list and the volume slider keep their own keys; a focused button keeps Space / Enter (native click)
    if (e.target === speedSel || e.target === vol || (tag === "BUTTON" && (k === " " || k === "Enter"))) {
      e.stopPropagation();
      return;
    }
    let done = true;
    if (k === " " || k === "k" || k === "K") toggle();
    else if (k === "ArrowLeft" || k === ",") (e.shiftKey ? jump(-1) : step(-1));
    else if (k === "ArrowRight" || k === ".") (e.shiftKey ? jump(+1) : step(+1));
    else if (k === "j" || k === "J") (reverse ? stopReverse() : startReverse());
    else if (k === "Home") { stopReverse(); setTime(0); }
    else if (k === "End") { stopReverse(); setTime(Number.isFinite(dur()) ? dur() : video.currentTime); }
    else if (k === "m" || k === "M") muteBtn.click();
    else if (k === "l" || k === "L") loopBtn.click();
    else if (k === "f" || k === "F") fsBtn.click();
    else done = false;
    if (done) { e.preventDefault(); e.stopPropagation(); }
  });
  stage.addEventListener("click", (e) => { e.stopPropagation(); root.focus({ preventScroll: true }); toggle(); });
  for (const ev of ["pointerdown", "mousedown"]) root.addEventListener(ev, stop);

  root.append(stage, warn, seek,
    el("div", { class: "h2v-pl__bar" }, [backBtn, prevBtn, revBtn, playBtn, nextBtn, fwdBtn, timeTxt,
      el("span", { class: "h2v-pl__sp" }), frameTxt, fpsTxt]),
    el("div", { class: "h2v-pl__bar" }, [loopBtn, speedSel, muteBtn, vol, el("span", { class: "h2v-pl__sp" }),
      onInspect ? inspectBtn : null, saveBtn, fsBtn]));
  showFps();
  video.src = entry.url;
  refresh();
  if (!st.paused) play();

  const snapshot = () => ({ time: video.currentTime || 0, paused: video.paused || !!reverse,
    rate: Number(speedSel.value) || 1, loop: video.loop, muted: video.muted, volume: video.volume });
  return {
    el: root,
    video,
    snapshot,
    destroy() {
      if (destroyed) return;
      onState?.(snapshot());
      destroyed = true;
      stopReverse();
      if (vfcId !== null) { try { video.cancelVideoFrameCallback?.(vfcId); } catch (_) { /* ignore */ } }
      document.removeEventListener("fullscreenchange", onFs);
      if (document.fullscreenElement === root) document.exitFullscreen?.().catch?.(() => {});
      for (const [k, fn] of Object.entries(vListeners)) video.removeEventListener(k, fn);
      video.pause();
      video.removeAttribute("src");
      try { video.load(); } catch (_) { /* releases the stream / decoder */ }
      root.remove();
    },
  };
}

// ── large view ─────────────────────────────────────────────────────────────────────────────────────────────────
let OPEN = null;

/** A full-window view of one or several images. {close()}. Images with `revoke: true` are object URLs it owns. */
export function openLightbox({ title = "Preview", images = [], index = 0, onClose = null } = {}) {
  ensurePlayerStyles();
  OPEN?.close();
  const opener = document.activeElement;
  let i = Math.min(Math.max(0, index), Math.max(0, images.length - 1)), viewer = null;
  const head = el("div", { class: "h2v-lb__title" });
  const body = el("div", { class: "h2v-lb__body" });
  const count = el("span", { class: "h2v-pl__ro" });
  const prev = btn("‹", "Previous image (Left)", () => go(-1));
  const next = btn("›", "Next image (Right)", () => go(+1));
  const closeBtn = btn("✕ Close", "Close the large view (Escape)", () => close());
  const box = el("div", { class: "h2v-lb h2v-pl", role: "dialog", "aria-modal": "true", "aria-label": title }, [
    el("div", { class: "h2v-lb__head" }, [head, count, images.length > 1 ? prev : null, images.length > 1 ? next : null,
      closeBtn]), body]);
  const show = () => {
    viewer?.destroy();
    const im = images[i];
    head.textContent = im?.label ? `${title} - ${im.label}` : title;
    count.textContent = images.length > 1 ? `${i + 1} / ${images.length}` : "";
    viewer = im ? createImageViewer({ ...im, label: im.label || title }, {
      height: Math.max(200, window.innerHeight - 110), original: !im.revoke }) : null;
    if (viewer) body.replaceChildren(viewer.el);
  };
  const go = (d) => { if (images.length > 1) { i = (i + d + images.length) % images.length; show(); } };
  const onKey = (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === "ArrowLeft" && images.length > 1 && !e.target?.closest?.(".h2v-pl__img")) { e.stopPropagation(); go(-1); }
    else if (e.key === "ArrowRight" && images.length > 1 && !e.target?.closest?.(".h2v-pl__img")) { e.stopPropagation(); go(+1); }
    else if (e.key === "Tab") {                                  // keep focus inside the dialog
      const f = [...box.querySelectorAll("button, a[href], [tabindex='0']")].filter((x) => !x.disabled);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
    // a modal: no plain key reaches the graph behind it (Delete would delete the selected node)
    if (!e.ctrlKey && !e.metaKey && !e.altKey) e.stopPropagation();
  };
  box.addEventListener("keydown", onKey);
  box.addEventListener("pointerdown", (e) => { e.stopPropagation(); if (e.target === box) close(); });
  box.addEventListener("wheel", stop);
  document.body.append(box);
  show();
  closeBtn.focus();
  function close() {
    if (OPEN !== handle) return;
    OPEN = null;
    viewer?.destroy();
    box.remove();
    for (const im of images) if (im.revoke && im.url) URL.revokeObjectURL(im.url);
    try { opener?.focus?.({ preventScroll: true }); } catch (_) { /* ignore */ }
    onClose?.();
  }
  const handle = { close };
  OPEN = handle;
  return handle;
}
