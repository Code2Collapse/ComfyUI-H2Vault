// H2Vault (AGPL-3.0). New for H2Vault (owner 2026-11-24, PART 3 "preview system", L9.342): the pure part of the vault's
// preview viewer - no DOM, no ComfyUI app. Frame / time math of the video player (frame stepping, reverse stepping,
// fps from metadata or measured), image zoom math, the per-output navigation state and the live-preview state.
// Used by web/js/_h2v_player.js and web/js/h2vault_previews.js. Tests: tests/test_preview_player.mjs.

export const FPS_FALLBACK = 30;
export const SPEEDS = [0.25, 0.5, 1, 1.5, 2];
export const ZOOM_MIN = 0.05;
export const ZOOM_MAX = 16;
const STANDARD_FPS = [8, 10, 12, 15, 16, 23.976, 24, 25, 29.97, 30, 48, 50, 59.94, 60, 120];

const finite = (x) => typeof x === "number" && Number.isFinite(x);

/** The output's own frame rate (VHS Video Combine reports `frame_rate`), or null. */
export function fpsFromFile(file) {
  const x = Number(file?.frame_rate);
  return file?.frame_rate != null && finite(x) && x > 0 && x <= 1000 ? x : null;
}

/** A measured rate -> the standard rate within 1 %, else rounded to 3 decimals. */
export function snapFps(raw) {
  if (!finite(raw) || raw <= 0) return null;
  let best = null;
  for (const f of STANDARD_FPS) {
    const d = Math.abs(raw - f) / f;
    if (d <= 0.01 && (best === null || d < best.d)) best = { f, d };
  }
  return best ? best.f : Math.round(raw * 1000) / 1000;
}

/** requestVideoFrameCallback samples [{mediaTime, presentedFrames}] -> fps (median frame duration), or null. */
export function estimateFps(samples) {
  const per = [];
  for (let i = 1; i < (samples || []).length; i++) {
    const a = samples[i - 1], b = samples[i];
    const df = Number(b?.presentedFrames) - Number(a?.presentedFrames);
    const dt = Number(b?.mediaTime) - Number(a?.mediaTime);
    if (finite(df) && finite(dt) && df >= 1 && dt > 0) per.push(dt / df);
  }
  if (per.length < 5) return null;
  per.sort((x, y) => x - y);
  const m = per.length % 2 ? per[(per.length - 1) / 2] : (per[per.length / 2 - 1] + per[per.length / 2]) / 2;
  return snapFps(1 / m);
}

/** 0-based index of the frame shown at time t (the 1e-4 absorbs float noise right below a frame boundary). */
export function frameAt(t, fps) {
  return Math.max(0, Math.floor(t * fps + 1e-4));
}

export function frameCount(duration, fps) {
  return finite(duration) ? Math.max(1, Math.round(duration * fps)) : null;
}

/** The time that shows frame i: mid-frame, because browsers round a seek to the nearest presented timestamp and an
 *  exact boundary can land on the previous frame. */
export function timeOfFrame(i, fps, duration) {
  let k = Math.max(0, Math.floor(i));
  const n = frameCount(duration, fps);
  if (n !== null) k = Math.min(k, n - 1);
  return (k + 0.5) / fps;
}

export function stepFrame(t, fps, duration, dir) {
  return timeOfFrame(frameAt(t, fps) + dir, fps, duration);
}

export function clampTime(t, duration) {
  return finite(duration) ? Math.min(Math.max(0, t), duration) : Math.max(0, t);
}

export function formatTime(t) {
  if (!finite(t)) return "--:--";
  const cs = Math.round(Math.max(0, t) * 100);
  const h = Math.floor(cs / 360000), m = Math.floor((cs % 360000) / 6000), s = Math.floor((cs % 6000) / 100);
  const c = String(cs % 100).padStart(2, "0");
  const ss = String(s).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${ss}.${c}` : `${m}:${ss}.${c}`;
}

/**
 * Reverse playback by controlled frame stepping. Native negative playbackRate is not supported by Chrome or Firefox
 * (only Safari), so the player keeps the element paused and seeks backwards: the wall clock since the anchor (the
 * time / moment reverse started, wrapped or changed speed) says how far back the playhead should be; the target is
 * snapped to a whole frame. -> {time, ended, wrapped}.
 */
export function reverseTarget({ anchorTime, anchorWall, now, speed, fps, duration, loop }) {
  const raw = anchorTime - ((now - anchorWall) / 1000) * speed;
  if (raw >= 0) return { time: timeOfFrame(frameAt(raw, fps), fps, duration), ended: false, wrapped: false };
  if (loop && finite(duration) && duration > 0) {
    const t = duration + (raw % duration);
    return { time: timeOfFrame(frameAt(t, fps), fps, duration), ended: false, wrapped: true };
  }
  return { time: timeOfFrame(0, fps, duration), ended: true, wrapped: false };
}

export function seekFromPointer(clientX, left, width, duration) {
  return clampTime(width > 0 ? ((clientX - left) / width) * duration : 0, duration);
}

// ── image zoom ─────────────────────────────────────────────────────────────────────────────────────────────────
export function fitScale(nw, nh, bw, bh) {
  if (!(nw > 0 && nh > 0 && bw > 0 && bh > 0)) return 1;
  return Math.min(bw / nw, bh / nh);
}

export function centered(nw, nh, bw, bh, scale) {
  return { scale, x: (bw - nw * scale) / 2, y: (bh - nh * scale) / 2 };
}

/** Zoom by `factor` keeping the image point under (px, py) (box coordinates) where it is. */
export function zoomAt(view, factor, px, py) {
  const scale = Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, view.scale * factor));
  const k = scale / view.scale;
  return { scale, x: px - (px - view.x) * k, y: py - (py - view.y) * k };
}

// ── several outputs: navigation + each video's own state ───────────────────────────────────────────────────────
const DEFAULT_STATE = { time: 0, paused: false, rate: 1, loop: true, muted: true, volume: 1 };

export function createViewer() {
  const states = new Map();
  const v = {
    entries: [],
    index: 0,
    setEntries(list) {
      const cur = v.current();
      const next = Array.isArray(list) ? list : [];
      let i = cur ? next.findIndex((e) => e.key === cur.key) : -1;
      if (i < 0 && cur) i = next.findIndex((e) => e.label === cur.label);
      v.entries = next;
      v.index = i < 0 ? 0 : i;
      const keys = new Set(next.map((e) => e.key));
      for (const k of [...states.keys()]) if (!keys.has(k)) states.delete(k);
    },
    current() {
      return v.entries[v.index] ?? null;
    },
    go(delta) {
      const n = v.entries.length;
      if (n) v.index = (((v.index + delta) % n) + n) % n;
    },
    select(i) {
      if (Number.isInteger(i) && i >= 0 && i < v.entries.length) v.index = i;
    },
    stateOf(key) {
      return { ...DEFAULT_STATE, ...(states.get(key) || {}) };
    },
    saveState(key, patch) {
      states.set(key, { ...(states.get(key) || {}), ...(patch || {}) });
    },
  };
  return v;
}

// ── live sampler previews ──────────────────────────────────────────────────────────────────────────────────────
export function createLive() {
  const blank = () => ({ url: null, kind: null, step: null, total: null, note: null });
  const l = {
    state: blank(),
    frame(url, kind) {
      const old = l.state.url;
      l.state.url = url;
      l.state.kind = kind;
      return old;
    },
    progress(value, max) {
      if (finite(value)) l.state.step = value;
      if (finite(max) && max > 0) l.state.total = max;          // a second sampler pass brings its own total
    },
    note(text) {
      l.state.note = text || null;
    },
    clear() {
      const old = l.state.url;
      l.state = blank();
      return old;
    },
    active() {
      return !!l.state.url || l.state.step !== null || !!l.state.note;
    },
  };
  return l;
}
