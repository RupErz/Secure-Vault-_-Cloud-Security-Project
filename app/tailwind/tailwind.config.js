// Tailwind scans these files for class names. upload.js is included because it
// builds progress rows with class strings at runtime.
//
// The palette REPLACES Tailwind's defaults (theme.colors, not extend) so only these roles
// exist; a stray `bg-slate-900` simply produces no CSS and is easy to spot.
// Contrast on `paper` (checked): ink 15.5, ink-2 7.4, ink-3 5.2, ok 5.9, bad 6.7, warn 6.2.
module.exports = {
  content: [
    "../vault/templates/**/*.html",
    "../vault/static/vault/*.js",
  ],
  theme: {
    colors: {
      transparent: "transparent",
      current: "currentColor",
      paper: "#f6f3ec",     // page canvas (warm off-white)
      sheet: "#fdfcf9",     // inputs and raised surfaces
      ink: "#1c1b18",       // primary text, primary buttons
      "ink-2": "#524f46",   // secondary text
      "ink-3": "#6a665b",   // tertiary text, placeholders (still >= 4.5:1)
      rule: "#ddd8cb",      // hairlines between rows/sections
      edge: "#8f8a7b",      // borders of interactive controls (>= 3:1)
      ok: "#1d6a49",        // encrypted / verified / success, and the focus ring
      "ok-tint": "#e4efe8",
      bad: "#a1261e",       // failures, destructive actions
      "bad-tint": "#f7e5e2",
      warn: "#7a5200",      // deletions in the audit trail
    },
    fontFamily: {
      sans: ['"IBM Plex Sans"', "ui-sans-serif", "system-ui", "sans-serif"],
      serif: ['"IBM Plex Serif"', "ui-serif", "Georgia", "serif"],
      mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
    },
    extend: {
      maxWidth: { page: "64rem" },
    },
  },
  plugins: [],
};
