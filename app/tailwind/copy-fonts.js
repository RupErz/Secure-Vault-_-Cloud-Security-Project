// Copies only the font files the stylesheet references into dist/fonts/ (self-hosted, so the
// CSP can stay font-src 'self'). Run after tailwindcss by `npm run build`.
const fs = require("fs");
const path = require("path");

const wanted = {
  "ibm-plex-sans": ["400", "500", "600"],
  "ibm-plex-serif": ["500"],
  "ibm-plex-mono": ["400"],
};
const out = path.join(__dirname, "dist", "fonts");
fs.mkdirSync(out, { recursive: true });
for (const [family, weights] of Object.entries(wanted)) {
  for (const w of weights) {
    const name = `${family}-latin-${w}-normal.woff2`;
    fs.copyFileSync(path.join(__dirname, "node_modules", "@fontsource", family, "files", name), path.join(out, name));
  }
}
console.log("fonts copied:", fs.readdirSync(out).join(", "));
