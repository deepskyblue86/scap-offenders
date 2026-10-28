// Runs the report's script with a stubbed DOM/Plotly and prints the resulting state as JSON.
// usage: node report_smoke.js report.html [comm-to-select]
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const code = html.match(/<script>\nconst D = [\s\S]*?<\/script>/)[0]
  .replace(/^<script>\n/, '').replace(/<\/script>$/, '');
const els = {};
const mk = () => ({
  style: {}, children: [],
  appendChild(c) { this.children.push(c); return c; },
  set textContent(v) { this._t = v; }, get textContent() { return this._t; },
});
global.document = {getElementById: id => els[id] || (els[id] = mk()), querySelector: () => mk(), createElement: () => mk()};
global.location = {hash: ''};
global.navigator = {clipboard: {writeText() {}}};
global.Plotly = {react: (id, traces, layout) => { global.__traces = traces; global.__layout = layout; }};
global.window = global;
eval(code + `;
comms.forEach(c => { c.cb = {checked: false}; });
const want = process.argv[3];
const i = want ? comms.findIndex(c => c.comm === want) : -1;
if (i >= 0) setSel([i]);
console.log(JSON.stringify({
  comms: comms.length,
  pct: els.pct.textContent,
  rate: els.rate.textContent,
  snippet: els.snippet.textContent,
  warn: els.warn.textContent || '',
  caveat: els.caveat.textContent || '',
  kept: global.__traces[0].y,
  skipped: global.__traces[1].y,
  xTickvals: global.__layout.xaxis ? global.__layout.xaxis.tickvals : null,
}));
`);
