// Runs the report's script with a stubbed DOM/Plotly and prints the resulting state as JSON.
// usage: node report_smoke.js report.html [comm-to-select]
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const code = html.match(/<script>\nconst D = [\s\S]*?<\/script>/)[0]
  .replace(/^<script>\n/, '').replace(/<\/script>$/, '');
const els = {};
const mk = () => ({
  style: {}, children: [], value: '', hidden: false,
  appendChild(c) { this.children.push(c); return c; },
  set textContent(v) { this._t = v; }, get textContent() { return this._t; },
  set innerHTML(v) { if (!v) { this.children = []; this.value = ''; } },
});
global.document = {getElementById: id => els[id] || (els[id] = mk()), querySelector: () => mk(), createElement: () => mk()};
global.location = {hash: ''};
global.navigator = {clipboard: {writeText() {}}};
global.__plots = {};
global.Plotly = {react: (id, traces, layout) => { global.__plots[id] = {traces, layout}; }};
global.window = global;
eval(code + `;
comms.forEach(c => { c.cb = {checked: false}; });
const wants = process.argv[3] ? process.argv[3].split(',') : [];
const ids = wants.map(n => comms.findIndex(c => c.comm === n)).filter(i => i >= 0);
if (ids.length) setSel(ids);
if (process.argv[4]) {
  els['process-select'].value = String(comms.findIndex(c => c.comm === process.argv[4]));
  els['process-select'].onchange();
}
if (process.argv[5] !== undefined) {
  const next = process.argv[5] ? process.argv[5].split(',') : [];
  setSel(next.map(n => comms.findIndex(c => c.comm === n)).filter(i => i >= 0));
}
const aggregate = global.__plots.chart;
const detail = global.__plots['process-chart'];
console.log(JSON.stringify({
  comms: comms.length,
  pct: els.pct.textContent,
  rate: els.rate.textContent,
  snippet: els.snippet.textContent,
  warn: els.warn.textContent || '',
  caveat: els.caveat.textContent || '',
  kept: aggregate.traces[0].y,
  skipped: aggregate.traces[1].y,
  aggregateTraceCount: aggregate.traces.length,
  aggregateColors: aggregate.traces.map(t => t.marker.color),
  xTickvals: aggregate.layout.xaxis.tickvals,
  detailHidden: els['process-detail'].hidden,
  detailOptions: els['process-select'].children.map(o => ({value: o.value, name: o.textContent})),
  detailValue: els['process-select'].value,
  detailTraces: detail ? detail.traces.map(t => ({name: t.name, y: t.y, type: t.type, color: t.marker.color})) : [],
  detailTickvals: detail ? detail.layout.xaxis.tickvals : null,
}));
`);
