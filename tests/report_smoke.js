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
  setAttribute(name, value) { this[name] = value; },
  set textContent(v) { this._t = v; }, get textContent() { return this._t; },
  set innerHTML(v) { if (!v) { this.children = []; this.value = ''; } },
});
const tbody = mk();
global.document = {getElementById: id => els[id] || (els[id] = mk()), querySelector: () => tbody, createElement: () => mk()};
global.location = {hash: ''};
global.navigator = {clipboard: {writeText() {}}};
global.__plots = {};
global.Plotly = {react: (id, traces, layout) => { global.__plots[id] = {traces, layout}; }};
global.window = global;
eval(code + `;
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
const visibleRows = () => tbody.children.filter(row => !row.hidden).map(row => row.children[1].textContent);
const initialRows = visibleRows();
const initialFilterStatus = els['filter-status']?.textContent;
let allRows, rowsAfterClear;
if (process.argv[6]) {
  els['show-all'].onclick();
  allRows = visibleRows();
  for (const name of process.argv[6].split(',')) {
    const c = comms.find(c => c.comm === name);
    if (c) { c.cb.checked = true; c.cb.onchange(); }
  }
  els['show-all'].onclick();
}
const filteredRows = visibleRows();
const filteredSnippet = els.snippet.textContent;
if (process.argv[6]) {
  els.clear.onclick();
  rowsAfterClear = visibleRows();
}
const aggregate = global.__plots.chart;
const detail = global.__plots['process-chart'];
console.log(JSON.stringify({
  comms: comms.length,
  initialRows,
  initialFilterStatus,
  allRows,
  visibleRows: filteredRows,
  rowsAfterClear,
  filteredSnippet,
  filterStatus: els['filter-status']?.textContent,
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
