// Exercise the actual compiled Jac handler with React state/effect semantics.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('function ResearchWorkspace() {');
const end = source.indexOf('  let inspections =', start);
assert(start >= 0 && end > start, 'Jac component was not compiled');
const slots = [], effects = [], timers = new Map(), calls = [];
let cursor = 0, effectCursor = 0, nextTimer = 1, terminal = false, pendingEffects = [];
const context = {
  Date, console,
  _jac: {exc: {matches: () => true}},
  useState(value) {
    const i = cursor++;
    if (!(i in slots)) slots[i] = i === 0 ? 'Compare project pricing' : value;
    return [slots[i], next => { slots[i] = next; }];
  },
  useRef(value) {
    const i = cursor++;
    if (!(i in slots)) slots[i] = {current: value};
    return slots[i];
  },
  useEffect(fn, deps) {
    const i = effectCursor++;
    const old = effects[i];
    if (!old || deps.some((v, j) => v !== old.deps[j])) {
      pendingEffects.push(() => {
        old?.cleanup?.();
        effects[i] = {deps, cleanup: fn()};
      });
    }
  },
  setTimeout(fn) { const id = nextTimer++; timers.set(id, fn); return id; },
  clearTimeout(id) { timers.delete(id); },
  async __jacCallFunction(name, args) {
    calls.push({name, args});
    if (name === 'guard_status') return {mode: 'heuristic-degraded'};
    if (name === 'start_research') return {ok: true, session_id: 'ses_new'};
    if (name === 'get_session') return {status: terminal ? 'COMPLETE' : 'RUNNING', answer: terminal ? 'Pricing answer' : ''};
    throw Error(name);
  }
};
vm.createContext(context);
vm.runInContext(source.slice(start, end) + 'return {startTask}; }', context);
function render() {
  cursor = effectCursor = 0;
  const handlers = context.ResearchWorkspace();
  const work = pendingEffects; pendingEffects = [];
  work.forEach(fn => fn());
  return handlers;
}
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
(async () => {
  let handler = render(); await flush();
  await Promise.all([handler.startTask(), handler.startTask()]);
  assert.equal(calls.filter(c => c.name === 'start_research').length, 1, 'double click starts one job');
  handler = render(); await flush();
  assert.equal(calls.filter(c => c.name === 'get_session').length, 1, 'accepted session immediately polled');
  assert.equal(calls.find(c => c.name === 'get_session').args.session_id, 'ses_new');
  assert.equal(timers.size, 1);
  terminal = true;
  const [id, tick] = timers.entries().next().value;
  timers.delete(id); tick(); await flush(); render();
  assert.equal(slots[1].answer, 'Pricing answer');
  assert.equal(timers.size, 0, 'terminal session stops polling');
  // Poll a new render/session and ensure unmount cleanup owns the timer.
  terminal = false; slots[2] = 'ses_another'; slots[1] = null;
  render(); await flush(); assert.equal(timers.size, 1);
  effects.forEach(e => e.cleanup?.());
  assert.equal(timers.size, 0, 'unmount clears timer');
  console.log('PASS: new-session polling, duplicate-click prevention, terminal answer, unmount cleanup');
})().catch(error => { console.error(error); process.exitCode = 1; });
