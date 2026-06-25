// Executed in the page by runtime_fingerprint.fingerprint_runtime().
// Returns {frontend, libraries, versions, evidence, scripts}.
() => {
  const out = { frontend: [], libraries: [], versions: {}, evidence: [], scripts: [] };
  const w = window;
  const add = (bucket, name, version, ev) => {
    const key = bucket === 'library' ? 'libraries' : bucket;  // out uses plural 'libraries'
    if (!out[key].includes(name)) out[key].push(name);
    if (version) out.versions[name] = String(version);
    out.evidence.push(ev);
  };

  // React: production-safe via fiber keys on DOM nodes.
  try {
    let react = !!(w.React || w.__REACT_DEVTOOLS_GLOBAL_HOOK__);
    if (!react) {
      const nodes = document.querySelectorAll('*');
      const max = Math.min(nodes.length, 3000);
      for (let i = 0; i < max; i++) {
        const keys = Object.keys(nodes[i]);
        if (keys.some(k => k.startsWith('__reactFiber$') ||
            k.startsWith('__reactContainer$') || k.startsWith('__reactProps$'))) {
          react = true;
          break;
        }
      }
    }
    if (react) add('frontend', 'React', w.React && w.React.version, 'runtime:react-fiber');
  } catch (e) {}

  // Angular
  try {
    const el = document.querySelector('[ng-version]');
    if (el || w.ng || w.getAllAngularRootElements) {
      add('frontend', 'Angular', el && el.getAttribute('ng-version'), 'runtime:ng-version');
    }
  } catch (e) {}

  // Vue
  try {
    if (w.__VUE__ || w.Vue || document.querySelector('[data-v-app]')) {
      add('frontend', 'Vue.js', w.Vue && w.Vue.version, 'runtime:vue');
    }
  } catch (e) {}

  // lit
  try {
    if (w.litHtmlVersions || w.litElementVersions || w.reactiveElementVersions) {
      add('library', 'lit', w.litHtmlVersions && w.litHtmlVersions[0], 'runtime:litVersions');
    }
  } catch (e) {}

  // Three.js
  try {
    if (w.THREE) add('library', 'Three.js', w.THREE.REVISION, 'runtime:THREE');
  } catch (e) {}

  // core-js
  try {
    const cj = w['__core-js_shared__'];
    if (cj) {
      let v = null;
      try { v = cj.versions && cj.versions[0] && cj.versions[0].version; } catch (e) {}
      add('library', 'core-js', v, 'runtime:__core-js_shared__');
    }
  } catch (e) {}

  // Common library globals
  const G = [
    ['jQuery', () => w.jQuery, () => w.jQuery.fn && w.jQuery.fn.jquery],
    ['Lodash', () => w._ && w._.VERSION, () => w._.VERSION],
    ['RxJS', () => w.rxjs, () => null],
    ['Redux', () => w.Redux || w.__REDUX_DEVTOOLS_EXTENSION__, () => null],
    ['D3.js', () => w.d3 && w.d3.version, () => w.d3.version],
    ['Mapbox GL', () => w.mapboxgl, () => w.mapboxgl.version],
    ['Leaflet', () => w.L && w.L.version, () => w.L.version],
    ['Moment.js', () => w.moment && w.moment.version, () => w.moment.version],
    ['Day.js', () => w.dayjs, () => null],
    ['Chart.js', () => w.Chart && w.Chart.version, () => w.Chart.version],
    ['Bootstrap', () => w.bootstrap && w.bootstrap.Tooltip,
      () => w.bootstrap.Tooltip && w.bootstrap.Tooltip.VERSION],
  ];
  for (const [name, present, ver] of G) {
    try {
      if (present()) add('library', name, ver(), 'runtime:global');
    } catch (e) {}
  }

  // Tailwind: --tw- custom properties in stylesheets / computed body.
  try {
    let tw = false;
    for (const sheet of document.styleSheets) {
      let rules;
      try { rules = sheet.cssRules; } catch (e) { continue; }
      if (!rules) continue;
      for (const r of rules) {
        if (r.cssText && r.cssText.indexOf('--tw-') > -1) { tw = true; break; }
      }
      if (tw) break;
    }
    if (!tw) {
      const cs = getComputedStyle(document.body || document.documentElement);
      if (cs.getPropertyValue('--tw-bg-opacity') ||
          cs.getPropertyValue('--tw-ring-offset-width')) tw = true;
    }
    if (tw) add('library', 'Tailwind CSS', null, 'runtime:--tw-');
  } catch (e) {}

  // PWA
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.controller) {
      add('library', 'PWA', null, 'runtime:sw');
    }
  } catch (e) {}
  try {
    if (document.querySelector('link[rel=manifest]')) add('library', 'PWA', null, 'runtime:manifest');
  } catch (e) {}

  // Loaded JS chunks (diagnostics).
  try {
    out.scripts = performance.getEntriesByType('resource')
      .map(e => e.name).filter(n => n.endsWith('.js')).slice(0, 60);
  } catch (e) {}

  return out;
}
