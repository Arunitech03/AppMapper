// Passive browser-intelligence capture, run ONCE at end-of-session by
// explorer.explore() via page.evaluate (only outside --safe-mode).
//
// Returns metadata/schemas/field-names — NOT full datasets or payloads. Values
// that come back are masked in Python before they are stored. Every section is
// wrapped so one failure never aborts the whole capture, and the async parts
// (IndexedDB / Cache Storage / Service Workers) are bounded by a timeout.
async () => {
  const out = {
    localStorage: {}, sessionStorage: {}, indexeddb: [], cache_storage: [],
    service_workers: [], runtime_config: {}, framework_state: {}, forms: [],
    routes: [], manifest: null,
  };

  const withTimeout = (p, ms) =>
    Promise.race([p, new Promise((res) => setTimeout(() => res(null), ms))]);

  // --- localStorage / sessionStorage (string maps) ---
  try { out.localStorage = Object.fromEntries(Object.entries(localStorage)); } catch (e) {}
  try { out.sessionStorage = Object.fromEntries(Object.entries(sessionStorage)); } catch (e) {}

  // --- IndexedDB: db -> stores -> {count, fields(keys only of one record)} ---
  try {
    if (indexedDB && indexedDB.databases) {
      const dbs = (await withTimeout(indexedDB.databases(), 2000)) || [];
      for (const meta of dbs.slice(0, 10)) {
        const dbInfo = { database: meta.name, version: meta.version, stores: [] };
        try {
          const db = await withTimeout(new Promise((resolve, reject) => {
            const req = indexedDB.open(meta.name);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
          }), 2000);
          if (db) {
            for (const storeName of Array.from(db.objectStoreNames).slice(0, 25)) {
              const info = { name: storeName, count: null, fields: [] };
              try {
                const tx = db.transaction(storeName, 'readonly');
                const store = tx.objectStore(storeName);
                info.count = await withTimeout(new Promise((r) => {
                  const c = store.count(); c.onsuccess = () => r(c.result); c.onerror = () => r(null);
                }), 1500);
                // ONE record, field names only (never the values).
                const rec = await withTimeout(new Promise((r) => {
                  const cur = store.openCursor();
                  cur.onsuccess = () => r(cur.result ? cur.result.value : null);
                  cur.onerror = () => r(null);
                }), 1500);
                if (rec && typeof rec === 'object') info.fields = Object.keys(rec).slice(0, 50);
              } catch (e) {}
              dbInfo.stores.push(info);
            }
            try { db.close(); } catch (e) {}
          }
        } catch (e) {}
        out.indexeddb.push(dbInfo);
      }
    }
  } catch (e) {}

  // --- Cache Storage: cache name -> request URLs ---
  try {
    if (window.caches && caches.keys) {
      const names = (await withTimeout(caches.keys(), 1500)) || [];
      for (const name of names.slice(0, 25)) {
        const entry = { cache: name, entries: [] };
        try {
          const cache = await caches.open(name);
          const reqs = (await withTimeout(cache.keys(), 1500)) || [];
          entry.entries = reqs.slice(0, 200).map((r) => r.url);
        } catch (e) {}
        out.cache_storage.push(entry);
      }
    }
  } catch (e) {}

  // --- Service Workers: scriptURL + scope ---
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
      const regs = (await withTimeout(navigator.serviceWorker.getRegistrations(), 1500)) || [];
      for (const reg of regs) {
        const sw = reg.active || reg.installing || reg.waiting;
        out.service_workers.push({ scope: reg.scope, scriptURL: sw ? sw.scriptURL : null });
      }
    }
  } catch (e) {}

  // --- Runtime config: common global config objects (shallow) ---
  try {
    const shallow = (obj) => {
      const o = {};
      for (const k of Object.keys(obj || {}).slice(0, 100)) {
        const v = obj[k];
        if (v === null || ['string', 'number', 'boolean'].includes(typeof v)) o[k] = v;
        else if (Array.isArray(v)) o[k] = v.slice(0, 50).filter((x) => typeof x !== 'object');
        else if (typeof v === 'object') o[k] = '[object]'; // keep nested keys out of values
      }
      return o;
    };
    for (const g of ['__CONFIG__', '__ENV__', 'appConfig', 'APP_CONFIG', 'environment',
                     'settings', 'config', 'ENV', 'runtimeConfig']) {
      try { if (window[g] && typeof window[g] === 'object') out.runtime_config[g] = shallow(window[g]); } catch (e) {}
    }
  } catch (e) {}

  // --- Framework state: TOP-LEVEL KEYS ONLY (state may hold tokens/PII) ---
  try {
    const fs = {};
    // Redux
    try {
      const store = window.store || window.__store__ ||
        (window.__REDUX_DEVTOOLS_EXTENSION__ && window.__REDUX_STORE__);
      if (store && typeof store.getState === 'function') fs.redux = Object.keys(store.getState() || {}).slice(0, 100);
    } catch (e) {}
    // Vuex
    try {
      const app = document.querySelector('#app');
      const vue = (app && (app.__vue__ || app.__vue_app__));
      const vstore = (window.$nuxt && window.$nuxt.$store) || (vue && vue.$store);
      if (vstore && vstore.state) fs.vuex = Object.keys(vstore.state).slice(0, 100);
    } catch (e) {}
    // Angular (presence + version), keys not generally reachable
    try { if (window.ng || window.getAllAngularRootElements) fs.angular = true; } catch (e) {}
    out.framework_state = fs;
  } catch (e) {}

  // --- Forms: action / method / field names ---
  try {
    for (const f of Array.from(document.querySelectorAll('form')).slice(0, 100)) {
      const fields = Array.from(f.querySelectorAll('input,select,textarea'))
        .map((el) => el.getAttribute('name') || el.getAttribute('id'))
        .filter(Boolean).slice(0, 60);
      out.forms.push({ action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'GET').toUpperCase(), fields });
    }
  } catch (e) {}

  // --- Routes: same-origin anchor hrefs (paths only) ---
  try {
    const seen = new Set();
    for (const a of Array.from(document.querySelectorAll('a[href]')).slice(0, 2000)) {
      try {
        const u = new URL(a.href, location.href);
        if (u.origin === location.origin && u.pathname && u.pathname !== '/') seen.add(u.pathname + (u.hash || ''));
      } catch (e) {}
    }
    out.routes = Array.from(seen).slice(0, 300);
  } catch (e) {}

  // --- Web manifest href ---
  try {
    const link = document.querySelector('link[rel="manifest"]');
    if (link) out.manifest = { href: link.href };
  } catch (e) {}

  return out;
}
