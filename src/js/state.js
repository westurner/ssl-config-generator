// DOM-bound thin wrapper around src/js/render.js (the pure renderer).
// This file is the entry point used by src/js/index.js in the browser; the
// off-line generators in scripts/ call render.js directly. See render.js
// for the actual TLS / cipher / PQ mode logic — keep them in sync.

import configs from './configs.js';
import pureState from './render.js';

const guideln_latest = '6.0';
const guidelines = {};
guidelines[guideln_latest] = require(`../static/guidelines/${guideln_latest}.json`);

export default async function () {

  async function fetch_guideline(guideln) {
    if (isNaN(guideln) || isNaN(parseFloat(guideln))) {
      return guideln_latest;
    }
    const url = "https://ssl-config.mozilla.org/guidelines/"+guideln+".json";
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`error retrieving ${guideln}.json: ${response.status}`);
      }
      guidelines[guideln] = await response.json();
      return guideln;
    } catch (error) {
      console.error(error.message);
      return guideln_latest;
    }
  }

  const form = document.getElementById('form-generator').elements;
  const server = form['server'].value;
  let guideln = form['guideline'].value !== '' ? form['guideline'].value : guideln_latest;
  let sstls = guidelines[guideln];
  if (!sstls) {
      guideln = await fetch_guideline(guideln);
      if (guideln === '5.0') {
        if (await fetch_guideline('5.1') === '5.1') {
          for (let x of ['modern', 'intermediate', 'old']) {
            let ss5 = guidelines['5.0'].configurations[x];
            ss5.ciphersuites = ss5.openssl_ciphersuites;
            ss5.ciphers = {
              iana: guidelines['5.1'].configurations[x].ciphers.iana,
              openssl: ss5.openssl_ciphers
            };
          }
        }
        else {
          guideln = guideln_latest;
        }
      }
      sstls = guidelines[guideln];
  }

  let pqMode = form['pq'] ? form['pq'].value : 'hybrid';

  const url = new URL(document.location);

  return pureState({
    server,
    serverVersion: form['version'].value,
    opensslVersion: form['openssl'].value,
    config: form['config'].value,
    hsts: !!form['hsts'].checked,
    ocsp: !!form['ocsp'].checked,
    pqMode,
    guideline: guideln,
    guidelineData: sstls,
    origin: url.origin,
    pathname: url.pathname,
    now: new Date(),
  });
};
