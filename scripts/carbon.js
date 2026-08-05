#!/usr/bin/env node
/**
 * carbon.js — vendored from https://github.com/serenasensini/hugo-carbon-footprint
 *
 * Measures homepage weight and computes estimated CO2 using
 * https://api.websitecarbon.com/data?bytes={n}&green={0/1}
 * (the only public endpoint available since July 14, 2025).
 *
 * The result is saved to data/carbon.json, which Hugo automatically
 * loads as site.Data.carbon in templates.
 *
 * Environment variables:
 *   CARBON_SITE_URL   – URL to analyze                 (default: http://localhost:1313)
 *   CARBON_GREEN      – green hosting? "1" or "0"      (default: "0")
 *   CARBON_BYTES      – fixed bytes sent to the API    (skips page fetch)
 *   CARBON_OUTPUT     – output path for the JSON file  (default: data/carbon.json)
 *
 * NOTE: run this locally, not in CI. The Website Carbon API sits behind
 * Cloudflare, which returns 403 for traffic from cloud/datacenter ASNs
 * (including GitHub Actions runners). Re-run manually and commit the
 * updated data/carbon.json whenever you want to refresh the figure.
 *
 * Requires Node.js >= 18 (native fetch).
 */

import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { resolve, dirname }                     from 'path';

const SITE_URL = process.env.CARBON_SITE_URL ?? 'http://localhost:1313';
const GREEN    = process.env.CARBON_GREEN    ?? '0';
const OUTPUT   = process.env.CARBON_OUTPUT
  ? resolve(process.cwd(), process.env.CARBON_OUTPUT)
  : resolve(process.cwd(), 'data', 'carbon.json');

// ---------------------------------------------------------------------------

/** Retrieves homepage size in bytes (HTML only). */
async function fetchPageBytes(url) {
  if (process.env.CARBON_BYTES) {
    const b = parseInt(process.env.CARBON_BYTES, 10);
    console.log(`[carbon] Using fixed CARBON_BYTES: ${b} bytes`);
    return b;
  }

  console.log(`[carbon] Measuring page size → ${url}`);
  const response = await fetch(url, {
    headers: { 'Accept': 'text/html', 'User-Agent': 'hugo-carbon-footprint/1.0' },
  });

  if (!response.ok) {
    throw new Error(`Unable to reach ${url}: HTTP ${response.status} ${response.statusText}`);
  }

  const buffer = await response.arrayBuffer();
  const bytes  = buffer.byteLength;

  console.log(`[carbon] HTML size: ${(bytes / 1024).toFixed(1)} KB (${bytes} bytes)`);
  console.log(`[carbon] ℹ️  To include CSS/JS/images, set CARBON_BYTES to the full page weight.`);
  return bytes;
}

// ---------------------------------------------------------------------------

async function main() {
  const bytes = await fetchPageBytes(SITE_URL);

  const apiUrl = `https://api.websitecarbon.com/data?bytes=${bytes}&green=${GREEN}`;
  console.log(`[carbon] API call → ${apiUrl}`);

  const response = await fetch(apiUrl, { headers: { 'Accept': 'application/json' } });

  if (!response.ok) {
    throw new Error(`API responded with: HTTP ${response.status} - ${response.statusText}`);
  }

  const data = await response.json();

  data._meta = {
    siteUrl:    SITE_URL,
    green:      GREEN === '1',
    bytes,
    measuredAt: new Date().toISOString(),
  };

  mkdirSync(dirname(OUTPUT), { recursive: true });
  writeFileSync(OUTPUT, JSON.stringify(data, null, 2), 'utf8');

  const grams       = typeof data.gco2e === 'number' ? data.gco2e.toFixed(4) : 'N/A';
  const cleanerThan = typeof data.cleanerThan === 'number'
    ? (data.cleanerThan * 100).toFixed(0)
    : 'N/A';

  console.log(`[carbon] ✅ Result saved to: ${OUTPUT}`);
  console.log(`[carbon]    CO2/visit  : ${grams}g`);
  console.log(`[carbon]    Rating     : ${data.rating ?? 'N/A'}`);
  console.log(`[carbon]    Cleaner than ${cleanerThan}% of analyzed websites`);
}

// ---------------------------------------------------------------------------

main().catch((err) => {
  console.error('\n[carbon] ❌ Error:', err.message);

  if (existsSync(OUTPUT)) {
    console.warn('[carbon] ℹ️  The existing carbon.json file will be used for the Hugo build.');
  } else {
    console.error('[carbon] No carbon.json found - the CO2 badge will not be shown in the footer.');
  }

  process.exit(0); // soft exit: do not block the Hugo build
});
