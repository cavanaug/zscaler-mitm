import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseSpkiDer } from '../asn1.js';

const MOZILLA_PEM_URL =
  'https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV';
const V4A_URL =
  'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4a';

/** Run xsv over `text`, return row objects for the selected columns.
 *  Only works for columns without embedded newlines (PEM is handled separately). */
function xsvRows(text, columns) {
  const dir = mkdtempSync(join(tmpdir(), 'ccadb-'));
  try {
    const csvPath = join(dir, 'in.csv');
    const selPath = join(dir, 'sel.csv');
    writeFileSync(csvPath, text);
    writeFileSync(
      selPath,
      execFileSync('xsv', ['select', columns.map((c) => `"${c}"`).join(','), csvPath], {
        maxBuffer: 1 << 26,
      }),
    );
    const tsv = execFileSync('xsv', ['fmt', '-t', '\t', selPath], { maxBuffer: 1 << 26, encoding: 'utf8' });
    const [header, ...lines] = tsv.trimEnd().split('\n');
    const keys = header.split('\t');
    return lines.map((line) => {
      const cells = line.split('\t');
      return Object.fromEntries(keys.map((k, i) => [k, cells[i] ?? '']));
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Extract one CSV column as raw per-record values, keeping multi-line quoted fields intact. */
function xsvSingleColumn(text, column) {
  const dir = mkdtempSync(join(tmpdir(), 'ccadb-'));
  try {
    const csvPath = join(dir, 'in.csv');
    writeFileSync(csvPath, text);
    const csv = execFileSync('xsv', ['select', `"${column}"`, csvPath], {
      maxBuffer: 1 << 26,
      encoding: 'utf8',
    });
    const out = [];
    let span = null; // open "..." record with embedded newlines
    for (const line of csv.trimEnd().split('\n')) {
      if (span !== null) {
        span.push(line);
        if (line.endsWith('"')) {
          out.push(span.join('\n'));
          span = null;
        }
      } else if (line.startsWith('"') && !line.endsWith('"')) {
        span = [line];
      } else {
        out.push(line);
      }
    }
    return out.slice(1); // drop header
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function csvUnquote(v) {
  return v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1).replace(/""/g, '"') : v;
}

function add(set, value) {
  const s = String(value ?? '').trim();
  if (s) set.add(s);
}

function addIssuerCn(set, value) {
  const s = String(value ?? '').trim();
  if (s.length >= 8) set.add(s);
}

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed ${url}: ${res.status}`);
  return res.text();
}

function spkiHash(pem) {
  try {
    let p = String(pem ?? '').trim();
    if (p.startsWith("'") && p.endsWith("'")) p = p.slice(1, -1);
    const spki = parseSpkiDer(p);
    return createHash('sha256').update(spki).digest('hex');
  } catch {
    return null;
  }
}

function processMozillaPem(rows, pems, organizations, issuerCNs, rootSpkis) {
  if (rows.length !== pems.length) {
    throw new Error(`mozilla row mismatch: ${rows.length} rows vs ${pems.length} pems`);
  }
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (!row['Trust Bits']?.includes('Websites')) continue;
    add(organizations, row.Owner);
    add(organizations, row['Certificate Issuer Organization']);
    addIssuerCn(issuerCNs, row['Common Name or Certificate Name']);
    const hash = spkiHash(csvUnquote(pems[i]));
    if (hash) rootSpkis.add(hash);
  }
}

function v4aIncluded(row) {
  if (row['Revocation Status'] === 'Revoked') return false;
  if (row['Chrome Status'] === 'Included') return true;
  if (row['Mozilla Status'] === 'Included') return true;
  const root = row['Status of Root Cert'] || '';
  return root.includes('Google Chrome: Included') || root.includes('Mozilla: Included');
}

function processV4a(rows, organizations, issuerCNs) {
  for (const row of rows) {
    if (!v4aIncluded(row)) continue;
    add(organizations, row['CA Owner']);
    addIssuerCn(issuerCNs, row['Certificate Name']);
  }
}

function addKnownOrgAliases(organizations) {
  if ([...organizations].some((o) => /internet security research group/i.test(o))) {
    add(organizations, "Let's Encrypt");
  }
}

async function main() {
  const [mozillaText, v4aText] = await Promise.all([fetchText(MOZILLA_PEM_URL), fetchText(V4A_URL)]);

  const organizations = new Set();
  const issuerCNs = new Set();
  const rootSpkis = new Set();

  processMozillaPem(
    xsvRows(mozillaText, [
      'Trust Bits',
      'Owner',
      'Certificate Issuer Organization',
      'Common Name or Certificate Name',
    ]),
    xsvSingleColumn(mozillaText, 'PEM Info'),
    organizations,
    issuerCNs,
    rootSpkis,
  );
  processV4a(
    xsvRows(v4aText, [
      'Revocation Status',
      'Chrome Status',
      'Mozilla Status',
      'Status of Root Cert',
      'CA Owner',
      'Certificate Name',
    ]),
    organizations,
    issuerCNs,
  );
  addKnownOrgAliases(organizations);

  const orgList = [...organizations].sort();
  if (orgList.length < 50) {
    console.error(`organizations.length ${orgList.length} < 50`);
    process.exit(1);
  }

  const out = {
    version: 1,
    generatedAt: new Date().toISOString(),
    source: 'ccadb-intermediates+roots',
    organizations: orgList,
    issuerCNs: [...issuerCNs].sort(),
    rootSpkis: [...rootSpkis].sort(),
  };

  writeFileSync('public-cas.json', JSON.stringify(out, null, 2) + '\n');
  console.log(
    `wrote public-cas.json: ${out.organizations.length} orgs, ${out.issuerCNs.length} CNs, ${out.rootSpkis.length} SPKIs`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
