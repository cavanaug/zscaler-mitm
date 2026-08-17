import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { parseSpkiDer } from '../cert.js';

const MOZILLA_PEM_URL =
  'https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV';
const V4A_URL =
  'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4a';

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let i = 0;
  let inQuotes = false;

  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
        } else {
          inQuotes = false;
          i++;
        }
      } else {
        field += c;
        i++;
      }
    } else if (c === '"') {
      inQuotes = true;
      i++;
    } else if (c === ',') {
      row.push(field);
      field = '';
      i++;
    } else if (c === '\r') {
      i++;
      if (text[i] === '\n') i++;
      row.push(field);
      field = '';
      if (row.some((x) => x !== '')) rows.push(row);
      row = [];
    } else if (c === '\n') {
      i++;
      row.push(field);
      field = '';
      if (row.some((x) => x !== '')) rows.push(row);
      row = [];
    } else {
      field += c;
      i++;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    if (row.some((x) => x !== '')) rows.push(row);
  }
  return rows;
}

function rowsToObjects(rows) {
  const [header, ...data] = rows;
  return data.map((cells) => {
    const obj = {};
    for (let i = 0; i < header.length; i++) obj[header[i]] = cells[i] ?? '';
    return obj;
  });
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

function processMozillaPem(rows, organizations, issuerCNs, rootSpkis) {
  for (const row of rows) {
    if (!row['Trust Bits']?.includes('Websites')) continue;
    add(organizations, row.Owner);
    add(organizations, row['Certificate Issuer Organization']);
    addIssuerCn(issuerCNs, row['Common Name or Certificate Name']);
    const hash = spkiHash(row['PEM Info']);
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

  processMozillaPem(rowsToObjects(parseCsv(mozillaText)), organizations, issuerCNs, rootSpkis);
  processV4a(rowsToObjects(parseCsv(v4aText)), organizations, issuerCNs);
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
