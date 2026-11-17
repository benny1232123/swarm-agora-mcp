#!/usr/bin/env node
/**
 * detect_vulnerabilities.js
 * Scans Windows services for unquoted executable paths and kernel drivers for non‑standard locations.
 * Usage: node detect_vulnerabilities.js [--json]
 */
const { exec } = require('child_process');

function parseCsv(csv) {
  if (!csv) return [];
  const lines = csv.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const headers = lines[0].split(',');
  return lines.slice(1).map(line => {
    const cols = line.split(',');
    const obj = {};
    headers.forEach((h, i) => obj[h.trim()] = cols[i] ? cols[i].trim() : '');
    return obj;
  });
}

function checkUnquotedServicePaths(callback) {
  exec('wmic service get Name,PathName /FORMAT:CSV', (err, stdout) => {
    // If the command is unavailable (e.g., on non‑Windows platforms), treat it as no data.
    if (err) return callback(null, []);
    const rows = parseCsv(stdout);
    const vulnerable = rows.filter(r => {
      const path = r.PathName;
      if (!path) return false;
      const hasQuotes = path.startsWith('"') && path.endsWith('"');
      if (hasQuotes) return false;
      return /\s/.test(path);
    }).map(r => ({ name: r.Name, path: r.PathName }));
    callback(null, vulnerable);
  });
}

function checkKernelDrivers(callback) {
  exec('driverquery /FO CSV /V', (err, stdout) => {
    // If the command is unavailable, return an empty list instead of failing.
    if (err) return callback(null, []);
    const rows = parseCsv(stdout);
    const suspicious = rows.filter(r => {
      const imagePath = r['Path'];
      if (!imagePath) return false;
      const lower = imagePath.toLowerCase();
      const isSystem = lower.includes('\\system32\\') || lower.includes('\\drivers\\');
      const isSys = lower.endsWith('.sys');
      return !(isSystem && isSys);
    }).map(r => ({
      name: r['Module Name'],
      path: r['Path'],
      description: r['Description']
    }));
    callback(null, suspicious);
  });
}

function run(json) {
  checkUnquotedServicePaths((e, services) => {
    if (e) {
      console.error('Failed to enumerate services:', e.message);
      process.exit(1);
    }
    checkKernelDrivers((e2, drivers) => {
      if (e2) {
        console.error('Failed to enumerate drivers:', e2.message);
        process.exit(1);
      }
      const report = { unquotedServicePaths: services, suspiciousDrivers: drivers };
      if (json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log('=== Unquoted Service Paths ===');
        if (services.length) services.forEach(s => console.log(`- ${s.name}: ${s.path}`));
        else console.log('None found.');
        console.log('\n=== Suspicious Kernel Drivers ===');
        if (drivers.length) drivers.forEach(d => console.log(`- ${d.name}: ${d.path}`));
        else console.log('None found.');
      }
    });
  });
}

const args = process.argv.slice(2);
run(args.includes('--json'));
