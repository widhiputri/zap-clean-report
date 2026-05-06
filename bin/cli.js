#!/usr/bin/env node

const fs   = require('fs');
const path = require('path');
const { generateReport } = require('../src/report');

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Usage:
  zap-clean-report <input.json> [options]

Options:
  --output, -o <file>   Output file path (overrides auto-generated name)
  --title  <text>       Report title (default: Security Scan Report)
  --help,  -h           Show this help

Examples:
  zap-clean-report zap-output.json
  zap-clean-report zap-output.json --output my-report.html
  zap-clean-report zap-output.json --title "My App - Sprint 22"

Auto-generated filename format:
  <hostname>-<UTC timestamp>-security-report.html
  e.g. app.example.com-20260504164752-security-report.html
`);
  process.exit(0);
}

const inputFile  = args[0];
let   outputFile = null;
let   title      = null;

for (let i = 1; i < args.length; i++) {
  if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) {
    outputFile = args[++i];
  } else if (args[i] === '--title' && args[i + 1]) {
    title = args[++i];
  }
}

function utcTimestamp() {
  return new Date().toISOString().replace(/\D/g, '').slice(0, 14);
}

function targetHostname(raw) {
  const sites = raw.site || [];
  if (!sites.length) return 'scan';
  const name = sites[0]['@name'] || sites[0]['@host'] || 'scan';
  try { return new URL(name).hostname; } catch { return name.replace(/[^a-zA-Z0-9.-]/g, '-'); }
}

if (!fs.existsSync(inputFile)) {
  console.error(`Error: file not found: ${inputFile}`);
  process.exit(1);
}

let raw;
try {
  raw = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
} catch (e) {
  console.error(`Error: could not parse JSON: ${e.message}`);
  process.exit(1);
}

if (!outputFile) {
  outputFile = `${targetHostname(raw)}-${utcTimestamp()}-security-report.html`;
}

const html = generateReport(raw, { title });
fs.writeFileSync(outputFile, html, 'utf8');
console.log(`Report written to: ${path.resolve(outputFile)}`);
