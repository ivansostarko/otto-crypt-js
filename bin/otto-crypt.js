#!/usr/bin/env node
'use strict';

const { OttoCrypt } = require('../src/index.js');
const fs = require('fs');

function usage() {
  console.log(`OTTO Crypt JS (compatible with Laravel package)

Usage:
  otto-crypt encrypt <in> <out> [--password=...] [--recipient=...] [--raw-key=...]
  otto-crypt decrypt <in> <out> [--password=...] [--sender-secret=...] [--raw-key=...]

Examples:
  otto-crypt encrypt in.mp4 out.otto --password="P@ssw0rd!"
  otto-crypt decrypt out.otto out.mp4 --password="P@ssw0rd!"
`);
}

(async () => {
  const args = process.argv.slice(2);
  if (args.length < 1) { usage(); process.exit(1); }

  const cmd = args[0];
  const getOpt = (name) => {
    const p = `--${name}=`;
    const found = args.find(a => a.startsWith(p));
    if (!found) return null;
    return found.substring(p.length);
  };

  const inPath = args[1];
  const outPath = args[2];
  const options = {};

  if (getOpt('password')) options.password = getOpt('password');
  if (getOpt('recipient')) options.recipient_public = getOpt('recipient');
  if (getOpt('raw-key')) options.raw_key = getOpt('raw-key');
  if (getOpt('sender-secret')) options.sender_secret = getOpt('sender-secret');

  const otto = new OttoCrypt();

  try {
    if (cmd === 'encrypt') {
      if (!inPath || !outPath) { usage(); process.exit(1); }
      await otto.encryptFile(inPath, outPath, options);
      console.log(`Encrypted -> ${outPath}`);
    } else if (cmd === 'decrypt') {
      if (!inPath || !outPath) { usage(); process.exit(1); }
      await otto.decryptFile(inPath, outPath, options);
      console.log(`Decrypted -> ${outPath}`);
    } else {
      usage(); process.exit(1);
    }
  } catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
  }
})();
