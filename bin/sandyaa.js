#!/usr/bin/env node

// Entry point for globally installed sandyaa CLI
// This file is referenced by package.json "bin" field

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import the compiled entry point
await import(join(__dirname, '..', 'dist', 'index.js'));
