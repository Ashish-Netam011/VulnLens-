#!/usr/bin/env node

/**
 * VulnLens CLI entry point.
 * Thin wrapper — all logic lives in src/cli/cli.js.
 */

import { main } from '../src/cli/cli.js';

process.exitCode = await main(process.argv);
