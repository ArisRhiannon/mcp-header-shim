#!/usr/bin/env node
'use strict';
require('../src/cli').main(process.argv.slice(2)).then((c) => { if (c !== undefined) process.exitCode = c; });
