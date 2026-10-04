'use strict';
// Worker thread for the parallel scan: replays one batch of transcript files
// and posts the raw aggregates back to scan.js, which merges them.
const { parentPort, workerData } = require('worker_threads');
const { collect } = require('./scan');
/** @type {import('worker_threads').MessagePort} */ (parentPort).postMessage(collect(workerData.files, workerData.cfg, Buffer.from(workerData.salt)));
