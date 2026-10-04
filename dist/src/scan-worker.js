"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Worker thread for the parallel scan: replays one batch of transcript files
// and posts the raw aggregates back to scan.js, which merges them.
const worker_threads_1 = require("worker_threads");
const scan_1 = require("./scan");
worker_threads_1.parentPort.postMessage((0, scan_1.collect)(worker_threads_1.workerData.files, worker_threads_1.workerData.cfg, Buffer.from(worker_threads_1.workerData.salt)));
