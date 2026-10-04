// Worker thread for the parallel scan: replays one batch of transcript files
// and posts the raw aggregates back to scan.js, which merges them.
import { parentPort, workerData } from 'worker_threads';
import { collect } from './scan';

(parentPort as import('worker_threads').MessagePort).postMessage(collect(workerData.files, workerData.cfg, Buffer.from(workerData.salt)));
