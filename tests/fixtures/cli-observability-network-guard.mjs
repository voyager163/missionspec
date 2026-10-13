import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';

let attempted = false;
const reject = () => {
  attempted = true;
  throw new Error('Observability controls must not attempt network delivery');
};
http.request = http.get = https.request = https.get = reject;
globalThis.fetch = reject;
syncBuiltinESMExports();
process.on('exit', () => { if (attempted) process.exitCode = 98; });
