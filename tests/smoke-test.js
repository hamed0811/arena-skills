import assert from 'node:assert/strict';
import {startTestServer} from './helpers/test-server.js';
const server=await startTestServer();
try{const response=await fetch(server.baseUrl+'/api/health');assert.equal(response.status,200);const data=await response.json();assert.equal(data.status,'ok');console.log('Smoke test passed: API health is healthy.');}
finally{await server.close();}
