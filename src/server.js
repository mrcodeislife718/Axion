import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { createAxionHandler } from './http-app.js';

export async function startAxionServer({ port = Number(process.env.PORT || 3000), host = process.env.HOST || '127.0.0.1' } = {}) {
  const server = http.createServer(createAxionHandler());
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const server = await startAxionServer();
  const address = server.address();
  console.log(`Axion listening on ${typeof address === 'object' && address ? address.port : process.env.PORT || 3000}`);
}
