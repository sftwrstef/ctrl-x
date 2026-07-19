import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createAudit, fetchText } from '../server/auditEngine.js';

function waitForAudit(audit, timeoutMs = 10_000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (audit.status === 'complete') return resolve(audit);
      if (audit.status === 'failed') return reject(new Error(audit.error || 'audit failed'));
      if (Date.now() - started > timeoutMs) return reject(new Error('audit timed out'));
      setTimeout(poll, 25);
    };
    poll();
  });
}

test('authorized safe Web audit captures live evidence and bounded findings', async () => {
  const fixture = http.createServer((request, response) => {
    if (request.url === '/.well-known/security.txt' || request.url === '/.env') {
      response.writeHead(404, { 'content-type': 'text/plain' });
      response.end('not found');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html', 'x-fixture-request-method': request.method });
    response.end('<html><head><title>Bug Bunny Fixture</title></head><body><a href="/api">API</a><form></form></body></html>');
  });

  await new Promise((resolve) => fixture.listen(0, '127.0.0.1', resolve));
  const address = fixture.address();
  const target = `http://127.0.0.1:${address.port}/`;

  try {
    assert.throws(() => createAudit({ target, scopeRules: 'local fixture', authorized: false }), /authorized/i);
    const audit = createAudit({ target, scopeRules: 'Local deterministic fixture only.', authorized: true, mode: 'authorized-safe-web' });
    await waitForAudit(audit);
    assert.equal(audit.status, 'complete');
    assert.equal(audit.target.origin, `http://127.0.0.1:${address.port}`);
    assert.equal(audit.evidence.http.status, 200);
    assert.equal(audit.evidence.http.title, 'Bug Bunny Fixture');
    assert.equal(audit.evidence.http.forms, 1);
    assert.ok(audit.evidence.routes.length >= 10);
    assert.ok(audit.evidence.cors);
    assert.ok(audit.findings.some((finding) => finding.title === 'Missing Content-Security-Policy header'));
    assert.ok(audit.findings.every((finding) => finding.poc));
    assert.match(audit.report.markdown, /authorized-safe-web/);
  } finally {
    fixture.closeAllConnections();
    await new Promise((resolve, reject) => fixture.close((error) => error ? reject(error) : resolve()));
  }
});

test('safe fetch blocks cross-origin redirects and oversized bodies', async () => {
  const destination = http.createServer((_request, response) => response.end('outside scope'));
  await new Promise((resolve) => destination.listen(0, '127.0.0.1', resolve));
  const destinationAddress = destination.address();

  const source = http.createServer((request, response) => {
    if (request.url === '/redirect') {
      response.writeHead(302, { location: `http://127.0.0.1:${destinationAddress.port}/` });
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('x'.repeat(1024));
  });
  await new Promise((resolve) => source.listen(0, '127.0.0.1', resolve));
  const sourceAddress = source.address();

  try {
    await assert.rejects(
      fetchText(`http://127.0.0.1:${sourceAddress.port}/redirect`),
      /cross-origin redirect/i
    );
    await assert.rejects(
      fetchText(`http://127.0.0.1:${sourceAddress.port}/large`, { maxBytes: 128 }),
      /response exceeded/i
    );
  } finally {
    source.closeAllConnections();
    destination.closeAllConnections();
    await Promise.all([
      new Promise((resolve, reject) => source.close((error) => error ? reject(error) : resolve())),
      new Promise((resolve, reject) => destination.close((error) => error ? reject(error) : resolve()))
    ]);
  }
});
