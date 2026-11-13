import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { pairRemote } from '../src/envs.js';

function server(handler) {
  return new Promise((resolve) => {
    const s = http.createServer((req, res) => {
      let body = '';
      req.on('data', (d) => (body += d)).on('end', () => handler(req, new URLSearchParams(body), res));
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

test('pairRemote trades a pairing code for a scoped bearer session', async (t) => {
  const sid = 'session-1';
  const token = `${Buffer.from(JSON.stringify({ sid })).toString('base64url')}.sig`;
  let seen;
  const s = await server((req, form, res) => {
    seen = { path: req.url, form: Object.fromEntries(form) };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ access_token: token, issued_token_type: 'x', token_type: 'Bearer', expires_in: 3600, scope: 'orchestration:read orchestration:operate' }));
  });
  t.after(() => s.close());

  const tok = await pairRemote(`http://127.0.0.1:${s.address().port}/`, 'CODE1234', 'WoW bridge (test)');
  assert.equal(seen.path, '/oauth/token');
  assert.equal(seen.form.grant_type, 'urn:ietf:params:oauth:grant-type:token-exchange');
  assert.equal(seen.form.subject_token, 'CODE1234');
  assert.equal(seen.form.subject_token_type, 'urn:t3:params:oauth:token-type:environment-bootstrap');
  assert.equal(seen.form.scope, 'orchestration:read orchestration:operate');
  assert.equal(tok.token, token);
  assert.equal(tok.sessionId, sid);
  assert.deepEqual(tok.scopes, ['orchestration:read', 'orchestration:operate']);
  assert.ok(Math.abs(Date.parse(tok.expiresAt) - Date.now() - 3600_000) < 5000);
});

test('pairRemote explains a refused code', async (t) => {
  const s = await server((req, form, res) => {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'invalid_grant' }));
  });
  t.after(() => s.close());
  await assert.rejects(pairRemote(`http://127.0.0.1:${s.address().port}/`, 'OLD'), /refused the pairing code \(invalid_grant\)/);
});
