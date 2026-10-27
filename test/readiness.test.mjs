import test from 'node:test';
import assert from 'node:assert/strict';
import {checkReadiness} from '../src/readiness.mjs';

test('readiness fails closed without a database or owner', async () => {
  assert.equal(await checkReadiness({configured:false, query:()=>assert.fail('must not query')}), false);
  assert.equal(await checkReadiness({configured:true, query:async()=>({rows:[{ready:false}]})}), false);
});
test('readiness reflects a database failure after a successful probe', async () => {
  let unavailable = false;
  const query = async options => {
    assert.equal(options.query_timeout, 3000);
    if (unavailable) throw new Error('private connection details');
    return {rows:[{ready:true}]};
  };
  assert.equal(await checkReadiness({configured:true, query}), true);
  unavailable = true;
  assert.equal(await checkReadiness({configured:true, query}), false);
});
