import {test} from 'node:test';
import assert from 'node:assert/strict';
import {trustedOrigin,assertMatch,DOMAIN_ERROR} from '../src/main/resources/static/lib/origin.js';
test('DNS case is insensitive, paths do not affect origin, default port is canonical', () => {
  assert.equal(trustedOrigin('https://mail.gOOgle.com/inbox?x=1'),'https://mail.google.com');
  assertMatch('https://mail.google.com','https://mail.gOOgle.com:443/inbox');
});
test('lookalikes, suffixes, ports, subdomains and HTTP never match', () => {
  for (const url of ['https://mail.go0gle.com','https://mail.google.com.attacker.org','https://google.com','https://accounts.google.com','http://mail.google.com','https://mail.google.com:444','https://mail.gоogle.com','https://xn--80ak6aa92e.com','https://mail.google.com.','https://mail.google.com@attacker.org'])
    assert.throws(() => assertMatch('https://mail.google.com',url),{message:DOMAIN_ERROR});
});
test('ambiguous and malformed addresses fail closed', () => {
  for (const url of ['javascript:alert(1)','https://user:pass@mail.google.com','https://%6dail.google.com','https://mail.google.com\\@attacker.org',' https://mail.google.com','https://mail.google.com\n','https://localhost','https://-mail.google.com','https://mail..google.com','https://[::1]'])
    assert.throws(() => trustedOrigin(url));
});
