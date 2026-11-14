import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {deriveKeys, encryptEntry, decryptEntry, generatePassword, passwordEntropy, randomSalt, newSecret} from '../src/main/resources/static/lib/crypto.js';

const email = 'alice@example.com', master = 'a long private master passphrase';
test('AES-GCM round trip, random IV, tamper protection, account and record binding', async () => {
  const salt = randomSalt(), secret = newSecret();
  const {key,authKey} = await deriveKeys(master,secret,salt,email);
  assert.equal(Buffer.from(authKey,'base64').length,32);
  const id = crypto.randomUUID(), value = {title:'Mail', origin:'https://mail.google.com', login:email, password:'S3cret!password', notes:'Заметка'};
  const encrypted = await encryptEntry(key,email,id,value);
  const second = await encryptEntry(key,email,id,value);
  assert.notEqual(encrypted.iv,second.iv); assert.notEqual(encrypted.ciphertext,second.ciphertext);
  assert.deepEqual(await decryptEntry(key,email,{id,revision:1,...encrypted}),{...value,id,revision:1});
  await assert.rejects(decryptEntry(key,'bob@example.com',{id,...encrypted}));
  await assert.rejects(decryptEntry(key,email,{id:crypto.randomUUID(),...encrypted}));
  const changed = Buffer.from(encrypted.ciphertext,'base64'); changed[0] ^= 1;
  await assert.rejects(decryptEntry(key,email,{id,...encrypted,ciphertext:changed.toString('base64')}));
  const wrong = await deriveKeys(master,newSecret(),salt,email);
  assert.notEqual(wrong.authKey,authKey);
  await assert.rejects(decryptEntry(wrong.key,email,{id,...encrypted}));
  const same = await deriveKeys(master,secret,salt,email);
  assert.equal(same.authKey,authKey);
  const wrongMaster = await deriveKeys(master+'x',secret,salt,email);
  assert.notEqual(wrongMaster.authKey,authKey);
  await assert.rejects(decryptEntry(wrongMaster.key,email,{id,...encrypted}));
});
test('generator uses the specified alphabet and length and avoids existing passwords', () => {
  for (const [alphabet, pattern] of Object.entries({digits:/^[0-9]+$/, lowercase:/^[a-z]+$/, alphanumeric:/^[a-zA-Z0-9]+$/, ascii:/^[\x20-\x7e]+$/})) {
    const seen = [];
    for (const length of [6, 10, 24, 128]) {
      for (let i = 0; i < 10; i++) {
        const password = generatePassword(length, seen, alphabet);
        assert.equal(password.length, length);
        assert.match(password, pattern);
        assert(!seen.includes(password));
        seen.push(password);
      }
    }
  }
  for (const length of [0,5,129,24.5,NaN]) assert.throws(() => generatePassword(length));
  assert.throws(() => generatePassword(24, [], 'toString'));
});
test('entropy uses the generator alphabet when known and character groups otherwise', () => {
  for (const [alphabet, size] of [['digits',10], ['lowercase',26], ['alphanumeric',62], ['ascii',95]]) {
    const sample = alphabet === 'digits' ? '123456' : 'abcdef';
    assert.deepEqual(passwordEntropy(sample, alphabet), {length:6, alphabetSize:size, bits:6 * Math.log2(size)});
  }
  assert.deepEqual(passwordEntropy('aaaaaa'), {length:6, alphabetSize:26, bits:6 * Math.log2(26)});
  assert.deepEqual(passwordEntropy('aA0! 😀😀'), {length:7, alphabetSize:96, bits:7 * Math.log2(96)});
  assert.deepEqual(passwordEntropy(''), {length:0, alphabetSize:0, bits:0});
});
test('extension and web use identical shared security modules', async () => {
  for (const file of ['crypto.js','origin.js','api.js']) assert.equal(await readFile(new URL(`../extension/lib/${file}`,import.meta.url),'utf8'),await readFile(new URL(`../src/main/resources/static/lib/${file}`,import.meta.url),'utf8'));
});
