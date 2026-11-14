import {test} from 'node:test';
import assert from 'node:assert/strict';
import {deriveKeys,encryptEntry,newSecret,randomSalt,b64} from '../src/main/resources/static/lib/crypto.js';

test('background gates credentials by sender, frame, origin, port, current navigation and session', async () => {
  let listener, vault, sent = [], tab = {id:7,url:'https://mail.google.com/'};
  const email = 'extension@example.com';
  const {key} = await deriveKeys('a sufficiently long master passphrase',newSecret(),randomSalt(),email,true);
  const id = crypto.randomUUID();
  const encrypted = {id,revision:1,...await encryptEntry(key,email,id,{title:'Mail',origin:'https://mail.google.com',login:email,password:'Private!Password123'})};
  const reset = () => vault = {email,token:'test-token',key:null,until:Date.now()+300000,expiresAt:new Date(Date.now()+1800000).toISOString()};
  reset(); vault.key = b64(new Uint8Array(await crypto.subtle.exportKey('raw',key)));
  const originalVault = structuredClone(vault);
  const popup = {id:'guard',url:'chrome-extension://guard/popup.html'};
  const content = {id:'guard',url:tab.url,tab:{id:7},frameId:0};
  globalThis.chrome = {
    storage:{session:{setAccessLevel:async()=>{},get:async()=>({vault}),set:async value=>{vault=value.vault;},remove:async()=>{vault=undefined;}}},
    action:{setBadgeText:async()=>{}}, alarms:{onAlarm:{addListener:()=>{}},create:async()=>{},clear:async()=>{}},
    runtime:{id:'guard',getURL:path=>`chrome-extension://guard/${path}`,onMessage:{addListener:fn=>{listener=fn;}}},
    tabs:{get:async()=>tab,query:async()=>[tab],sendMessage:async(...args)=>{sent.push(args);return {ok:true};}}
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async url => new Response(JSON.stringify(url.endsWith('/entries') ? [encrypted] : {}),{headers:{'Content-Type':'application/json'}});
  try {
    await import('../extension/background.js');
    const send = (message,sender) => new Promise(resolve=>listener(message,sender,resolve));
    const suggestion = await send({type:'suggest'},content);
    assert.deepEqual(suggestion,{ok:true,data:[{id,title:'Mail'}]});
    assert(!JSON.stringify(suggestion).includes('Private!Password123'));
    const filled = await send({type:'fill',id},content);
    assert.equal(filled.data.password,'Private!Password123');
    for (const url of ['https://mail.go0gle.com','https://mail.google.com.attacker.org','https://mail.google.com:444','http://mail.google.com']) {
      tab = {id:7,url};
      const result = await send({type:'manual-fill',id},popup);
      assert.equal(result.ok,false); assert.match(result.error,/Данный домен/);
    }
    assert.equal(sent.length,0);
    tab = {id:7,url:'https://mail.google.com',pendingUrl:'https://attacker.org'};
    assert.equal((await send({type:'fill',id},content)).ok,false);
    tab = {id:7,url:'https://mail.gOOgle.com/inbox'};
    assert.equal((await send({type:'manual-fill',id},popup)).ok,true);
    assert.equal(sent.length,1);
    assert.equal(sent[0][1].password,'Private!Password123');
    assert.equal((await send({type:'fill',id},{...content,frameId:1})).ok,false);
    assert.equal((await send({type:'list'},content)).ok,false);
    assert.equal((await send({type:'unlock'},content)).ok,false);
    assert.equal((await send({type:'list'},{...popup,id:'evil'})).ok,false);
    vault = {...originalVault,until:Date.now()-1};
    assert.equal((await send({type:'fill',id},content)).ok,false);
    assert.equal(vault,undefined);
  } finally { globalThis.fetch = originalFetch; delete globalThis.chrome; }
});
