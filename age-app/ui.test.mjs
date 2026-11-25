// DOM and transport doubles only; no browser, key, or user configuration.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { test } from "node:test";

const source = (await readFile(new URL("web/app.mjs", import.meta.url), "utf8"))
  .replace(/^import .* from "age-encryption";\n/, "");
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b}); return {promise,resolve,reject}; };
const tick = () => new Promise(resolve => setImmediate(resolve));
const page = {title:"Synthetic enrollment",reason:"Enroll the disposable vault key.",done:false,request:{id:"synthetic-step",op:"enroll",step:1,total:3}};

async function harness() {
  const elements = Object.fromEntries(["#title","#reason","#decision-hint","#message","#progress","#continue","#decline"].map(id => [id,{textContent:"",disabled:true,addEventListener(_,cb){this.click=cb}}]));
  const auth = deferred(), waiting = []; let interval;
  const context = vm.createContext({document:{querySelector:id=>elements[id]},location:{hash:"#"+"a".repeat(64)},history:{replaceState(){}},
    webauthn:{createCredential:()=>auth.promise},Stanza:class{},Uint8Array,AbortSignal,setTimeout,clearTimeout,
    btoa:s=>Buffer.from(s,"binary").toString("base64"),atob:s=>Buffer.from(s,"base64").toString("binary"),
    setInterval:cb=>{interval=cb;return 1},clearInterval:()=>{interval=undefined},
    fetch:(url,options)=>{const d=deferred();waiting.push({url,options,...d});return d.promise},
  });
  const running = new vm.Script("(async()=>{"+source+"})()").runInContext(context);
  const respond = (request,value,ok=true) => request.resolve({ok,json:async()=>structuredClone(value)});
  respond(waiting.shift(),page); await running;
  return {elements,auth,waiting,respond,poll:()=>interval?.(),polling:()=>Boolean(interval)};
}

test("the purpose is visible before approval and declining does not need a key", async () => {
  const h = await harness();
  assert.equal(h.elements["#reason"].textContent, page.reason);
  assert.equal(h.elements["#decline"].disabled, false);
  assert.equal(h.elements["#continue"].disabled, false);
});

test("an unchanged step leaves the live status announcement in place",async()=>{
  const h=await harness(), status=h.elements["#message"], text=status.textContent;
  let writes=0;
  Object.defineProperty(status,"textContent",{get:()=>text,set:()=>{writes++}});
  const repeat=h.poll();h.respond(h.waiting.shift(),page);await repeat;
  assert.equal(writes,0);
  assert.equal(h.polling(),true);
});

test("a slow poll cannot re-enable the button during a security-key request",async()=>{
  const h=await harness();const poll=h.poll(),old=h.waiting.shift();
  void h.elements["#continue"].click();
  assert.equal(h.elements["#continue"].disabled,true);
  h.respond(old,page);await poll;
  assert.equal(h.elements["#continue"].disabled,true,"stale poll re-enabled the action while authentication was pending");
});

test("a late poll cannot replace a terminal failure with the previous step",async()=>{
  const h=await harness();const poll=h.poll(),old=h.waiting.shift();
  const click=h.elements["#continue"].click();h.auth.resolve("synthetic-identity");await tick();
  h.respond(h.waiting.shift(),{},false);await click;
  const failure=h.elements["#message"].textContent;
  h.respond(old,page);await poll;
  assert.equal(h.elements["#message"].textContent,failure,"stale poll hid the failure");
  assert.equal(h.elements["#continue"].disabled,true);
});

test("poll requests do not accumulate while an earlier poll is waiting",async()=>{
  const h=await harness();void h.poll();void h.poll();void h.poll();
  assert.equal(h.waiting.length,1);
});

test("decline rejects the active step without calling WebAuthn or reviving an older poll", async () => {
  const h = await harness();
  const stale = h.poll(), old = h.waiting.shift();
  const click = h.elements["#decline"].click();
  const reply = h.waiting.shift();
  assert.equal(reply.url, "/api/reply");
  assert.deepEqual(JSON.parse(reply.options.body), {id:page.request.id, declined:true});
  h.respond(reply, {});
  await click;
  h.respond(old, page);
  await stale;
  assert.match(h.elements["#message"].textContent, /Request declined/);
  assert.equal(h.elements["#reason"].hidden, true);
  assert.equal(h.elements["#decision-hint"].hidden, true);
  assert.equal(h.elements["#continue"].disabled, true);
  assert.equal(h.elements["#decline"].disabled, true);
});

test("verified enrollment explains where to find the credential",async()=>{
  const h=await harness();
  const click=h.elements["#continue"].click();
  h.auth.resolve("synthetic-identity"); await tick();
  h.respond(h.waiting.shift(),{}); await tick();
  h.respond(h.waiting.shift(),{title:page.title,done:true,success:true});
  await click;
  assert.match(h.elements["#message"].textContent,/non-discoverable credential/);
  assert.equal(h.polling(),false);
  const ack = h.waiting.shift();
  assert.equal(ack.url,"/api/poll");
  assert.deepEqual(JSON.parse(ack.options.body),{displayed:true});
  h.respond(ack,{});
});

test("a stale completion poll waits for the active page to display the result", async () => {
  const h = await harness();
  const done = {title:page.title, done:true, success:true};
  const stale = h.poll();
  const oldRequest = h.waiting.shift();
  const click = h.elements["#continue"].click();
  h.respond(oldRequest, done);
  await stale;
  assert.equal(h.waiting.length, 0);
  assert.equal(h.polling(), true);

  h.auth.resolve("synthetic-identity");
  await tick();
  h.respond(h.waiting.shift(), {});
  await tick();
  h.respond(h.waiting.shift(), done);
  await click;
  assert.equal(h.elements["#continue"].textContent, "Completed");
  const receipt = h.waiting.shift();
  assert.deepEqual(JSON.parse(receipt.options.body), {displayed:true});
  h.respond(receipt, {});
});
