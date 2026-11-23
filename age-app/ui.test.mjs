// DOM and transport doubles only; no browser, key, or user configuration.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { test } from "node:test";

const source = (await readFile(new URL("web/app.mjs", import.meta.url), "utf8"))
  .replace(/^import .* from "age-encryption";\n/, "");
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b}); return {promise,resolve,reject}; };
const tick = () => new Promise(resolve => setImmediate(resolve));
const page = {title:"Synthetic enrollment",done:false,request:{id:"synthetic-step",op:"enroll",step:1,total:3}};

async function harness() {
  const elements = Object.fromEntries(["#title","#message","#progress","#continue","#decline"].map(id => [id,{textContent:"",disabled:true,addEventListener(_,cb){this.click=cb}}]));
  const auth = deferred(), waiting = []; let interval;
  const context = vm.createContext({document:{querySelector:id=>elements[id]},location:{hash:"#"+"a".repeat(64)},history:{replaceState(){}},
    webauthn:{createCredential:()=>auth.promise},Stanza:class{},Uint8Array,AbortSignal,setTimeout,clearTimeout,
    btoa:s=>Buffer.from(s,"binary").toString("base64"),atob:s=>Buffer.from(s,"base64").toString("binary"),
    setInterval:cb=>{interval=cb},fetch:(url,options)=>{const d=deferred();waiting.push({url,options,...d});return d.promise},
  });
  const running = new vm.Script("(async()=>{"+source+"})()").runInContext(context);
  const respond = (request,value,ok=true) => request.resolve({ok,json:async()=>structuredClone(value)});
  respond(waiting.shift(),page); await running;
  return {elements,auth,waiting,respond,poll:()=>interval()};
}

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
  assert.deepEqual(JSON.parse(reply.options.body), {id:page.request.id, failed:true});
  h.respond(reply, {});
  await click;
  h.respond(old, page);
  await stale;
  assert.match(h.elements["#message"].textContent, /Request declined/);
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
});
