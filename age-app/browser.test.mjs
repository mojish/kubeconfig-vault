// Synthetic data only. Explicit temporary state/config, virtual authenticator,
// disposable Chrome profile, and loopback API. Never use default helper state.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { mkdtemp, copyFile, readFile, readlink, realpath, rename, symlink, writeFile, rm, readdir, chmod, stat } from "node:fs/promises";
import https from "node:https";
import http from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";
import { clientCertificateFixture } from "./test-support/client-certificate.mjs";
import { chromeConnection } from "./test-support/cdp.mjs";

const cwd = fileURLToPath(new URL(".", import.meta.url));
const root = await mkdtemp(join(tmpdir(), "kua-"));
let state = join(root, "state");
const legacyExecutable = join(root, "kube-unlock-age");
let executable = legacyExecutable;
const launcher = join(root,"browser"), urlsFile = join(root,"urls");
const recovery = join(root,"offline-key"), source = join(root,"source"), children = [];
const tokenA = "SYNTHETIC-AGE-TOKEN-ONE", tokenB = "SYNTHETIC-AGE-TOKEN-TWO";
let acceptedToken = tokenA, server, certificateAPI, failure;
const timeout = setTimeout(() => { failure = new Error("Synthetic integration timed out");for(const p of children)p.kill("SIGKILL");server?.closeAllConnections();server?.close(); },420000);

function launch(args, { terminal = false, program: cliProgram = executable, ...extra } = {}) {
  const command = [cliProgram, "--state-dir", state, "--browser", launcher, ...args];
  // Capture the synthetic key in a disposable pseudo-terminal. Never print the transcript.
  const terminalCommand = ["python3", "-c", "import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))", ...command];
  const [program, ...argv] = terminal ? terminalCommand : command;
  const p = spawn(program, argv, {stdio:[terminal ? "pipe" : "ignore","pipe","pipe"],...extra});
  children.push(p);let stdout="",stderr="";const result={done:false,child:p,get output(){return stdout}};
  p.stdout.on("data",b=>stdout+=b);p.stderr.on("data",b=>stderr+=b);
  result.promise = new Promise((resolve,reject)=>{p.once("error",reject);p.once("exit",code=>{result.done=true;result.code=code;result.stdout=stdout;result.stderr=stderr;resolve(result)})});
  return result;
}
async function cli(...args){const r=await launch(args).promise;if(r.code!==0)throw new Error("Synthetic CLI failed: "+r.stderr);return r.stdout;}
async function waitFor(fn, label, iterations=150){for(let i=0;i<iterations;i++){if(failure)throw failure;const result=await fn();if(result)return result;await delay(50)}throw new Error("Timed out: "+label)}
async function urls(){try{return(await readFile(urlsFile,"utf8")).trim().split("\n").filter(Boolean)}catch{return[]}}
async function bootstrapTarget(uri){
  const file=new URL(uri);assert.equal(file.protocol,"file:");assert.equal(file.hash,"");
  const path=fileURLToPath(file);assert.equal((await stat(path)).mode&0o777,0o600);
  const target=(await readFile(path,"utf8")).match(/0;url=([^"<>]+)/)?.[1];
  assert.ok(target?.startsWith("http://localhost:"));return target;
}

async function startCertificateAPI(certificate, privateKey) {
  const fixture = await clientCertificateFixture(root);
  const { clientCert, clientKey } = fixture;
  const mtls = https.createServer({cert:certificate,key:privateKey,...fixture.tls},(req,res)=>{
    if (!fixture.accepts(req)) {
      res.writeHead(403).end();
      return;
    }
    res.writeHead(200,{"Content-Type":"application/json"}).end('{"gitVersion":"v1.mtls"}');
  });
  mtls.on("tlsClientError", error => {
    console.error("Synthetic mutual TLS handshake failed:",error.code,error.reason || error.message);
  });
  await new Promise((resolve,reject)=>{mtls.once("error",reject);mtls.listen(0,"127.0.0.1",resolve)});
  return {mtls,clientCert,clientKey};
}

try {
  if (process.env.KUBE_UNLOCK_TEST_BINARY) {
    await copyFile(process.env.KUBE_UNLOCK_TEST_BINARY,executable);
    await chmod(executable,0o700);
  } else {
    await build({absWorkingDir:cwd,entryPoints:["web/app.mjs"],outfile:"web/app.js",bundle:true,format:"esm",platform:"browser",target:"es2023",legalComments:"inline"});
    const compiled=spawnSync("go",["build","-race","-o",executable,"."],{cwd,encoding:"utf8",timeout:60000,env:{...process.env,GOTOOLCHAIN:"local",GOPROXY:"off",GOPATH:process.env.GOPATH||join(tmpdir(),"kube-unlock-go-path"),GOCACHE:process.env.GOCACHE||join(tmpdir(),"kube-unlock-go-cache")}});
    if(compiled.status!==0)throw new Error("Native integration build failed: "+compiled.stderr);
  }
  // Keep the generated exec command at the same path across a real upgrade.
  const previous = process.env.KUBE_UNLOCK_TEST_PREVIOUS_BINARY;
  const candidate = join(root, "candidate");
  if (previous) {
    await rename(executable, candidate);
    await copyFile(previous, executable);
    await chmod(executable, 0o700);
  }
  await writeFile(launcher,`#!${process.execPath}\nimport('node:fs').then(fs=>fs.appendFileSync(${JSON.stringify(urlsFile)},process.argv[2]+'\\n',{mode:0o600}));\n`,{mode:0o700});
  const cert=join(root,"cert.pem"),key=join(root,"key.pem");
  const generated=spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-subj","/CN=localhost","-days","1","-addext","subjectAltName=IP:127.0.0.1"],{encoding:"utf8",timeout:15000});
  assert.equal(generated.status,0,"synthetic TLS fixture generation failed");
  const certificate=await readFile(cert),privateKey=await readFile(key);
  server=https.createServer({key:privateKey,cert:certificate},(req,res)=>{
    if(req.headers.authorization!==`Bearer ${acceptedToken}`){res.writeHead(401).end();return}
    res.writeHead(200,{"Content-Type":"application/json"});res.end(JSON.stringify({gitVersion:"v1.32.0"}));
  });
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve)});
  const sourceObject={apiVersion:"v1",kind:"Config",clusters:[{name:"synthetic",cluster:{server:`https://127.0.0.1:${server.address().port}`,"certificate-authority-data":certificate.toString("base64")}}],users:[{name:"synthetic",user:{token:tokenA}}],contexts:[{name:"synthetic",context:{cluster:"synthetic",user:"synthetic"}}],"current-context":"synthetic",preferences:{colors:true}};
  sourceObject.clusters.push({name:"second",cluster:{...sourceObject.clusters[0].cluster,server:sourceObject.clusters[0].cluster.server+"/second"}});
  sourceObject.contexts.push({name:"second",context:{cluster:"second",user:"synthetic"}});
  const {mtls,clientCert,clientKey} = await startCertificateAPI(certificate,privateKey);
  certificateAPI = mtls;
  const certificateCluster = {server:`https://127.0.0.1:${mtls.address().port}`,"certificate-authority-data":certificate.toString("base64")};
  const certificateUser = {"client-certificate-data":clientCert.toString("base64"),"client-key-data":clientKey.toString("base64")};
  // Establish that the test issuer and client fixture work on this OS before exercising the vault.
  const directConfig = join(root,"plain-mtls");
  const direct = structuredClone(sourceObject);
  direct.users[0].user = certificateUser;
  direct.clusters[0].cluster = certificateCluster;
  await writeFile(directConfig,JSON.stringify(direct),{mode:0o600});
  const plainClient = spawn(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl",
    ["--kubeconfig",directConfig,"--context","synthetic","get","--raw=/version","--request-timeout=15s"],
    {stdio:["ignore","ignore","pipe"]});
  children.push(plainClient);
  let diagnostic = "";
  plainClient.stderr.on("data",buf=>diagnostic+=buf);
  const [plainCode] = await once(plainClient,"exit");
  assert.equal(plainCode,0,"plaintext fixture failed mutual TLS before vault setup: "+diagnostic);
  console.log("PASS: synthetic client and issuer work with kubectl before enrollment.");
  const original=JSON.stringify(sourceObject,null,2);await writeFile(source,original,{mode:0o600});
  const fresh = JSON.parse(await cli("status", "--json"));
  assert.equal(fresh.configured, false);
  assert.equal(fresh.helper_running, false);
  await assert.rejects(stat(state), {code:"ENOENT"});
  const missingConfig = await launch(["path", "kubeconfig"]).promise;
  assert.equal(missingConfig.code, 1);
  assert.equal(missingConfig.stdout, "");
  assert.match(missingConfig.stderr, previous ? /run import first/ : /kubeconfig-vault setup/);
  await assert.rejects(stat(state), { code: "ENOENT" });
  const prematureLink = await launch(["config", "link", "--kubeconfig", source]).promise;
  assert.equal(prematureLink.code, 1);
  assert.equal(await readFile(source, "utf8"), original);
  await assert.rejects(stat(source + ".before-kubeconfig-vault"), { code: "ENOENT" });
  let daemonLog = "";
  async function startDaemon() {
    const child = spawn(executable, ["--state-dir",state,"--browser",launcher,"serve"], {stdio:["ignore","ignore","pipe"]});
    children.push(child);
    child.stderr.on("data", chunk => daemonLog += chunk);
    await waitFor(async()=>{try{return(await stat(join(state,"session.sock"))).isSocket()}catch{return false}},"private daemon socket");
    return child;
  }
  let daemon = await startDaemon();
  const nonInteractive = await launch(["import", source], { detached: true }).promise;
  assert.equal(nonInteractive.code, 1);
  assert.match(nonInteractive.stderr, /terminal is required/);
  const abandoned = launch(["import", source], { terminal: true });
  await waitFor(() => abandoned.output.includes("Press Enter to show it"), "recovery reveal prompt");
  assert.ok(!abandoned.output.includes("AGE-SECRET-KEY-"));
  abandoned.child.stdin.write("\n");
  await waitFor(() => abandoned.output.includes("Type saved"), "recovery confirmation prompt");
  assert.deepEqual(await urls(), []);
  abandoned.child.stdin.write("verify\n");
  await waitFor(() => abandoned.output.includes("input is hidden"), "hidden confirmation prompt");
  abandoned.child.stdin.end("invalid-synthetic-copy\r");
  assert.equal((await abandoned.promise).code, 1);
  assert.ok(!abandoned.output.includes("invalid-synthetic-copy"));
  await assert.rejects(stat(join(state, "current")), { code: "ENOENT" });
  assert.deepEqual(await urls(), []);
  const {call:cdp,events}=chromeConnection(join(root,"chrome"),children);
  const {targetId}=await cdp("Target.createTarget",{url:"about:blank"});
  const {sessionId}=await cdp("Target.attachToTarget",{targetId,flatten:true});
  const call=(method,params={})=>cdp(method,params,sessionId);
  const evaluate=async expression=>{const r=await call("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(r.exceptionDetails)throw new Error("Synthetic page evaluation failed");return r.result.value};
  await call("Page.enable");await call("Runtime.enable");await call("Network.enable");await call("WebAuthn.enable",{enableUI:false});
  const virtualKeyOptions = {protocol:"ctap2",ctap2Version:"ctap2_1",transport:"usb",hasResidentKey:false,
    hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true};
  const originalKey = await call("WebAuthn.addVirtualAuthenticator", {options:virtualKeyOptions});
  let navigated=0; const visibleSteps = new Set();
  async function complete(operation, buttonId = "continue"){
    await waitFor(async()=>{
      const opened=await urls();
      if(opened.length>navigated){
        navigated=opened.length;
        const bootstrap=opened.at(-1);
        const destination=new URL(await bootstrapTarget(bootstrap));
        const start=events.length;
        await call("Page.navigate",{url:bootstrap});
        // The file page immediately redirects. Wait for the localhost document
        // before issuing Runtime.evaluate into an execution context Chrome is replacing.
        await waitFor(()=>events.slice(start).some(event=>
          event.sessionId===sessionId && event.method==="Page.frameNavigated" &&
          event.params.frame.url.split("#")[0]===destination.origin+"/"
        ),"localhost browser navigation");
      }
      if(operation.done)return true;
      if(await evaluate("document.body?.textContent.trim()==='Forbidden'"))throw new Error("Private-file redirect was rejected by HTTP navigation checks");
      const step=await evaluate(`(()=>{const b=document.getElementById(${JSON.stringify(buttonId)});if(b&&!b.disabled){const step=document.querySelector('#progress').textContent;b.click();return step}})()`);
      if(step)visibleSteps.add(step);return false;
    },"browser operation",500);
    return await operation.promise;
  }
  async function successful(operation){const r=await complete(operation);if(r.code!==0)throw new Error("Synthetic browser/CLI operation failed: "+r.stderr);return r}
  const clientAlias = join(root,"config-alias");
  await symlink("source",clientAlias);
  const importing = launch(["setup", clientAlias], { terminal: true });
  await waitFor(() => importing.output.includes("Press Enter to show it"), "recovery reveal prompt");
  importing.child.stdin.write("\n");
  await waitFor(() => importing.output.includes("Type saved"), "recovery confirmation prompt");
  const savedKey = importing.output.match(/\bAGE-SECRET-KEY-[A-Z0-9-]+\b/)?.[0];
  assert.ok(savedKey, "No synthetic recovery key was shown");
  assert.deepEqual(await urls(), []);
  importing.child.stdin.write("verify\n");
  await waitFor(() => importing.output.includes("input is hidden"), "hidden confirmation prompt");
  importing.child.stdin.end(savedKey + "\r");
  await successful(importing);
  assert.match(importing.stdout,/Security key verified/);
  assert.equal(importing.output.split(savedKey).length - 1, 1, "verification echoed the recovery key");
  await assert.rejects(stat(recovery), { code: "ENOENT" });
  for(const step of ["Step 1 of 3","Step 2 of 3","Step 3 of 3"])assert.ok(visibleSteps.has(step),"Missing enrollment progress step");
  assert.equal(await readlink(clientAlias),"source");
  const generatedConfig = (await cli("path", "kubeconfig")).trimEnd();
  const encryptedVault = (await cli("path", "vault")).trimEnd();
  const initialGeneration=await readFile(encryptedVault);
  assert.ok(initialGeneration.subarray(0,22).toString().startsWith("age-encryption.org/v1"));
  const projection = await readFile(generatedConfig, "utf8");
  assert.ok(!projection.includes(tokenA) && !projection.includes("preferences:"));
  console.log("PASS: setup verifies both recipients and switches the client after recovery confirmation.");

  await cli("config", "link", "--kubeconfig", source);
  assert.equal(await readlink(source), generatedConfig);
  const rollback = source + ".before-kubeconfig-vault.age";
  assert.deepEqual(await readFile(rollback), initialGeneration);
  await assert.rejects(stat(source + ".before-kubeconfig-vault"), {code:"ENOENT"});
  assert.match(await cli("setup",source),/Already set up/);

  // Reproduce the install layout change with this disposable, already-enrolled vault.
  assert.ok(projection.includes(legacyExecutable));
  kubectlConfig("use-context", "second");
  const oldDaemonExit = once(daemon, "exit");
  await cli("stop");
  await oldDaemonExit;
  executable = join(root, "kubeconfig-vault");
  if (previous) {
    await rm(legacyExecutable);
    await rename(candidate, executable);
  } else {
    await rename(legacyExecutable, executable);
  }
  await symlink("kubeconfig-vault", legacyExecutable);
  for (const command of ["lock", "stop"]) {
    assert.equal(JSON.parse(await cli(command)).fully_locked, true);
    assert.equal(JSON.parse(await cli("status")).helper_running, false);
  }
  daemon = await startDaemon();

  const pagesBeforeInvalidSetup = (await urls()).length;
  const invalidSource = join(root, "unsupported-input");
  const redactionMarker = "SYNTHETIC-PRIVATE-INPUT";
  for (const [field, change] of [
    ["tokenFile", c => { c.users[0].user = {tokenFile:redactionMarker}; }],
    ["user.exec", c => { c.users[0].user = {exec:{command:redactionMarker,env:[{name:"EXAMPLE",value:redactionMarker}]}}; }],
    ["proxy-url", c => { c.clusters[0].cluster["proxy-url"] = "https://proxy.invalid/?q="+redactionMarker; }],
  ]) {
    const invalid = structuredClone(sourceObject);
    change(invalid);
    await writeFile(invalidSource, JSON.stringify(invalid), {mode:0o600});
    const rejected = launch(["setup",invalidSource]);
    await waitFor(async () => {
      assert.equal((await urls()).length, pagesBeforeInvalidSetup, "unsupported setup opened a browser");
      return rejected.done;
    }, "redacted setup diagnostic");
    await rejected.promise;
    assert.equal(rejected.code, 1);
    assert.ok(rejected.stderr.includes(field));
    assert.ok(!(rejected.stdout+rejected.stderr).includes(redactionMarker));
  }
  assert.equal((await urls()).length, pagesBeforeInvalidSetup);

  const kube=(context="synthetic", kubeconfig=source)=>{
    const p=spawn(process.env.KUBE_UNLOCK_TEST_KUBECTL||"kubectl",["--context",context,"--cache-dir",join(root,"kubecache"),"get","--raw=/version","--request-timeout=30s"],{env:{...process.env,KUBECONFIG:kubeconfig},stdio:["ignore","pipe","pipe"]});
    children.push(p);let stdout="",stderr="";const result={done:false};p.stdout.on("data",b=>stdout+=b);p.stderr.on("data",b=>stderr+=b);result.promise=new Promise((resolve,reject)=>{p.once("error",reject);p.once("exit",code=>{result.done=true;Object.assign(result,{code,stdout,stderr});resolve(result)})});return result;
  };
  function kubectlConfig(...args) {
    const result = spawnSync(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl",
      ["--kubeconfig",source,"config",...args], {encoding:"utf8"});
    assert.equal(result.status, 0, "synthetic kubectl config command failed");
    return result.stdout.trim();
  }
  // An independently imported client can retain settings from before a save.
  const staleClient = join(root, "stale-client");
  await copyFile(generatedConfig, staleClient);
  const staleSettings = spawnSync(process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl",
    ["--kubeconfig", staleClient, "config", "set-cluster", "synthetic", "--tls-server-name=old.example.invalid"]);
  assert.equal(staleSettings.status, 0);
  const pagesBeforeStale = (await urls()).length;
  const stale = await kube("synthetic", staleClient).promise;
  assert.notEqual(stale.code, 0);
  assert.match(stale.stderr, /credential is not approved for this cluster/);
  assert.equal((await urls()).length, pagesBeforeStale);
  const afterStale = JSON.parse(await cli("status"));
  assert.equal(afterStale.unlocked, false);
  assert.equal(afterStale.automatic_unlock_paused_until, undefined);
  const before=(await urls()).length,first=kube(),second=kube("second");
  assert.equal(JSON.parse((await successful(first)).stdout).gitVersion,"v1.32.0");assert.equal((await second.promise).code,0);
  assert.equal((await urls()).length,before+1);
  console.log("PASS: a stale kubectl config failed before opening the browser; the next approved client unlocked normally.");
  if (previous) console.log("PASS: upgraded an existing vault after kubectl rewrote the previous version's linked config.");
  kubectlConfig("set-context", "--current", "--namespace", "vault-test");
  const warm=kube();assert.equal((await warm.promise).code,0);assert.equal((await urls()).length,before+1);
  const cached=JSON.parse(await cli("status"));assert.equal(cached.unlocked,true);assert.ok(Date.parse(cached.expires_at)-Date.now()>3500000);
  assert.deepEqual(await evaluate("[localStorage.length,sessionStorage.length]"),[0,0]);
  console.log("PASS: real kubectl to synthetic HTTPS API, concurrent unlock sharing, one-hour cache, empty browser storage.");

  // A rejected browser request produces one failed unlock for two different clusters.
  await cli("lock");
  const dismiss = await call("Page.addScriptToEvaluateOnNewDocument", {
    source: "Object.defineProperty(navigator.credentials,'get',{value:async()=>{throw new DOMException('Dismissed by test','NotAllowedError')}})"
  });
  const dismissBefore=(await urls()).length, left=kube(), right=kube("second");
  await complete(left);
  assert.notEqual(left.code,0);
  assert.notEqual((await right.promise).code,0);
  assert.equal((await urls()).length,dismissBefore+1);
  const devicePause = JSON.parse(await cli("status"));
  const deviceRemaining = Date.parse(devicePause.automatic_unlock_paused_until) - Date.now();
  assert.equal(devicePause.unlocked, false);
  assert.ok(deviceRemaining > 0 && deviceRemaining <= 30000);
  await call("Page.removeScriptToEvaluateOnNewDocument",{identifier:dismiss.identifier});
  await successful(launch(["unlock"]));
  console.log("PASS: two clusters share one approval; a dismissed prompt produces one page and explicit unlock can retry immediately.");

  await cli("lock");
  const beforeDecline = (await urls()).length, declined = kube(), queued = kube("second");
  await complete(declined, "decline");
  assert.notEqual(declined.code, 0);
  assert.notEqual((await queued.promise).code, 0);
  assert.equal((await urls()).length, beforeDecline + 1);
  const paused = JSON.parse(await cli("status"));
  const remaining = Date.parse(paused.automatic_unlock_paused_until) - Date.now();
  assert.equal(paused.unlocked, false);
  assert.ok(remaining > 570000 && remaining <= 600000);
  for (const retry of await Promise.all([kube().promise, kube("second").promise])) {
    assert.notEqual(retry.code, 0);
    assert.ok(retry.stderr.includes(paused.automatic_unlock_paused_until));
    assert.match(retry.stderr, /kubeconfig-vault unlock/);
  }
  assert.equal((await urls()).length, beforeDecline + 1);
  await successful(launch(["unlock"]));
  assert.equal(JSON.parse(await cli("status")).automatic_unlock_paused_until, undefined);
  console.log("PASS: declining on the vault page rejects both clients and keeps the vault locked.");

  // Exercise one long-lived client-go process against the disposable API.
  const proxyPath=process.env.KUBE_UNLOCK_TEST_FREELENS_PROXY||"/opt/Freelens/resources/x64/freelens-k8s-proxy";
  {
    const freelens=await stat(proxyPath).then(info=>info.isFile(),()=>false);
    const program=freelens ? proxyPath : process.env.KUBE_UNLOCK_TEST_KUBECTL || "kubectl";
    // Observe actual exec refreshes without recording arguments, tokens or responses.
    const callsFile=join(root,"proxy-calls");
    const shim=join(root,"proxy-exec");
    const proxyConfig=join(root,"proxy-config");
    await writeFile(shim,`#!${process.execPath}\nconst fs=require("node:fs"),{spawnSync}=require("node:child_process");\nfs.appendFileSync(${JSON.stringify(callsFile)},"call\\n",{mode:0o600});\nconst run=spawnSync(${JSON.stringify(executable)},process.argv.slice(2),{stdio:"inherit"});\nprocess.exit(run.status??1);\n`,{mode:0o700});
    const observedConfig=projection.replaceAll(legacyExecutable,shim);
    assert.notEqual(observedConfig,projection);
    await writeFile(proxyConfig,observedConfig,{mode:0o600});
    const calls=async()=>(await readFile(callsFile,"utf8")).trim().split("\n").length;
    const args=["proxy","--kubeconfig",proxyConfig];
    const env={...process.env,KUBECONFIG:proxyConfig};
    if(freelens) Object.assign(env,{FREELENS_PROXY_CONTEXT:"synthetic",FREELENS_PROXY_API_PREFIX:"/synthetic-test",FREELENS_PROXY_KEY:privateKey.toString(),FREELENS_PROXY_CERT:certificate.toString()});
    else args.push("--port=0","--address=127.0.0.1");
    const proxy=spawn(program,args,{env,stdio:["ignore","pipe","pipe"]});
    children.push(proxy);
    let output="";
    proxy.stdout.on("data",b=>output+=b);proxy.stderr.on("data",b=>output+=b);
    const port=await waitFor(()=>output.match(/127\.0\.0\.1:(\d+)/)?.[1],"loopback proxy");
    const readProxy=()=>new Promise((resolve,reject)=>{
      const transport=freelens?https:http;
      transport.get({hostname:"127.0.0.1",port,path:freelens?"/synthetic-test/version":"/version",ca:certificate,timeout:30000},res=>{
        res.resume();
        res.on("end",()=>res.statusCode===200?resolve():reject(new Error("Synthetic proxy request failed")));
      }).on("error",reject).on("timeout",function(){this.destroy()});
    });
    const proxyStart=(await urls()).length;
    await readProxy();
    const firstCalls=await calls();
    await delay(61000);
    await readProxy();
    assert.equal(await calls(),firstCalls+1,"warm proxy did not refresh the credential");
    assert.equal((await urls()).length,proxyStart);
    await cli("lock");
    await readProxy();
    assert.equal(await calls(),firstCalls+1,"immediate access unexpectedly refreshed the credential");
    await delay(61000);
    const refresh={done:false};
    refresh.promise=readProxy().then(()=>({code:0})).finally(()=>{refresh.done=true});
    await complete(refresh);
    assert.equal(await calls(),firstCalls+2,"locked proxy did not refresh the credential");
    assert.equal((await urls()).length,proxyStart+1);
    assert.ok(!output.includes(tokenA));proxy.kill();await once(proxy,"exit");
    console.log(`PASS: one live ${freelens ? "Freelens" : "kubectl"} proxy refreshed silently after 61s, reused its token immediately after lock, and required one approval on its next refresh.`);
  }

  await successful(launch(["config","unlock"]));
  const edit = (await cli("path", "edit")).trimEnd();
  assert.equal(edit, JSON.parse(await cli("status")).edit_path);
  assert.equal(await readFile(edit,"utf8"),original);
  const locked=JSON.parse(await cli("lock"));assert.equal(locked.fully_locked,false);assert.equal(locked.edit_open,true);
  await writeFile(edit,"not: [valid",{mode:0o600});
  assert.notEqual((await complete(launch(["config","lock"]))).code,0);
  assert.deepEqual(await readFile(join(state,"current","vault.age")),initialGeneration);assert.ok(await stat(edit));
  sourceObject.users[0].user.token=tokenB;await writeFile(edit,JSON.stringify(sourceObject,null,2),{mode:0o600});
  await successful(launch(["config","lock"]));acceptedToken=tokenB;
  const savedProjection = await readFile(generatedConfig, "utf8");
  assert.equal(kubectlConfig("current-context"), "second");
  assert.equal(kubectlConfig("view","--minify","-o","jsonpath={.contexts[0].context.namespace}"), "vault-test");
  assert.ok(savedProjection.includes(executable) && !savedProjection.includes(legacyExecutable));
  assert.equal(await stat(edit).catch(()=>false),false);assert.equal(JSON.parse(await cli("status")).fully_locked,true);
  const closedEdit = await launch(["path", "edit"]).promise;
  assert.equal(closedEdit.code, 1);
  assert.equal(closedEdit.stdout, "");
  assert.notDeepEqual(await readFile(join(state,"current","vault.age")),initialGeneration);
  assert.equal((await successful(kube())).code,0);
  console.log("PASS: fresh edit authentication, visible plaintext state, failed-save preservation, verified encrypted save and cache invalidation.");

  await cli("lock");
  const repair = () => launch(["config","repair","--kubeconfig",source]);
  const cipherBefore = await readFile(join(state,"current","vault.age"));
  await successful(launch(["config","unlock"]));
  await rm(generatedConfig);
  const human = await launch(["status"], {terminal:true}).promise;
  assert.equal(human.code, 1);
  assert.match(human.stdout, /Vault status degraded/);
  assert.ok(human.stdout.includes(edit));
  const openEdit = await launch(["status","--json"]).promise;
  const editStatus = JSON.parse(openEdit.stdout);
  assert.equal(openEdit.code, 1);
  assert.deepEqual(editStatus.edit_paths,[edit]);
  assert.equal(editStatus.fully_locked,false);
  const pagesBeforeRefusal = (await urls()).length;
  assert.notEqual((await repair().promise).code, 0);
  assert.equal((await urls()).length, pagesBeforeRefusal);
  await cli("config","discard");
  const damaged = await launch(["status","--json"]).promise;
  assert.equal(damaged.code, 1);
  assert.match(JSON.parse(damaged.stdout).next_action, /config repair/);
  assert.notEqual((await complete(repair(), "decline")).code, 0);
  await assert.rejects(stat(generatedConfig), {code:"ENOENT"});
  await successful(repair());
  assert.equal(await readlink(source), generatedConfig);
  assert.deepEqual(await readFile(join(state,"current","vault.age")), cipherBefore);
  assert.equal(kubectlConfig("current-context"), "second");
  assert.equal(kubectlConfig("view","--minify","-o","jsonpath={.contexts[0].context.namespace}"), "vault-test");
  assert.equal((await successful(kube())).code, 0);
  console.log("PASS: declined repair preserved the missing file; authenticated repair restored kubectl access and saved selections.");

  const exported=join(root,"exported");await successful(launch(["export",exported]));assert.ok((await readFile(exported,"utf8")).includes(tokenB));
  await cli("lock");const cancelled=launch(["unlock"]);await waitFor(async()=>(await urls()).length>navigated,"pending authentication");
  const oldLaunch=(await urls()).at(-1),oldUrl=await bootstrapTarget(oldLaunch);navigated=(await urls()).length;
  await cli("lock");assert.notEqual((await cancelled.promise).code,0);assert.equal(JSON.parse(await cli("status")).unlocked,false);
  assert.equal(await fetch(oldUrl.split("#")[0]).then(()=>true,()=>false),false);
  assert.equal(await stat(fileURLToPath(oldLaunch)).catch(()=>false),false);
  console.log("PASS: explicit lock cancels an outstanding browser unlock and prevents a late cached session.");

  const disconnected=launch(["unlock"]);await waitFor(async()=>(await urls()).length>navigated,"client disconnect authentication");
  const disconnectedLaunch=(await urls()).at(-1),disconnectedUrl=await bootstrapTarget(disconnectedLaunch);navigated=(await urls()).length;
  disconnected.child.kill("SIGTERM");await disconnected.promise;
  await waitFor(async()=>await fetch(disconnectedUrl.split("#")[0]).then(()=>false,()=>true),"disconnected browser listener closes");
  assert.equal(JSON.parse(await cli("status")).unlocked,false);
  console.log("PASS: exiting the requesting client cancels authentication instead of leaving it running.");

  // The daemon's short lifetime here is solely to exercise real expiry.
  await Promise.all([once(daemon,"exit"),cli("stop")]);
  const short=spawn(executable,["--state-dir",state,"--browser",launcher,"--session-seconds","1","serve"],{stdio:["ignore","ignore","pipe"]});children.push(short);short.stderr.on("data",b=>daemonLog+=b);
  await waitFor(async()=>{try{return(await stat(join(state,"session.sock"))).isSocket()}catch{return false}},"short-session daemon");
  await successful(kube());await delay(1300);assert.equal(JSON.parse(await cli("status")).unlocked,false);
  await successful(kube());console.log("PASS: elapsed session expires and the next kubectl invocation requires fresh browser authentication.");

  const backup = join(root,"separate-backup.age");
  await cli("backup",backup);
  await writeFile(recovery,savedKey+"\n",{mode:0o600});
  assert.match(await cli("recover",backup,"--key",recovery,"--check"), /verified/);
  const pagesBeforeOfflineRead = (await urls()).length;
  const latest = join(root, "latest-offline");
  await cli("recover",backup,"--key",recovery,"--out",latest);
  assert.equal((await kube("synthetic",latest).promise).code, 0, "latest saved backup must authenticate");
  assert.ok((await readFile(latest,"utf8")).includes(tokenB), "backup did not contain the saved credential");
  assert.equal((await urls()).length, pagesBeforeOfflineRead, "offline access opened a browser");
  // A missing or substituted rollback must leave the working link in place.
  const safeRollback = await readFile(rollback);
  await rm(rollback);
  assert.notEqual((await launch(["config","unlink","--kubeconfig",source]).promise).code,0);
  await writeFile(rollback,Buffer.from("corrupt"),{mode:0o600});
  assert.notEqual((await launch(["setup",source]).promise).code,0);
  assert.equal(await readlink(source),generatedConfig);
  await writeFile(rollback,safeRollback);
  const canonicalSource = join(await realpath(dirname(source)), basename(source));
  const receipt = join(state, "rollback-" + createHash("sha256").update(canonicalSource).digest("hex") + ".sha256");
  const receiptBytes = await readFile(receipt);
  const savedClient = await readFile(generatedConfig);
  await rm(generatedConfig);
  await successful(launch(["config","unlink","--kubeconfig",clientAlias]));
  assert.equal(await readFile(source,"utf8"), original);
  await writeFile(generatedConfig, savedClient, {mode:0o600});

  // Resume after plaintext replacement, and after durable restoration was
  // recorded. An edit made after restoration must survive either retry.
  const restoredInode = (await stat(source)).ino;
  for (const journal of [receipt, receipt + ".restored"]) {
    await writeFile(journal, receiptBytes, {mode:0o600});
    await writeFile(rollback, safeRollback, {mode:0o600});
    const changed = original + "\n# local edit after interrupted unlink\n";
    await writeFile(source, changed);
    const conflicted = launch(["config","unlink","--kubeconfig",clientAlias]);
    await complete(conflicted);
    assert.notEqual(conflicted.code, 0);
    assert.equal(await readFile(source,"utf8"), changed);
    assert.deepEqual(await readFile(rollback), safeRollback);
    assert.deepEqual(await readFile(journal), receiptBytes);
    await writeFile(source, original);
    await successful(launch(["config","unlink","--kubeconfig",clientAlias]));
    assert.equal((await stat(source)).ino, restoredInode);
    for (const path of [receipt, receipt + ".restored", rollback]) {
      await assert.rejects(stat(path), {code:"ENOENT"});
    }
  }
  // The ciphertext removal was already durable. Only the receipt remains.
  await writeFile(receipt + ".restored", receiptBytes, {mode:0o600});
  const beforeReceiptCleanup = (await urls()).length;
  await cli("config","unlink","--kubeconfig",clientAlias);
  assert.equal((await urls()).length, beforeReceiptCleanup);
  assert.equal(await readFile(source,"utf8"), original);
  assert.equal((await stat(source)).ino, restoredInode);
  await assert.rejects(stat(receipt + ".restored"), {code:"ENOENT"});
  console.log("PASS: exact rollback with a missing generated config; interrupted unlink verifies an existing original and preserves a later edit.");
  // A v0.1.1 link can have an old plaintext backup after an edited vault has moved on.
  await writeFile(source+".before-kubeconfig-vault", original, {mode:0o600});
  await rm(source);
  await symlink(generatedConfig,source);
  await successful(launch(["setup",source]));
  await assert.rejects(stat(source+".before-kubeconfig-vault"), {code:"ENOENT"});
  assert.ok(!(await readFile(rollback)).includes(tokenA));
  await successful(launch(["config","unlink","--kubeconfig",source]));
  assert.equal(await readFile(source,"utf8"),original);
  await successful(launch(["history","prune","--keep","1"]));
  assert.equal((await readdir(join(state,"generations"))).length,1);

  // Simulate losing the original key and helper. Keep the old files aside for the later rollback checks.
  await Promise.all([once(short,"exit"),cli("stop")]);
  await call("WebAuthn.removeVirtualAuthenticator", {authenticatorId:originalKey.authenticatorId});
  const oldState = state, offlineState = join(root,"old-state-offline");
  await rename(oldState, offlineState);
  state=join(root,"relocated");
  const relocated=join(root,"relocated-cli");
  await copyFile(executable,relocated);
  const wrongKey = join(root,"unrelated-recovery-key");
  await cli("recovery-key","new",wrongKey);
  const beforeWrongKey = (await urls()).length;
  const rejected = await launch(["restore",backup,"--key",wrongKey],{program:relocated}).promise;
  assert.notEqual(rejected.code,0,"an unrelated recovery key must fail");
  assert.equal((await urls()).length,beforeWrongKey,"failed recovery opened a browser");
  await assert.rejects(stat(join(state,"current")),{code:"ENOENT"});
  const replacementKey = await call("WebAuthn.addVirtualAuthenticator", {options:virtualKeyOptions});
  assert.notEqual(replacementKey.authenticatorId,originalKey.authenticatorId);
  const restored=launch(["restore",backup,"--key",recovery],{program:relocated});
  await successful(restored);
  const restoredProjection=await readFile(join(state,"current","kubeconfig"),"utf8");
  assert.ok(restoredProjection.includes(state) && restoredProjection.includes(relocated));
  await cli("lock");
  const beforeReplacementUnlock = (await urls()).length;
  const restoredClient = join(state,"current","kubeconfig");
  const firstRecoveredRequest = await successful(kube("synthetic",restoredClient));
  assert.equal(JSON.parse(firstRecoveredRequest.stdout).gitVersion,"v1.32.0");
  const reused = await kube("synthetic",restoredClient).promise;
  assert.equal(reused.code,0);
  assert.equal(JSON.parse(reused.stdout).gitVersion,"v1.32.0");
  assert.equal((await urls()).length,beforeReplacementUnlock+1);
  console.log("PASS: wrong offline key rejected; a replacement authenticator unlocked the saved credential in new state and two kubectl requests shared one approval.");
  const absentClient = join(root,"new-client");
  await cli("config","link","--kubeconfig",absentClient);
  assert.match(await cli("setup", absentClient), /Already set up/);
  await cli("config","unlink","--kubeconfig",absentClient);
  await assert.rejects(stat(absentClient), {code:"ENOENT"});
  const editor=join(root,"fixture-editor");
  await writeFile(editor,"#!/bin/sh\nexit 0\n",{mode:0o700});
  const editGeneration=await readlink(join(state,"current")), editPages=(await urls()).length;
  const unchanged=await successful(launch(["edit"],{env:{...process.env,VISUAL:editor}}));
  assert.match(unchanged.stdout,/No changes/);
  assert.equal(await readlink(join(state,"current")),editGeneration);
  assert.equal((await urls()).length,editPages+1);
  assert.deepEqual(await readdir(join(state,"edit")),[]);
  console.log("PASS: closing an unchanged edit requires only its opening page and preserves the generation.");
  // Use the restored vault to exercise mixed auth without changing the original fixture.
  const keyMarker = clientKey.toString().split("\n")[1];
  {
    await successful(launch(["config","unlock"]));
    const mixedEdit = (await cli("path","edit")).trim();
    assert.ok((await readFile(mixedEdit,"utf8")).includes(tokenB));
    const mixed = structuredClone(sourceObject);
    mixed.users.push({name:"cert-user",user:certificateUser});
    mixed.clusters.push({name:"mtls",cluster:certificateCluster});
    mixed.contexts.push({name:"cert",context:{cluster:"mtls",user:"cert-user"}});
    await writeFile(mixedEdit,JSON.stringify(mixed),{mode:0o600});
    await successful(launch(["config","lock","--accept-connection-changes"]));
    const client = join(state,"current","kubeconfig");
    const projection = await readFile(client,"utf8");
    assert.ok(!projection.includes("client-key-data") && !projection.includes(clientKey.toString("base64")) && !projection.includes(keyMarker));
    const certResult = await successful(kube("cert",client));
    assert.equal(JSON.parse(certResult.stdout).gitVersion,"v1.mtls");
    assert.equal(JSON.parse((await kube("synthetic",client).promise).stdout).gitVersion,"v1.32.0");
    const certBackup = join(root,"mixed.age"), certRecovery = join(root,"mixed-recovered");
    await cli("backup",certBackup);
    await cli("recover",certBackup,"--key",recovery,"--out",certRecovery);
    assert.equal(JSON.parse((await kube("cert",certRecovery).promise).stdout).gitVersion,"v1.mtls");
    const browserRequests = JSON.stringify(events.filter(e=>e.method==="Network.requestWillBeSent").map(e=>e.params.request));
    for (const visible of [projection,browserRequests,daemonLog]) {
      assert.ok(!visible.includes(keyMarker) && !visible.includes(clientKey.toString("base64")),"client key escaped native credential handling");
    }
    console.log("PASS: real kubectl used a token and an embedded client certificate in one vault; mutual TLS worked after offline recovery.");
  }
  await cli("stop");
  // Provision another disposable vault without a controlling terminal.
  state = join(root, "file-key-state");
  const fileKeySource = join(root, "file-key-source");
  await writeFile(fileKeySource, original, {mode: 0o600});
  const pagesBeforeFileKey = (await urls()).length;
  const withKey = launch(["setup", fileKeySource, "--recovery-key", recovery], {detached: true});
  await successful(withKey);
  assert.equal((await urls()).length, pagesBeforeFileKey + 1);
  assert.ok(!(withKey.stdout + withKey.stderr).includes(savedKey));
  assert.equal(await readlink(fileKeySource), join(state, "current", "kubeconfig"));
  const fileKeyBackup = join(root, "file-key.age");
  await cli("backup", fileKeyBackup);
  assert.match(await cli("recover", fileKeyBackup, "--key", recovery, "--check"), /verified/);
  const pagesBeforeRepeat = (await urls()).length;
  const repeat = await launch(["setup", fileKeySource, "--recovery-key", wrongKey]).promise;
  assert.notEqual(repeat.code, 0);
  assert.match(repeat.stderr, /already has a recovery key/);
  assert.equal((await urls()).length, pagesBeforeRepeat);
  await cli("stop");
  console.log("PASS: setup used an existing offline key with browser approval; the same key decrypted the backup.");
  await call("WebAuthn.removeVirtualAuthenticator",{authenticatorId:replacementKey.authenticatorId});
  await rename(offlineState,oldState);
  state=oldState;
  const recovered = join(root, "recovered");
  const restoring = launch(["recover", encryptedVault, "--out", recovered], { terminal: true });
  await waitFor(() => restoring.output.includes("input is hidden"), "hidden recovery prompt");
  restoring.child.stdin.end(savedKey + "\r");
  assert.equal((await restoring.promise).code, 0, "Pasted recovery key did not unlock synthetic vault");
  assert.ok(!restoring.output.includes(savedKey), "Recovery prompt echoed the pasted key");
  await writeFile(recovery, savedKey + "\n", { mode: 0o600 });
  const fileRecovered = join(root, "file-recovered");
  await cli("recover", encryptedVault, "--key", recovery, "--out", fileRecovered);
  assert.ok((await readFile(fileRecovered, "utf8")).includes(tokenB));
  assert.ok((await readFile(recovered,"utf8")).includes(tokenB));
  const publicMetadata=await readFile(join(state,"current","metadata.json"),"utf8");assert.ok(!publicMetadata.includes(await readFile(recovery,"utf8")));
  console.log("PASS: offline recovery with all authenticators removed; new portable plaintext file only.");

  const requests=events.filter(e=>e.method==="Network.requestWillBeSent").map(e=>e.params.request);
  const launches=new Set(await urls());
  assert.ok(requests.every(r=>r.url.startsWith("http://localhost:")||launches.has(r.url)));
  const httpText=JSON.stringify(requests),recoveryText=(await readFile(recovery,"utf8")).trim();
  assert.ok(!httpText.includes(tokenA)&&!httpText.includes(tokenB)&&!httpText.includes(recoveryText));
  assert.ok(!daemonLog.includes(tokenA)&&!daemonLog.includes(tokenB)&&!daemonLog.includes(recoveryText)&&!daemonLog.includes("DATA RACE"));
  for(const name of await readdir(join(state,"generations"))){for(const file of ["vault.age","metadata.json","kubeconfig"]){const data=await readFile(join(state,"generations",name,file));assert.ok(!data.includes(tokenA)&&!data.includes(tokenB)&&!data.includes(recoveryText))}}
  assert.equal(await readFile(source, "utf8"), original);
  assert.ok(!(await stat(source + ".before-kubeconfig-vault").catch(() => false)));
  await assert.rejects(stat(join(state, "session.sock")), { code: "ENOENT" });
  console.log("PASS: existing client path works across vault saves, and authenticated unlink restores the original bytes.");
  console.log("PASS: local assets only; no Kubernetes token or private recovery key in browser HTTP or persistent generations.");
} finally {
  clearTimeout(timeout);
  for(const p of children.reverse()){if(p.exitCode===null&&p.signalCode===null){const exited=once(p,"exit");p.kill();await Promise.race([exited,delay(2000)]);if(p.exitCode===null&&p.signalCode===null){p.kill("SIGKILL");await exited}}}
  if(certificateAPI?.listening){certificateAPI.closeAllConnections();await new Promise(resolve=>certificateAPI.close(resolve))}
  if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
  await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
