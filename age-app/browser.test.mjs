// Synthetic data only. Explicit temporary state/config, virtual authenticator,
// disposable Chrome profile, and loopback API. Never use default helper state.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, copyFile, readFile, readlink, symlink, writeFile, rm, readdir, chmod, stat } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";
import { chromeConnection } from "./test-support/cdp.mjs";

const cwd = fileURLToPath(new URL(".", import.meta.url));
const root = await mkdtemp(join(tmpdir(), "kua-"));
let state = join(root, "state");
const executable = join(root, "app"), launcher = join(root,"browser"), urlsFile = join(root,"urls");
const recovery = join(root,"offline-key"), source = join(root,"source"), children = [];
const tokenA = "SYNTHETIC-AGE-TOKEN-ONE", tokenB = "SYNTHETIC-AGE-TOKEN-TWO";
let acceptedToken = tokenA, server, failure;
const timeout = setTimeout(() => { failure = new Error("Synthetic integration timed out");for(const p of children)p.kill("SIGKILL");server?.closeAllConnections();server?.close(); },120000);

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

try {
  await build({absWorkingDir:cwd,entryPoints:["web/app.mjs"],outfile:"web/app.js",bundle:true,format:"esm",platform:"browser",target:"es2023",legalComments:"inline"});
  const compiled=spawnSync("go",["build","-race","-o",executable,"."],{cwd,encoding:"utf8",timeout:60000,env:{...process.env,GOTOOLCHAIN:"local",GOPROXY:"off",GOPATH:process.env.GOPATH||join(tmpdir(),"kube-unlock-go-path"),GOCACHE:process.env.GOCACHE||join(tmpdir(),"kube-unlock-go-cache")}});
  if(compiled.status!==0)throw new Error("Native integration build failed: "+compiled.stderr);
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
  const original=JSON.stringify(sourceObject,null,2);await writeFile(source,original,{mode:0o600});
  const missingConfig = await launch(["path", "kubeconfig"]).promise;
  assert.equal(missingConfig.code, 1);
  assert.equal(missingConfig.stdout, "");
  assert.match(missingConfig.stderr, /run import first/);
  await assert.rejects(stat(state), { code: "ENOENT" });
  const prematureLink = await launch(["config", "link", "--kubeconfig", source]).promise;
  assert.equal(prematureLink.code, 1);
  assert.equal(await readFile(source, "utf8"), original);
  await assert.rejects(stat(source + ".before-kubeconfig-vault"), { code: "ENOENT" });
  const daemon=spawn(executable,["--state-dir",state,"--browser",launcher,"serve"],{stdio:["ignore","ignore","pipe"]});children.push(daemon);let daemonLog="";daemon.stderr.on("data",b=>daemonLog+=b);
  await waitFor(async()=>{try{return(await stat(join(state,"session.sock"))).isSocket()}catch{return false}},"private daemon socket");
  const nonInteractive = await launch(["import", source], { detached: true }).promise;
  assert.equal(nonInteractive.code, 1);
  assert.match(nonInteractive.stderr, /terminal is required/);
  const abandoned = launch(["import", source], { terminal: true });
  await waitFor(() => abandoned.output.includes("Press Enter to show it"), "recovery reveal prompt");
  assert.ok(!abandoned.output.includes("AGE-SECRET-KEY-"));
  abandoned.child.stdin.write("\n");
  await waitFor(() => abandoned.output.includes("Type saved"), "recovery confirmation prompt");
  assert.deepEqual(await urls(), []);
  abandoned.child.stdin.end("cancel\n");
  assert.equal((await abandoned.promise).code, 1);
  await assert.rejects(stat(join(state, "current")), { code: "ENOENT" });
  assert.deepEqual(await urls(), []);
  const {call:cdp,events}=chromeConnection(join(root,"chrome"),children);
  const {targetId}=await cdp("Target.createTarget",{url:"about:blank"});
  const {sessionId}=await cdp("Target.attachToTarget",{targetId,flatten:true});
  const call=(method,params={})=>cdp(method,params,sessionId);
  const evaluate=async expression=>{const r=await call("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true,userGesture:true});if(r.exceptionDetails)throw new Error("Synthetic page evaluation failed");return r.result.value};
  await call("Page.enable");await call("Runtime.enable");await call("Network.enable");await call("WebAuthn.enable",{enableUI:false});
  const authenticator=await call("WebAuthn.addVirtualAuthenticator",{options:{protocol:"ctap2",ctap2Version:"ctap2_1",transport:"usb",hasResidentKey:false,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true}});
  let navigated=0; const visibleSteps = new Set();
  async function complete(operation){
    await waitFor(async()=>{
      const opened=await urls();if(opened.length>navigated){navigated=opened.length;await bootstrapTarget(opened.at(-1));await call("Page.navigate",{url:opened.at(-1)})}
      if(operation.done)return true;
      if(await evaluate("document.body?.textContent.trim()==='Forbidden'"))throw new Error("Private-file redirect was rejected by HTTP navigation checks");
      const step=await evaluate("(()=>{const b=document.querySelector('#continue');if(b&&!b.disabled){const step=document.querySelector('#progress').textContent;b.click();return step}})()");
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
  importing.child.stdin.end("saved\n");
  await successful(importing);
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

  const kube=()=>{
    const p=spawn(process.env.KUBE_UNLOCK_TEST_KUBECTL||"kubectl",["--cache-dir",join(root,"kubecache"),"get","--raw=/version","--request-timeout=30s"],{env:{...process.env,KUBECONFIG:source},stdio:["ignore","pipe","pipe"]});
    children.push(p);let stdout="",stderr="";const result={done:false};p.stdout.on("data",b=>stdout+=b);p.stderr.on("data",b=>stderr+=b);result.promise=new Promise((resolve,reject)=>{p.once("error",reject);p.once("exit",code=>{result.done=true;Object.assign(result,{code,stdout,stderr});resolve(result)})});return result;
  };
  const before=(await urls()).length,first=kube(),second=kube();
  assert.equal(JSON.parse((await successful(first)).stdout).gitVersion,"v1.32.0");assert.equal((await second.promise).code,0);
  assert.equal((await urls()).length,before+1);
  const warm=kube();assert.equal((await warm.promise).code,0);assert.equal((await urls()).length,before+1);
  const cached=JSON.parse(await cli("status"));assert.equal(cached.unlocked,true);assert.ok(Date.parse(cached.expires_at)-Date.now()>3500000);
  assert.deepEqual(await evaluate("[localStorage.length,sessionStorage.length]"),[0,0]);
  console.log("PASS: real kubectl to synthetic HTTPS API, concurrent unlock sharing, one-hour cache, empty browser storage.");

  // Exercise the installed proxy only against the explicit synthetic config.
  const proxyPath=process.env.KUBE_UNLOCK_TEST_FREELENS_PROXY||"/opt/Freelens/resources/x64/freelens-k8s-proxy";
  if(await stat(proxyPath).catch(()=>false)){
    const proxy=spawn(proxyPath,["proxy","--kubeconfig",source],{env:{...process.env,KUBECONFIG:source,FREELENS_PROXY_CONTEXT:"synthetic",FREELENS_PROXY_API_PREFIX:"/synthetic-test",FREELENS_PROXY_KEY:privateKey.toString(),FREELENS_PROXY_CERT:certificate.toString()},stdio:["ignore","pipe","pipe"]});children.push(proxy);let output="";proxy.stdout.on("data",b=>output+=b);proxy.stderr.on("data",b=>output+=b);
    const port=await waitFor(()=>output.match(/127\.0\.0\.1:(\d+)/)?.[1],"synthetic Freelens proxy");
    await new Promise((resolve,reject)=>{https.get({hostname:"127.0.0.1",port,path:"/synthetic-test/version",ca:certificate,timeout:10000},res=>{res.resume();res.on("end",()=>res.statusCode===200?resolve():reject(new Error("Synthetic proxy request failed")))}).on("error",reject).on("timeout",function(){this.destroy()})});
    assert.ok(!output.includes(tokenA));proxy.kill();await once(proxy,"exit");
    console.log("PASS: Freelens bundled Kubernetes proxy uses the new exec helper (no real profile).");
  }else console.log("SKIP: Freelens proxy executable unavailable; no GUI compatibility claim.");

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
  assert.equal(await stat(edit).catch(()=>false),false);assert.equal(JSON.parse(await cli("status")).fully_locked,true);
  const closedEdit = await launch(["path", "edit"]).promise;
  assert.equal(closedEdit.code, 1);
  assert.equal(closedEdit.stdout, "");
  assert.notDeepEqual(await readFile(join(state,"current","vault.age")),initialGeneration);
  assert.equal((await successful(kube())).code,0);
  console.log("PASS: fresh edit authentication, visible plaintext state, failed-save preservation, verified encrypted save and cache invalidation.");

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
  await cli("stop");await once(daemon,"exit");
  const short=spawn(executable,["--state-dir",state,"--browser",launcher,"--session-seconds","1","serve"],{stdio:["ignore","ignore","pipe"]});children.push(short);short.stderr.on("data",b=>daemonLog+=b);
  await waitFor(async()=>{try{return(await stat(join(state,"session.sock"))).isSocket()}catch{return false}},"short-session daemon");
  await successful(kube());await delay(1300);assert.equal(JSON.parse(await cli("status")).unlocked,false);
  await successful(kube());console.log("PASS: elapsed session expires and the next kubectl invocation requires fresh browser authentication.");

  const backup = join(root,"separate-backup.age");
  await cli("backup",backup);
  await writeFile(recovery,savedKey+"\n",{mode:0o600});
  assert.match(await cli("recover",backup,"--key",recovery,"--check"), /verified/);
  // A missing or substituted rollback must leave the working link in place.
  const safeRollback = await readFile(rollback);
  await rm(rollback);
  assert.notEqual((await launch(["config","unlink","--kubeconfig",source]).promise).code,0);
  await writeFile(rollback,Buffer.from("corrupt"),{mode:0o600});
  assert.notEqual((await launch(["setup",source]).promise).code,0);
  assert.equal(await readlink(source),generatedConfig);
  await writeFile(rollback,safeRollback);
  await successful(launch(["config","unlink","--kubeconfig",clientAlias]));
  assert.equal(await readFile(source,"utf8"), original);
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

  // Restore at new state and executable paths, with the same recovery identity.
  const oldState=state;
  state=join(root,"relocated");
  const relocated=join(root,"relocated-cli");
  await copyFile(executable,relocated);
  const restored=launch(["restore",backup,"--key",recovery],{program:relocated});
  await successful(restored);
  const restoredProjection=await readFile(join(state,"current","kubeconfig"),"utf8");
  assert.ok(restoredProjection.includes(state) && restoredProjection.includes(relocated));
  console.log("PASS: restored backup rebuilds paths for a new installation.");
  const editor=join(root,"fixture-editor");
  await writeFile(editor,"#!/bin/sh\nexit 0\n",{mode:0o700});
  await successful(launch(["config","edit"],{env:{...process.env,VISUAL:editor}}));
  await cli("stop");
  state=oldState;
  await call("WebAuthn.removeVirtualAuthenticator",{authenticatorId:authenticator.authenticatorId});
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
  await cli("stop");await once(short,"exit");

  assert.equal(await readFile(source, "utf8"), original);
  assert.ok(!(await stat(source + ".before-kubeconfig-vault").catch(() => false)));
  await assert.rejects(stat(join(state, "session.sock")), { code: "ENOENT" });
  console.log("PASS: existing client path works across vault saves, and authenticated unlink restores the original bytes.");
  console.log("PASS: local assets only; no Kubernetes token or private recovery key in browser HTTP or persistent generations.");
} finally {
  clearTimeout(timeout);
  for(const p of children.reverse()){if(p.exitCode===null&&p.signalCode===null){const exited=once(p,"exit");p.kill();await Promise.race([exited,delay(2000)]);if(p.exitCode===null&&p.signalCode===null){p.kill("SIGKILL");await exited}}}
  if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
  await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
