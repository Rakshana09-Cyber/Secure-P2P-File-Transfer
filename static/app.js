const $ = (id) => document.getElementById(id);
let peer, myId = "", activeConn = null, receivedChunks = [], receiveMeta = null, receiveKey = null;
const CHUNK_SIZE = 16 * 1024;

function setStatus(message) { $("status").textContent = message; }
function setSend(message) { $("send-status").textContent = message; }
function setReceive(message) { $("receive-status").textContent = message; }
function bytesToB64(bytes) {
  let binary = ""; const arr = new Uint8Array(bytes);
  for (let i=0;i<arr.length;i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}
function b64ToBytes(value) {
  const binary = atob(value); const out = new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++) out[i]=binary.charCodeAt(i);
  return out;
}
function waitForBuffer(conn) {
  if (conn.dataChannel.bufferedAmount < 512 * 1024) return Promise.resolve();
  return new Promise(resolve => {
    conn.dataChannel.bufferedAmountLowThreshold = 256 * 1024;
    conn.dataChannel.addEventListener("bufferedamountlow", resolve, {once:true});
  });
}
async function makeKeyPair() {
  return crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
}
async function exportPublic(key) {
  return bytesToB64(await crypto.subtle.exportKey("raw",key));
}
async function deriveAesKey(privateKey, remotePublicB64) {
  const remote = await crypto.subtle.importKey("raw",b64ToBytes(remotePublicB64),{name:"ECDH",namedCurve:"P-256"},false,[]);
  const shared = await crypto.subtle.deriveBits({name:"ECDH",public:remote},privateKey,256);
  const material = await crypto.subtle.importKey("raw",shared,"HKDF",false,["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name:"HKDF",hash:"SHA-256",salt:new TextEncoder().encode("ShadowProtocol-P2P-v1"),info:new TextEncoder().encode("file-transfer")},
    material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
  );
}
async function digestHex(buffer) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256",buffer));
  return [...hash].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function sendJSON(conn,obj){conn.send(obj);}

peer = new Peer();
peer.on("open", id => {
  myId=id; $("my-id").textContent=id; $("copy-id").disabled=false;
  setStatus("Connected to signaling service. Your peer ID is ready.");
  updateSendButton();
});
peer.on("error", err => setStatus("Peer connection error: "+err.type+". Refresh and try again."));
peer.on("connection", conn => {
  if(activeConn && activeConn.open){conn.close();return;}
  activeConn=conn; setupReceiver(conn);
});

$("copy-id").addEventListener("click",async()=>{
  try{await navigator.clipboard.writeText(myId);$("copy-id").textContent="Copied!";}
  catch{setStatus("Copy unavailable. Select and copy your peer ID manually.");}
});
$("file-input").addEventListener("change",()=>{
  const f=$("file-input").files[0]; $("file-label").textContent=f?`${f.name} (${formatBytes(f.size)})`:"Choose a file"; updateSendButton();
});
$("remote-id").addEventListener("input",updateSendButton);
function updateSendButton(){ $("send-btn").disabled=!(myId && $("remote-id").value.trim() && $("file-input").files.length); }
function formatBytes(n){if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";return (n/1048576).toFixed(2)+" MB";}

$("send-btn").addEventListener("click",async()=>{
  const file=$("file-input").files[0], remoteId=$("remote-id").value.trim();
  $("send-btn").disabled=true;$("send-progress").value=0;$("download-link").classList.add("hidden");
  try{
    setSend("Connecting directly to receiver…");
    const conn=peer.connect(remoteId,{reliable:true,serialization:"json"});
    activeConn=conn;
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("Connection timed out. Check the peer ID and try again.")),20000);
      conn.on("open",()=>{clearTimeout(timer);resolve();});
      conn.on("error",e=>{clearTimeout(timer);reject(e);});
    });
    setSend("Establishing encrypted session…");
    const pair=await makeKeyPair(), pub=await exportPublic(pair.publicKey);
    conn.send({type:"hello",publicKey:pub});
    const remotePub=await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("Receiver did not respond to key exchange.")),20000);
      conn.on("data",function handler(msg){if(msg.type==="hello"){clearTimeout(timer);conn.off("data",handler);resolve(msg.publicKey);}});
    });
    const key=await deriveAesKey(pair.privateKey,remotePub);
    const arrayBuffer=await file.arrayBuffer();
    const hash=await digestHex(arrayBuffer);
    sendJSON(conn,{type:"file-start",name:file.name,size:file.size,mime:file.type||"application/octet-stream",chunks:Math.ceil(file.size/CHUNK_SIZE),sha256:hash});
    const total=Math.ceil(file.size/CHUNK_SIZE);
    for(let i=0;i<total;i++){
      await waitForBuffer(conn);
      const part=arrayBuffer.slice(i*CHUNK_SIZE,Math.min((i+1)*CHUNK_SIZE,arrayBuffer.byteLength));
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,part);
      sendJSON(conn,{type:"file-chunk",index:i,iv:bytesToB64(iv),data:bytesToB64(encrypted)});
      $("send-progress").value=Math.round(((i+1)/total)*100);
      setSend(`Encrypting and sending chunk ${i+1} of ${total}…`);
    }
    sendJSON(conn,{type:"file-end"});
    setSend("Transfer sent. Waiting for receiver verification…");
    conn.on("data",msg=>{if(msg.type==="complete")setSend("Success: receiver verified the SHA-256 checksum.");if(msg.type==="failure")setSend("Receiver reported an integrity or decryption error.");});
  }catch(err){setSend("Transfer failed: "+err.message);}
  finally{$("send-btn").disabled=false;}
});

function setupReceiver(conn) {
  receivedChunks = [];
  receiveMeta = null;
  receiveKey = null;
  $("receive-progress").value = 0;
  $("download-link").classList.add("hidden");
  setReceive("Incoming peer connection. Negotiating encryption…");

  // PeerJS may deliver data events quickly. Queue async work so that
  // file-end cannot be handled before the preceding chunks are decrypted.
  let receiveQueue = Promise.resolve();

  conn.on("data", (msg) => {
    receiveQueue = receiveQueue.then(async () => {
      if (!msg || typeof msg.type !== "string") {
        throw new Error("Invalid transfer message.");
      }

      if (msg.type === "hello") {
        const pair = await makeKeyPair();
        conn.send({ type: "hello", publicKey: await exportPublic(pair.publicKey) });
        receiveKey = await deriveAesKey(pair.privateKey, msg.publicKey);
        setReceive("Encrypted session established. Waiting for file…");

      } else if (msg.type === "file-start") {
        if (!receiveKey) throw new Error("Encryption key is not ready.");
        if (!Number.isSafeInteger(msg.chunks) || msg.chunks < 0 || msg.chunks > 100000) {
          throw new Error("Invalid file chunk count.");
        }
        if (!Number.isSafeInteger(msg.size) || msg.size < 0) {
          throw new Error("Invalid file size.");
        }
        receiveMeta = msg;
        receivedChunks = new Array(msg.chunks);
        $("receive-progress").value = 0;
        setReceive(`Receiving ${msg.name} (${formatBytes(msg.size)})…`);
        if (msg.chunks === 0) await finishReceive(conn);

      } else if (msg.type === "file-chunk") {
        if (!receiveMeta || !receiveKey) throw new Error("Unexpected file chunk.");
        if (!Number.isInteger(msg.index) || msg.index < 0 || msg.index >= receiveMeta.chunks) {
          throw new Error("Invalid file chunk index.");
        }
        if (receivedChunks[msg.index] !== undefined) {
          throw new Error("Duplicate file chunk received.");
        }
        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: b64ToBytes(msg.iv) },
          receiveKey,
          b64ToBytes(msg.data)
        );
        receivedChunks[msg.index] = plain;
        const done = receivedChunks.filter(chunk => chunk instanceof ArrayBuffer).length;
        $("receive-progress").value = receiveMeta.chunks
          ? Math.round((done / receiveMeta.chunks) * 100) : 100;
        setReceive(`Decrypting chunk ${done} of ${receiveMeta.chunks}…`);

      } else if (msg.type === "file-end") {
        await finishReceive(conn);
      }
    }).catch(err => {
      setReceive("Receive failed: " + err.message);
      try { conn.send({ type: "failure" }); } catch (_) {}
    });
  });

  conn.on("close", () => {
    if (!$("download-link").href) setReceive("Peer disconnected.");
  });
}

async function finishReceive(conn) {
  if (!receiveMeta) throw new Error("Missing file metadata.");
  if (receivedChunks.length !== receiveMeta.chunks ||
      receivedChunks.some(chunk => !(chunk instanceof ArrayBuffer))) {
    throw new Error("Some file chunks are missing or still being decrypted.");
  }

  const blob = new Blob(receivedChunks, { type: receiveMeta.mime || "application/octet-stream" });
  const buffer = await blob.arrayBuffer();
  if (buffer.byteLength !== receiveMeta.size) {
    throw new Error(`Received file size does not match (expected ${receiveMeta.size}, got ${buffer.byteLength}).`);
  }

  const actual = await digestHex(buffer);
  if (actual !== receiveMeta.sha256) {
    setReceive("Integrity check failed: SHA-256 does not match.");
    conn.send({ type: "failure" });
    return;
  }

  const url = URL.createObjectURL(blob);
  const link = $("download-link");
  link.href = url;
  link.download = receiveMeta.name.replace(/[\\/:*?"<>|]/g, "_");
  link.classList.remove("hidden");
  $("receive-progress").value = 100;
  setReceive(`Received and verified ${receiveMeta.name} (${formatBytes(receiveMeta.size)}).`);
  conn.send({ type: "complete" });
}
