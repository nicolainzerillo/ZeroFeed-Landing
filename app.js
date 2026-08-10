// ZeroFeed Landing Page Bilingual & Interactive WASM Engine

let isWasmLoaded = false;
let activeWs = null;

// Async loader for Go WebAssembly module zerofeed.wasm
async function loadWasmEngine() {
    if (isWasmLoaded) return true;
    if (typeof Go === 'undefined') {
        console.warn('Go WASM runtime wasm_exec.js not loaded');
        return false;
    }

    const go = new Go();
    try {
        const response = await fetch('zerofeed.wasm?v=' + Date.now());
        const buffer = await response.arrayBuffer();
        const result = await WebAssembly.instantiate(buffer, go.importObject);
        go.run(result.instance);
        isWasmLoaded = true;
        console.log('[✓] ZeroFeed WASM Engine successfully loaded into browser RAM.');
        return true;
    } catch (err) {
        console.error('Failed to load zerofeed.wasm:', err);
        return false;
    }
}

// Binary Frame Protocol Constants (Matching Go pkg/protocol/messages.go ZeroFeed v2)
const Version = 2;
const MsgTypePAKEInitPub = 1;
const MsgTypePAKEInitSub = 2;
const MsgTypePAKEStep2   = 3; // Publisher PAKE response payload frame
const MsgTypeDataStream  = 4; // Encrypted data payload frame
const MsgTypeRekey       = 9; // In-stream key rotation (Rekeying & PFS)
const HeaderSize = 38; // 4B Magic + 1B Ver + 1B Type + 16B SessionID + 12B Nonce + 4B PayloadLen

function createHeader(msgType, sessionID, payloadLen, nonceBytes) {
    const buf = new ArrayBuffer(HeaderSize);
    const view = new DataView(buf);
    
    view.setUint8(0, 0x5A); // 'Z'
    view.setUint8(1, 0x46); // 'F'
    view.setUint8(2, 0x45); // 'E'
    view.setUint8(3, 0x44); // 'D'
    
    view.setUint8(4, Version);
    view.setUint8(5, msgType);
    
    // SessionID (16 bytes, offset 6 to 22)
    for (let i = 0; i < 16; i++) {
        view.setUint8(6 + i, sessionID[i] || 0);
    }
    
    // Nonce (12 bytes, offset 22 to 34)
    if (nonceBytes && nonceBytes.length === 12) {
        for (let i = 0; i < 12; i++) {
            view.setUint8(22 + i, nonceBytes[i]);
        }
    } else {
        for (let i = 0; i < 12; i++) {
            view.setUint8(22 + i, 0);
        }
    }
    
    // Payload length uint32 (4 bytes, offset 34 to 38)
    view.setUint32(34, payloadLen, false); // Big endian
    return new Uint8Array(buf);
}

function hexToBytes(hexString) {
    if (typeof hexString !== 'string') return new Uint8Array(0);
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function initWasmSubscriber() {
    const channelInput = document.getElementById('wasm-channel-code');
    const statusBanner = document.getElementById('wasm-status-banner');
    const statusText = document.getElementById('wasm-status-text');
    const sasBadge = document.getElementById('wasm-sas-badge');
    const consoleOutput = document.getElementById('wasm-output-console');
    const connectBtn = document.getElementById('wasm-connect-btn');
    const wipeBtn = document.getElementById('wasm-wipe-btn');

    if (!channelInput || !channelInput.value.trim()) {
        alert('Please enter a valid Channel Code / Passphrase.');
        return;
    }

    const code = channelInput.value.trim();
    connectBtn.disabled = true;
    connectBtn.textContent = 'Loading Engine...';

    const loaded = await loadWasmEngine();
    if (!loaded || typeof window.zeroFeedPAKEInitSub !== 'function') {
        alert('Failed to initialize WebAssembly engine.');
        connectBtn.disabled = false;
        connectBtn.textContent = 'Connect & Decrypt';
        return;
    }

    statusBanner.style.display = 'block';
    statusText.textContent = 'Generating Post-Quantum PAKE Handshake payload...';
    sasBadge.textContent = '';
    consoleOutput.textContent = `[+] Initializing E2EE Web Subscriber for channel: "${code}"\n`;

    try {
        const initResult = window.zeroFeedPAKEInitSub(code);
        if (initResult.error) {
            statusText.textContent = `Error: ${initResult.error}`;
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect & Decrypt';
            return;
        }

        const subMsgBytes = hexToBytes(initResult.subWireMsgHex);
        consoleOutput.textContent += `[✓] PAKE Subscriber Wire Payload generated (${subMsgBytes.length} bytes)\n`;

        // Connect to local WebSocket Relay port (8444)
        const host = window.location.hostname || '127.0.0.1';
        const wsUrl = `ws://${host}:8444/`;
        consoleOutput.textContent += `[+] Connecting to Relay WebSocket: ${wsUrl}...\n`;

        const ws = new WebSocket(wsUrl);
        ws.binaryType = 'arraybuffer';
        activeWs = ws;

        let sessionKeyHex = null;
        let incomingFileName = 'received_file.bin';
        let incomingFileSize = 0;
        let fileChunks = [];

        ws.onopen = () => {
            try {
                consoleOutput.textContent += `[✓] WebSocket Connected to Relay!\n`;
                consoleOutput.textContent += `[+] Deriving Zero-Knowledge Session ID via Argon2id...\n`;
                
                const sessionIDHex = window.zeroFeedDeriveSessionID(code);
                console.log('Derived Session ID:', sessionIDHex);
                
                if (typeof sessionIDHex !== 'string' || sessionIDHex.length !== 32) {
                    consoleOutput.textContent += `[!] Error deriving Session ID: ${sessionIDHex}\n`;
                    return;
                }

                consoleOutput.textContent += `[✓] Session ID derived: [${sessionIDHex.substring(0, 8)}...]\n`;
                const sessionIDBytes = hexToBytes(sessionIDHex);

                const header = createHeader(MsgTypePAKEInitSub, sessionIDBytes, subMsgBytes.length);
                const frame = new Uint8Array(header.length + subMsgBytes.length);
                frame.set(header, 0);
                frame.set(subMsgBytes, header.length);
                
                consoleOutput.textContent += `[+] Transmitting PAKE Init Frame (${frame.length} bytes) to Relay...\n`;
                ws.send(frame.buffer.slice(frame.byteOffset, frame.byteOffset + frame.byteLength));
            } catch (e) {
                consoleOutput.textContent += `[!] Exception in ws.onopen: ${e.message}\n`;
                console.error('ws.onopen exception:', e);
            }
        };

        ws.onmessage = (event) => {
            try {
                const data = new Uint8Array(event.data);
                if (data.length < HeaderSize) return;

                const magic = String.fromCharCode(data[0], data[1], data[2], data[3]);
                if (magic !== 'ZFED') return;

                const msgType = data[5];
                const sessionID = data.slice(6, 22);
                const nonce = data.slice(22, 34);
                
                const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
                const payloadLen = dv.getUint32(34, false);
                const payload = data.slice(HeaderSize, HeaderSize + payloadLen);

                if (msgType === MsgTypePAKEInitPub || msgType === MsgTypePAKEStep2) {
                    // Publisher PAKE response (MsgTypePAKEStep2 = 0x03)
                    const pubWireHex = bytesToHex(payload);
                    const updateRes = window.zeroFeedPAKEUpdateSub(pubWireHex, code);
                    if (updateRes.error) {
                        consoleOutput.textContent += `[!] Handshake Error: ${updateRes.error}\n`;
                        return;
                    }

                    sessionKeyHex = updateRes.sessionKeyHex;
                    sasBadge.textContent = `🛡️ SAS: ${updateRes.sasEmoji} [${updateRes.sasHex}]`;
                    statusText.textContent = 'Authenticated E2EE Stream Active (RAM-Only)';
                    consoleOutput.textContent += `[✓] SAS Verification Badge: ${updateRes.sasEmoji} [${updateRes.sasHex}]\n`;
                    consoleOutput.textContent += `[+] E2EE Session Key derived! Listening for encrypted payload stream...\n`;

                } else if (msgType === MsgTypeRekey && sessionKeyHex) {
                    if (payload.length < 8) return;
                    const ciphertext = payload.slice(8);
                    const headerBuf = createHeader(MsgTypeRekey, sessionID, payload.length, nonce);

                    const cipherHex = bytesToHex(ciphertext);
                    const nonceHex = bytesToHex(nonce);
                    const headerHex = bytesToHex(headerBuf);

                    const saltHex = window.zeroFeedDecrypt(sessionKeyHex, cipherHex, nonceHex, headerHex);
                    if (!saltHex || saltHex.error || typeof saltHex !== 'string') {
                        consoleOutput.textContent += `[!] Rekey Decryption Failed\n`;
                        return;
                    }

                    const ratchetRes = window.zeroFeedRatchetKey(sessionKeyHex, saltHex);
                    if (ratchetRes && !ratchetRes.error) {
                        sessionKeyHex = ratchetRes.nextKeyHex;
                        if (sasBadge) sasBadge.textContent = `🛡️ SAS: ${ratchetRes.sasEmoji} [${ratchetRes.sasHex}]`;
                        consoleOutput.textContent += `[🔄] In-Stream Key Rotation (PFS Ratchet) Completed! New SAS: ${ratchetRes.sasEmoji} [${ratchetRes.sasHex}]\n`;
                    }
                    return;

                } else if (msgType === MsgTypeDataStream && sessionKeyHex) {
                    if (payload.length < 8) return;

                    const ciphertext = payload.slice(8);
                    const headerBuf = createHeader(MsgTypeDataStream, sessionID, payload.length, nonce);

                    const cipherHex = bytesToHex(ciphertext);
                    const nonceHex = bytesToHex(nonce);
                    const headerHex = bytesToHex(headerBuf);

                    const decryptedHex = window.zeroFeedDecrypt(sessionKeyHex, cipherHex, nonceHex, headerHex);

                    if (!decryptedHex || decryptedHex.error || typeof decryptedHex !== 'string') {
                        consoleOutput.textContent += `[!] Decryption Failed for frame\n`;
                        return;
                    }

                    const decBytes = hexToBytes(decryptedHex);
                    const tag = decBytes[0];

                    const streamDisplay = document.getElementById('wasm-stream-display');
                    const liveIndicator = document.getElementById('wasm-live-indicator');
                    const fileCard = document.getElementById('wasm-file-card');
                    const fileNameEl = document.getElementById('wasm-file-name');
                    const fileSizeEl = document.getElementById('wasm-file-size');
                    const fileDownloadBtn = document.getElementById('wasm-file-download-btn');

                    if (liveIndicator) liveIndicator.style.display = 'inline-block';

                    if (tag === 0x01) { // TagText
                        const text = new TextDecoder().decode(decBytes.slice(1));
                        if (streamDisplay) {
                            if (streamDisplay.innerHTML.includes('Waiting for Publisher data stream')) {
                                streamDisplay.innerHTML = '';
                            }
                            const timeStr = new Date().toLocaleTimeString();
                            streamDisplay.innerHTML += `<div style="margin-bottom: 0.5rem;"><span style="color: #64748b; font-size: 0.85rem;">[${timeStr}]</span> <span style="color: #10b981; font-weight: 600;">&gt; ${text}</span></div>`;
                            streamDisplay.scrollTop = streamDisplay.scrollHeight;
                        }
                        consoleOutput.textContent += `> ${text}`;

                    } else if (tag === 0x02) { // TagFileStart
                        // Format: Tag(1B) + NameLen(2B) + Name + Size(8B) + Hash(32B)
                        const nameLen = (decBytes[1] << 8) | decBytes[2];
                        incomingFileName = new TextDecoder().decode(decBytes.slice(3, 3 + nameLen));
                        fileChunks = [];
                        
                        if (fileCard) fileCard.style.display = 'block';
                        if (fileNameEl) fileNameEl.textContent = incomingFileName;
                        if (fileSizeEl) fileSizeEl.textContent = 'Decrypting incoming chunks...';

                        consoleOutput.textContent += `[!] Incoming File Transfer: "${incomingFileName}"...\n`;

                    } else if (tag === 0x03) { // TagFileChunk
                        fileChunks.push(decBytes.slice(1));
                        consoleOutput.textContent += `[.] Received chunk (${decBytes.length - 1} bytes)\n`;
                        consoleOutput.scrollTop = consoleOutput.scrollHeight;

                    } else if (tag === 0x04) { // TagFileEnd
                        // Concatenate chunks into a Blob and trigger automatic browser file download
                        let totalLen = 0;
                        for (const chunk of fileChunks) totalLen += chunk.length;

                        const merged = new Uint8Array(totalLen);
                        let offset = 0;
                        for (const chunk of fileChunks) {
                            merged.set(chunk, offset);
                            offset += chunk.length;
                        }

                        const blob = new Blob([merged], { type: 'application/octet-stream' });
                        const blobUrl = URL.createObjectURL(blob);

                        if (fileCard) fileCard.style.display = 'block';
                        if (fileNameEl) fileNameEl.textContent = incomingFileName;
                        if (fileSizeEl) fileSizeEl.textContent = `${totalLen} Bytes • E2EE Decrypted`;
                        if (fileDownloadBtn) {
                            fileDownloadBtn.href = blobUrl;
                            fileDownloadBtn.download = incomingFileName;
                        }

                        if (streamDisplay) {
                            if (streamDisplay.innerHTML.includes('Waiting for Publisher data stream')) {
                                streamDisplay.innerHTML = '';
                            }
                            const timeStr = new Date().toLocaleTimeString();
                            streamDisplay.innerHTML += `<div style="margin-bottom: 0.5rem; color: #38bdf8;"><span style="color: #64748b; font-size: 0.85rem;">[${timeStr}]</span> 📄 <strong>Received File:</strong> ${incomingFileName} (${totalLen} bytes)</div>`;
                            streamDisplay.scrollTop = streamDisplay.scrollHeight;
                        }

                        const downloadAnchor = document.createElement('a');
                        downloadAnchor.href = blobUrl;
                        downloadAnchor.download = incomingFileName;
                        document.body.appendChild(downloadAnchor);
                        downloadAnchor.click();
                        document.body.removeChild(downloadAnchor);

                        consoleOutput.textContent += `[✓] File Received & Downloaded Successfully: "${incomingFileName}" (${totalLen} bytes)\n`;
                        statusText.textContent = `[✓] Downloaded: ${incomingFileName} (${totalLen} bytes)`;
                    }
                }
            } catch (e) {
                consoleOutput.textContent += `[!] Exception in ws.onmessage: ${e.message}\n`;
            }
        };

        ws.onerror = (err) => {
            console.warn('WebSocket error:', err);
        };

        ws.onclose = () => {
            consoleOutput.textContent += `[*] WebSocket Session Closed.\n`;
        };

        connectBtn.style.display = 'none';
        wipeBtn.style.display = 'inline-block';

    } catch (err) {
        consoleOutput.textContent += `[!] Exception: ${err.message}\n`;
        connectBtn.disabled = false;
        connectBtn.textContent = 'Connect & Decrypt';
    }
}

function wipeWasmSubscriber() {
    const statusBanner = document.getElementById('wasm-status-banner');
    const consoleOutput = document.getElementById('wasm-output-console');
    const connectBtn = document.getElementById('wasm-connect-btn');
    const wipeBtn = document.getElementById('wasm-wipe-btn');

    if (activeWs) {
        activeWs.close();
        activeWs = null;
    }

    if (typeof window.zeroFeedWipe === 'function') {
        window.zeroFeedWipe();
    }

    if (consoleOutput) {
        consoleOutput.textContent += `\n[🧹] crypto.WipeAll() triggered: All memory buffers zeroed in browser RAM.\n`;
    }
    if (statusBanner) statusBanner.style.display = 'none';
    if (connectBtn) {
        connectBtn.style.display = 'inline-block';
        connectBtn.disabled = false;
        connectBtn.textContent = 'Connect & Decrypt';
    }
    if (wipeBtn) wipeBtn.style.display = 'none';
}

function setLanguage(lang) {
    const isIt = (lang === 'it');

    const btnEn = document.getElementById('btn-en');
    const btnIt = document.getElementById('btn-it');
    if (btnEn) btnEn.classList.toggle('active', !isIt);
    if (btnIt) btnIt.classList.toggle('active', isIt);

    document.documentElement.lang = lang;
    localStorage.setItem('zerofeed_lang', lang);

    const translatableElements = document.querySelectorAll('[data-en][data-it]');
    translatableElements.forEach(el => {
        const translation = el.getAttribute(`data-${lang}`);
        if (translation) {
            el.textContent = translation;
        }
    });
}

function copyCommand(elementId) {
    const codeElement = document.getElementById(elementId);
    if (!codeElement) return;

    const textToCopy = codeElement.innerText || codeElement.textContent;
    navigator.clipboard.writeText(textToCopy).then(() => {
        const copyBtn = codeElement.nextElementSibling;
        if (copyBtn) {
            const originalSVG = copyBtn.innerHTML;
            copyBtn.innerHTML = `<span style="color: #10B981; font-weight: bold; font-size: 0.75rem; font-family: monospace;">COPIED!</span>`;
            setTimeout(() => {
                copyBtn.innerHTML = originalSVG;
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy command: ', err);
    });
}

function checkHashInvite() {
    const hash = window.location.hash;
    if (!hash || !hash.includes('join=')) return;

    try {
        const rawParam = hash.split('join=')[1];
        if (!rawParam) return;
        
        let decoded = decodeURIComponent(rawParam);
        if (decoded.includes('%')) {
            try { decoded = decodeURIComponent(decoded); } catch (ignored) {}
        }
        let channelCode = decoded;

        if (decoded.startsWith('zerofeed://')) {
            const urlObj = new URL(decoded.replace('zerofeed://join', 'https://placeholder.local'));
            channelCode = urlObj.searchParams.get('code') || channelCode;
        }

        const channelInput = document.getElementById('wasm-channel-code');
        if (channelInput) {
            channelInput.value = channelCode;
            channelInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            
            const consoleOutput = document.getElementById('wasm-output-console');
            if (consoleOutput) {
                consoleOutput.textContent += `\n[🔗] Client-Generated Invite Link Detected!\n    Channel Code: ${channelCode}\n    Ready to connect & decrypt.\n`;
            }
        }
    } catch (e) {
        console.warn('Failed to parse hash invite:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const savedLang = localStorage.getItem('zerofeed_lang') || 'en';
    setLanguage(savedLang);
    checkHashInvite();
});

window.addEventListener('hashchange', checkHashInvite);
