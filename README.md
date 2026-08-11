# ZeroFeed Web Landing Page & WebAssembly Client ⚡

> **Official Web Landing Page & Client-Side In-Browser E2EE WebAssembly Engine**

[![Live WSS Site](https://img.shields.io/badge/Live%20Site-GitHub%20Pages-brightgreen?style=flat-square&logo=github)](https://nicolainzerillo.github.io/ZeroFeed-Landing/)
[![WebAssembly Engine](https://img.shields.io/badge/WebAssembly-Client--Side%20RAM-blue?style=flat-square&logo=webassembly)](https://nicolainzerillo.github.io/ZeroFeed-Landing/)
[![PQC Standard](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM--768-purple?style=flat-square)](https://csrc.nist.gov/pubs/fips/203/final)
[![License](https://img.shields.io/badge/License-Apache%202.0-orange?style=flat-square)](LICENSE)

This repository contains the source code for the official ZeroFeed Web Landing Page and the in-browser WebAssembly E2EE decryption engine hosted live on GitHub Pages:

👉 **[https://nicolainzerillo.github.io/ZeroFeed-Landing/](https://nicolainzerillo.github.io/ZeroFeed-Landing/)**

---

## 📺 Live WebAssembly Streaming Demo

![ZeroFeed Live E2EE WebAssembly Stream Demo](docs/media/demo.png)

*Figure 1: Live E2EE stream broadcast from CLI Publisher terminal to WebAssembly browser subscriber with matching SAS Verification Badges.*

---

## 🌟 Features

- **🌐 100% In-Browser Decryption**: Zero installation, zero browser extensions, zero user account registration required.
- **🛡️ NIST FIPS 203 Hybrid PQC**: SPAKE2+ hybrid key exchange (ML-KEM-768 + X25519) executing directly inside WebAssembly browser RAM.
- **🔒 Privacy-Preserving Link Hash**: `zerofeed://` URIs and `#join=...` hash fragments are processed strictly inside the local browser DOM and are **never transmitted to GitHub or HTTP web servers**.
- **⚡ Native WSS Support**: Connects natively to `wss://zerofeed.duckdns.org:8444/` with Let's Encrypt TLS certificates.
- **🇮🇹 Bilingual Internationalization**: Full English and Italian interactive UI toggle.

---

## 🏗️ Repository Architecture

- `index.html`: Responsive, glassmorphism UI with live stream terminal logs, RFC specifications, and interactive WASM controls.
- `app.js`: Client-side JavaScript orchestration, WebSocket frame encoding/decoding, and UI event binding.
- `wasm_exec.js`: Official Go WebAssembly JavaScript bridge runner.
- `zerofeed.wasm`: Static WebAssembly binary compiled from `github.com/zerofeed/zerofeed/cmd/wasm`.
- `styles.css`: Pure CSS design system with responsive layouts, dark themes, and smooth micro-animations.

---

## 🛠️ Building WebAssembly from Source

To compile `zerofeed.wasm` from the main ZeroFeed repository:

```bash
# In the main ZeroFeed repository
GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o /path/to/ZeroFeed-Landing/zerofeed.wasm ./cmd/wasm
```

---

## ⚖️ License

Distributed under the **Apache License 2.0**. See `LICENSE` for details.
