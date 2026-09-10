# Git Secret & PII Sanitizer — Code Evolution Engine

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue?logo=typescript)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.3-61dafb?logo=react)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4-38bdf8?logo=tailwindcss)](https://tailwindcss.com/)
[![Gemini AI](https://img.shields.io/badge/AI-Google%20Gemini%20Pro-8e75ff?logo=google)](https://ai.google.dev/)
[![SARIF Compatible](https://img.shields.io/badge/Format-SARIF%20v2.1.0-orange)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

A developer-first security scanner, PII detector, Git commit history purge generator, SARIF exporter, and AI-powered Code Evolution Architect. Detect secrets and sensitive data across live code snippets, local project directories, and remote GitHub repositories before or after they leak.

---

## 🌟 Key Capabilities

- **40+ Detection Patterns & High-Entropy Analysis:** Identifies credentials across Cloud Providers (AWS, GCP, Azure), AI Platforms (OpenAI, Gemini, Anthropic, Hugging Face), Payment Gateways (Stripe, PayPal), Authentication Tokens (GitHub PAT/OAuth, JWT, Slack, Discord), Private Keys (RSA, SSH, PGP), and PII (Credit Cards, SSNs, IBANs, Emails, Phone Numbers).
- **Remote GitHub Repository Scanning:** Deep-scans repositories via GitHub REST API with recursive tree pagination, concurrency management, `X-RateLimit` tracking, and optional Personal Access Token (PAT) authentication for private repos.
- **Local Directory Auditing:** 100% client-side file scanning via the HTML5 File System Directory API. Scans local folders without uploading source files to any remote server, automatically filtering binaries, package managers, and large files.
- **Real-Time Live Snippet Redaction:** Side-by-side CodeMirror editors that highlight and surgically replace sensitive strings with contextual redaction masks (`<AWS_SECRET_KEY_REDACTED>`).
- **Git Commit History Purge Generator:** Generates automated shell scripts using `git-filter-repo --replace-text` to rewrite Git commit history across all branches and tags, permanently excising exposed secrets.
- **AI Code Evolution Architect (Google Gemini):** Leverages Google Gemini with reasoning thinking capabilities to analyze threat vectors, calculate organizational blast radius, review compliance obligations (GDPR, PCI-DSS, SOC 2, HIPAA), and generate clean, environment-variable-backed code refactorings.
- **Enterprise Reporting & SARIF Export:** Export scan results to SARIF v2.1.0 (directly uploadable to GitHub Code Scanning Alerts), structured JSON, or CSV.
- **Internationalization:** Native translation support covering 70+ languages powered by `xnx3/translate`.

---

## 🚀 Quick Start

### Prerequisites

- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **Gemini API Key**: Required for AI Evolution Architect features ([Get one at Google AI Studio](https://aistudio.google.com/))

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/craighckby-stack/Git-Secret-PII-Sanitizer.git
   cd Git-Secret-PII-Sanitizer
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Add your Gemini API key inside `.env`:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

4. **Run the development server:**
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🛠️ Application Modules

### 1. GitHub Repository Scanner (`GitHub Repo` Tab)
- Connect to any public or private GitHub repository (e.g., `https://github.com/owner/repository`).
- Branch selector automatically inspects available branches (`main`, `master`, `dev`, etc.).
- Real-time scanning progress tracking commit tree nodes, rate limits, and finding counts.
- Concurrency limiter with rate-limit throttling to prevent HTTP 403 secondary rate limit lockouts.

### 2. Live Snippet Sanitizer (`Live Snippet` Tab)
- Paste raw configuration blocks, `.env` files, source files, or terminal logs.
- Includes pre-loaded test samples for rapid verification across multi-cloud and PII credentials.
- Instant line-by-line syntax-highlighted redaction with one-click copy of sanitized text.

### 3. Local Folder Scanner (`Local Folder` Tab)
- Zero-cloud local disk scanning utilizing the browser's native File System directory access.
- Smart skip filters ignore binary assets (`.png`, `.exe`, `.wasm`, `.zip`), dependencies (`node_modules`, `vendor`), and lockfiles (`package-lock.json`, `yarn.lock`).
- Configurable per-file size cap (default: 8MB) to preserve browser memory.

### 4. Git History Purge Generator (`Generate Purge Script` Modal)
- When a secret has already been committed to Git history, deleting the file or committing a fix is insufficient.
- This generator synthesizes a clean, automated bash script utilizing `git-filter-repo` with custom replace-text expressions.
- Includes safety confirm verification (`DELETE`) to prevent accidental destruction of git trees.

### 5. AI Code Evolution Architect (`AI Architect` Tab)
- Send detected vulnerability contexts to Google Gemini for security reasoning.
- **Threat Vector & Blast Radius:** Outlines what an attacker can achieve with the leaked credential.
- **Compliance Audit:** Highlights regulations violated by the exposure (PCI-DSS §3.4, GDPR Art. 32, SOC 2 CC6.1).
- **Refactored Code Patch:** Ready-to-apply patch extracting credentials into environment variables or secrets managers (e.g., AWS Secrets Manager, HashiCorp Vault).
- **Interactive Security Advisor Chat:** Converse with Gemini about secret rotation procedures, webhook revoking, and Git pre-commit hooks.

### 6. Findings Table & Export Engine
- Severity filters: **Critical**, **High**, **Medium**, **Low**.
- Search by file path, pattern name, or matched string.
- Export formats:
  - **SARIF v2.1.0** for integration into GitHub Advanced Security or CI/CD pipelines.
  - **JSON** for programmatic analysis.
  - **CSV** for executive audit logging and spreadsheet triage.

---

## 🛡️ Supported Pattern Categories

| Category | Targeted Credential Types | Example Signatures |
| :--- | :--- | :--- |
| **Cloud Keys** | AWS Access & Secret Keys, Google Cloud API Keys, Azure Connection Strings | `AKIA[0-9A-Z]{16}`, `AIzaSy[0-9A-Za-z-_]{33}` |
| **AI & LLM Keys** | OpenAI API Keys, Anthropic API Keys, Gemini API Keys, Hugging Face Tokens | `sk-[a-zA-Z0-9]{32,}`, `sk-ant-api[0-9]{2}-...` |
| **Authentication & Tokens** | GitHub PAT / Fine-Grained Tokens, GitLab Tokens, JWTs, Bearer Tokens | `ghp_[a-zA-Z0-9]{36}`, `github_pat_[a-zA-Z0-9_]{82}` |
| **Payment & Finance** | Stripe Secret & Publishable Keys, PayPal Client Credentials, Square Access Tokens | `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_...` |
| **Database & Storage** | MongoDB Connection URIs, PostgreSQL/MySQL DSNs, Redis URLs | `mongodb(\+srv)?://...`, `postgres://...` |
| **Private Keys & Certs** | RSA, DSA, EC, OPENSSH, and PGP Private Key headers | `-----BEGIN (RSA\|OPENSSH) PRIVATE KEY-----` |
| **Communication & SaaS**| Slack Bot Tokens, Slack Webhooks, Discord Bot Tokens, Twilio API Keys | `xoxb-[0-9]{11,}`, `SK[0-9a-fA-F]{32}` |
| **PII & Financial Data**| Credit Card Numbers (Luhn-checked), US Social Security Numbers, IBAN Numbers | Standardized Luhn regex & national formats |

---

## 🏗️ Architecture & Tech Stack

```
├── server.ts                       # Express server proxying Gemini API & serving Vite SPA
├── src/
│   ├── components/
│   │   ├── AiEvolutionArchitect.tsx # Gemini-powered security analyst & chat
│   │   ├── CodeMirrorViewer.tsx    # CodeMirror 6 syntax-highlighted code editor
│   │   ├── FindingsTable.tsx       # Aggregated scan results with filters & exports
│   │   ├── FolderScanner.tsx       # Local directory file reader & filter
│   │   ├── GithubScanner.tsx       # GitHub REST API tree recursion & crawler
│   │   ├── LanguageSelector.tsx    # Multi-language selector (70+ languages)
│   │   ├── PurgeModal.tsx          # Git-filter-repo purge script generator
│   │   ├── SnippetScanner.tsx      # Side-by-side snippet redaction editor
│   │   └── StatsOverview.tsx       # Security posture dashboard & metrics
│   ├── lib/
│   │   ├── patterns.ts             # 40+ regex patterns & classification metadata
│   │   ├── purgeScript.ts          # Shell script builder for git-filter-repo
│   │   ├── sarifExporter.ts        # SARIF v2.1.0 schema generator
│   │   └── scanner.ts              # Core regex scanner & context snippet builder
│   ├── App.tsx                     # Main application layout & state coordinator
│   ├── main.tsx                    # React DOM entry point
│   └── types.ts                    # TypeScript schemas & type guards
```

---

## 📜 Scripts

| Command | Description |
| :--- | :--- |
| `npm run dev` | Boots the application in development mode via `tsx server.ts` |
| `npm run build` | Builds client assets with Vite and bundles server with esbuild |
| `npm run start` | Runs the compiled production server (`dist/server.cjs`) |
| `npm run lint` | Validates TypeScript types across the codebase (`tsc --noEmit`) |

---

## 🔒 Security Best Practices

1. **Never commit real credentials:** Treat every detection as potentially compromised. If a key is flagged, rotate it immediately with the issuing provider before purging history.
2. **Git Purge Caution:** Running `git-filter-repo` rewrites commit hashes. Always create a bare clone backup (`git clone --mirror <url>`) before executing history purge scripts.
3. **API Key Isolation:** The Gemini API key is configured strictly server-side in `server.ts` and is never exposed to client browsers.

---

## 📄 License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**.  
See [LICENSE](https://creativecommons.org/licenses/by-nc/4.0/) for details.

*Copyright © 2026 craighckby-stack.*
