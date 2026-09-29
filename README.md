# 🛡️ Nexus AI: Autonomous AppSec Remediation Engine
**Official Submission Handbook & User Guide**

---

## 1. Project Title Options
*   **Nexus AI:** Autonomous AppSec Remediation Engine
*   **Aegis:** Self-Healing Vulnerability Patcher
*   **Sentinel:** Hindsight-Driven Security Auditor
*   **OpenClaw:** Autonomous CVE Patching & Memory Framework

---

## 2. Executive Summary
Modern security tools are great at flagging vulnerabilities (CVEs), but terrible at actually fixing them. Auto-generated patches routinely break application code (e.g., ESM vs CommonJS conflicts). 

**Nexus AI** bridges this gap. It is an autonomous Application Security (AppSec) agent that doesn't just suggest fixes—it actively tests them in a local sandbox, evaluates build failures, and remembers the outcomes. Utilizing a custom **Hindsight Memory Framework**, Nexus AI generates "Reflection Rules" from its failures so it never makes the same mistake twice.

---

## 3. Deployment & Open-Source Availability
To ensure accessibility and collaboration, the entire Nexus AI ecosystem has been successfully deployed to the cloud:
*   **GitHub Repository:** The complete source code, memory engine, and UI are fully version-controlled and pushed to a public GitHub repository. This allows for open-source community contributions and easy auditing.
*   **Cloud Hosting (Render):** The application is hosted live on Render.com. The Python FastAPI backend and HTML frontend are seamlessly served via Uvicorn, allowing users to access the autonomous agent 24/7 via a public `.onrender.com` URL without needing to run the sandbox locally.

---

## 4. Core Features & UI Walkthrough

### A. The Dual Interface (Simple vs. Advanced)
Nexus AI respects user workflows by offering two toggleable interfaces without losing state:
1.  **Classic Mode:** A distraction-free, standard chat environment for quick security Q&A.
2.  **Advanced Workspace:** A highly dense, dark-mode dashboard designed for power users.

> *(Insert your uploaded screenshot of the Advanced UI Dashboard here)*
*The Advanced UI features side-by-side components: The main chat interface, a local terminal scratchpad for real-time log monitoring, and a dedicated code-generation panel.*

### B. Knowledge Feeding (Dynamic Context)
Users can train the model dynamically without expensive fine-tuning. 
*   **How it works:** Locate the **"Upload Knowledge"** dropzone on the left sidebar.
*   Users can upload vulnerability reports, audit logs, or architecture diagrams (`.PDF`, `.TXT`, `.MD`).
*   The backend extracts the text, vectorizes the context, and permanently injects it into the agent's contextual memory (`memory.json`).

### C. Hindsight Memory Framework
Nexus AI is governed by a strict operational rubric:
*   **Retain:** The agent stores patch outcomes and terminal logs.
*   **Reflect:** It evaluates why a build broke (e.g., *"Upgrading node-fetch to 3.x breaks CommonJS imports"*).
*   **Recall:** When asked to patch a similar repository, the agent recalls past failures and automatically formulates a bypass (like creating a compatibility shim) on Attempt 1.

> *(Insert your uploaded screenshot of the Chat UI answering the test prompt here)*

### D. Autonomous Self-Healing Loop
When asked to write a patch, Nexus AI doesn't just return code—it executes it.
1.  The agent writes a fix.
2.  It runs a background bash command (e.g., `npm ci && npm test`).
3.  If the test fails, it intercepts the `stderr` logs, reads the failure, re-writes the patch, and tries again (up to a hard cap of 3 attempts).

---

## 5. Technical Architecture
*   **Backend:** Python, FastAPI, Uvicorn (Asynchronous HTTP server).
*   **AI Engine:** Groq API routing Llama-3 (or GPT-oss) via the `litellm` gateway.
*   **Frontend:** HTML5, Tailwind CSS, Vanilla JS.
*   **State Management:** Stateless API endpoints reading/writing to a local persistent `memory.json` engine. 
*   **Rate Limit Protection:** Built-in sleep triggers catch API `429 Too Many Requests` errors to respect free-tier TPM limits without crashing.

---

## 6. Quick Start Guide
**Live Cloud Access:**
1. Navigate to the project's official `.onrender.com` web URL.
2. The server handles all model requests and memory retention automatically in the cloud.

**Local Development:**
1. Clone the GitHub repository.
2. Run `pip install -r requirements.txt`
3. Launch the server: `python -m uvicorn server:app --host 127.0.0.1 --port 8001`
4. Access the UI at `http://127.0.0.1:8001/`
5. Drag and drop a `.PDF` vulnerability report to train the model, or type *"Formulate a patch plan for this report"*!
