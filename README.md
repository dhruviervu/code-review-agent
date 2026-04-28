# 🧠 AI Code Review Agent

An AI-powered code review tool that analyzes your code across **security, quality, and performance** using multiple specialized agents — all in real time.

Built with Next.js and Groq LLMs, this app provides fast, structured, and actionable feedback similar to a senior engineer review.

---

## 🚀 Features

* 🔍 **Multi-Agent Code Review**

  * Security Agent (vulnerabilities, secrets, auth issues)
  * Quality Agent (structure, readability, best practices)
  * Performance Agent (efficiency, bottlenecks)

* ⚡ **Real-Time Streaming Results**

  * Each agent responds independently
  * Results stream live to the UI

* 📂 **Flexible Input**

  * Paste code directly
  * Upload multiple files

* 📊 **Structured Output**

  * Severity levels (Critical → Info)
  * Categorized findings
  * Line-level insights (when available)

* 📈 **Scoring System**

  * Automated code quality score (0–100)

* 📥 **Export Options**

  * Download Markdown report
  * Export raw JSON results

---

## 🛠️ Tech Stack

* **Frontend:** Next.js 16, React 19, TailwindCSS 
* **Backend:** Next.js API Routes (Edge-compatible streaming) 
* **AI:** Groq SDK (LLaMA 3.3 70B) 
* **Styling:** TailwindCSS + custom theme 

---

## 📦 Installation

```bash
git clone https://github.com/your-username/code-review-agent.git
cd code-review-agent
npm install
```

---

## 🔑 Environment Variables

Create a `.env.local` file:

```env
GROQ_API_KEY=your_api_key_here
```

---

## 💻 Running Locally

```bash
npm run dev
```

Then open:

```
http://localhost:3000
```

---

## ⚙️ How It Works

1. User submits code (paste or upload)
2. Backend splits review into **3 parallel AI agents**
3. Each agent analyzes a specific concern:

   * Security
   * Code Quality
   * Performance
4. Results are streamed back using **Server-Sent Events (SSE)** 
5. Findings are:

   * Deduplicated
   * Sorted by severity
   * Combined into a final report
6. A score and summary are generated

---

## 📁 Project Structure

```
app/
├── page.tsx        # Main UI (client)
├── layout.tsx      # Root layout
├── globals.css     # Styling
├── api/
│   └── review/
│       └── route.ts  # AI agents + streaming logic
```

---

## 🧠 Key Design Decisions

### Multi-Agent Architecture

Instead of a single LLM call, the system uses **specialized prompts per domain**, improving accuracy and clarity.

### Streaming Responses

Uses `ReadableStream` + SSE to deliver results progressively rather than waiting for full completion.

### Language Detection

Automatically detects the programming language and overrides user selection when necessary.

### Deduplication Logic

Findings are merged and deduplicated to avoid repeated issues across agents.

---

## ⚠️ Limitations

* Max input size: **10,000 characters** 
* LLM responses may occasionally return malformed JSON (handled with fallback parsing)
* Language detection is heuristic-based (not 100% accurate)
* No authentication or user history (stateless)

---

## 🔮 Future Improvements

* User accounts & saved reports
* GitHub repo integration
* More agents (e.g., testing, architecture deep dive)
* Better language detection (AST-based)
* Rate limiting & caching
* UI enhancements (filters, grouping, charts)

---

## 🚀 Deployment (Vercel)

1. Push code to GitHub
2. Go to Vercel
3. Import repository
4. Add environment variable:

   ```
   GROQ_API_KEY
   ```
5. Deploy

---

## 📌 Example Use Cases

* Reviewing pull requests quickly
* Learning best practices
* Catching security issues early
* Preparing for technical interviews

---

## 📄 License

MIT License

---

## 👨‍💻 Author

Built by [Your Name]

---

## ⭐ Final Note

This project demonstrates:

* Full-stack development (Next.js)
* AI integration (LLMs)
* Streaming architecture
* Real-world problem solving

Perfect for showcasing in a portfolio or interviews.
