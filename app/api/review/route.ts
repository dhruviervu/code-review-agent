import Groq from "groq-sdk";
import { NextResponse } from "next/server";

type ReviewRequest = {
  code?: string;
  language?: string;
};

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Category = "security" | "quality" | "performance" | "architecture" | "docs";

type Finding = {
  id: string;
  severity: Severity;
  category: Category;
  title: string;
  explanation: string;
  suggestion: string;
  line: number | null;
};

type AgentStatus = "success" | "failed";
type DetectedLanguage =
  | "python"
  | "javascript"
  | "typescript"
  | "java"
  | "go"
  | "rust"
  | "ruby"
  | "php"
  | "c++"
  | "unknown";

const SECURITY_PROMPT = `You are a senior security engineer performing a security audit.
Analyze the provided code ONLY for security vulnerabilities.
Focus on: SQL injection, XSS, hardcoded secrets, authentication flaws, 
insecure dependencies, input validation, sensitive data exposure, 
broken access control, security misconfigurations.
Return ONLY a valid raw JSON array of findings with no markdown, no backticks:
[
  {
    "id": "sec_1",
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "category": "security",
    "title": "Short title",
    "explanation": "What is wrong and why it matters",
    "suggestion": "Exact fix",
    "line": <number or null>
  }
]
If no security issues found, return empty array: []`;

const QUALITY_PROMPT = `You are a senior software engineer reviewing code quality.
Analyze the provided code ONLY for code quality issues.
Focus on: code complexity, poor naming, missing error handling, 
code duplication, dead code, poor structure, missing tests, 
unclear logic, bad practices for the language.
Return ONLY a valid raw JSON array of findings with no markdown, no backticks:
[
  {
    "id": "qual_1",
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "category": "quality",
    "title": "Short title",
    "explanation": "What is wrong and why it matters",
    "suggestion": "Exact fix",
    "line": <number or null>
  }
]
If no quality issues found, return empty array: []`;

const PERFORMANCE_PROMPT = `You are a senior performance engineer reviewing code efficiency.
Analyze the provided code ONLY for performance issues.
Focus on: inefficient algorithms, N+1 queries, unnecessary loops,
memory leaks, blocking operations, missing caching opportunities,
expensive operations inside loops, unoptimized data structures.
Return ONLY a valid raw JSON array of findings with no markdown, no backticks:
[
  {
    "id": "perf_1",
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "category": "performance",
    "title": "Short title",
    "explanation": "What is wrong and why it matters",
    "suggestion": "Exact fix",
    "line": <number or null>
  }
]
If no performance issues found, return empty array: []`;

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function detectLanguage(code: string): DetectedLanguage {
  const scores: Record<DetectedLanguage, number> = {
    python: 0,
    javascript: 0,
    typescript: 0,
    java: 0,
    go: 0,
    rust: 0,
    ruby: 0,
    php: 0,
    "c++": 0,
    unknown: 0,
  };

  // Python signals
  if (/^def\s+\w+\s*\(/m.test(code)) scores.python += 3;
  if (/^class\s+\w+.*:/m.test(code)) scores.python += 3;
  if (/^import\s+\w+/m.test(code)) scores.python += 2;
  if (/^from\s+\w+\s+import/m.test(code)) scores.python += 3;
  if (/elif\s+/.test(code)) scores.python += 3;
  if (/^\s*print\s*\(/m.test(code)) scores.python += 2;
  if (/__init__\s*\(/.test(code)) scores.python += 3;
  if (/:\s*$\n\s+\S/m.test(code)) scores.python += 2;
  if (/self\.\w+/.test(code)) scores.python += 3;
  if (/#.*$/m.test(code)) scores.python += 1;

  // JavaScript signals
  if (/\bconsole\.log\s*\(/.test(code)) scores.javascript += 3;
  if (/\brequire\s*\(\s*['"]/.test(code)) scores.javascript += 3;
  if (/\bmodule\.exports\b/.test(code)) scores.javascript += 4;
  if (/=>\s*\{/.test(code)) scores.javascript += 2;
  if (/\bvar\s+\w+\s*=/.test(code)) scores.javascript += 2;
  if (/\bdocument\.\w+/.test(code)) scores.javascript += 3;
  if (/\bwindow\.\w+/.test(code)) scores.javascript += 3;
  if (/\bPromise\s*\(/.test(code)) scores.javascript += 2;
  if (/\.then\s*\(/.test(code)) scores.javascript += 2;
  if (/\basync\s+function\b/.test(code)) scores.javascript += 2;

  // TypeScript signals (check before JS to outscore it)
  if (/\:\s*(string|number|boolean|void|any|never)\b/.test(code)) scores.typescript += 3;
  if (/\binterface\s+\w+\s*\{/.test(code)) scores.typescript += 4;
  if (/\btype\s+\w+\s*=/.test(code)) scores.typescript += 4;
  if (/<\w+(\[\])?>/.test(code)) scores.typescript += 2;
  if (/\benum\s+\w+\s*\{/.test(code)) scores.typescript += 4;
  if (/\bas\s+(string|number|boolean|\w+Type)/.test(code)) scores.typescript += 3;
  if (/\bReadonly</.test(code)) scores.typescript += 3;
  if (/\bPartial</.test(code)) scores.typescript += 3;
  if (/\bRecord</.test(code)) scores.typescript += 3;
  if (/\:\s*\w+\[\]\s*[=;{]/.test(code)) scores.typescript += 2;

  // Java signals
  if (/\bpublic\s+(static\s+)?class\s+\w+/.test(code)) scores.java += 4;
  if (/\bSystem\.out\.print/.test(code)) scores.java += 4;
  if (/\bpublic\s+static\s+void\s+main/.test(code)) scores.java += 5;
  if (/\bimport\s+java\./.test(code)) scores.java += 5;
  if (/\bnew\s+\w+\s*\(/.test(code)) scores.java += 2;
  if (/@Override\b/.test(code)) scores.java += 4;
  if (/\bprivate\s+\w+\s+\w+\s*;/.test(code)) scores.java += 3;
  if (/\bpublic\s+\w+\s+get\w+\s*\(\s*\)/.test(code)) scores.java += 3;
  if (/\bthrows\s+\w+Exception/.test(code)) scores.java += 4;
  if (/\bArrayList</.test(code)) scores.java += 4;

  // Go signals
  if (/^package\s+\w+/m.test(code)) scores.go += 5;
  if (/^func\s+\w+\s*\(/m.test(code)) scores.go += 4;
  if (/\bfmt\.(Println|Printf|Sprintf)\s*\(/.test(code)) scores.go += 5;
  if (/\:\=\s*/.test(code)) scores.go += 3;
  if (/\bgoroutine\b/.test(code)) scores.go += 5;
  if (/\bchan\s+\w+/.test(code)) scores.go += 5;
  if (/^import\s+\(/m.test(code)) scores.go += 3;
  if (/\bdefer\s+\w+/.test(code)) scores.go += 4;
  if (/\bgo\s+func\s*\(/.test(code)) scores.go += 5;
  if (/\berr\s*\!\=\s*nil/.test(code)) scores.go += 4;

  // Rust signals
  if (/^fn\s+\w+\s*\(/m.test(code)) scores.rust += 4;
  if (/\blet\s+mut\s+\w+/.test(code)) scores.rust += 4;
  if (/\bprintln!\s*\(/.test(code)) scores.rust += 5;
  if (/\bimpl\s+\w+/.test(code)) scores.rust += 4;
  if (/\buse\s+std::/.test(code)) scores.rust += 5;
  if (/\bmatch\s+\w+\s*\{/.test(code)) scores.rust += 3;
  if (/=>\s*\w+/.test(code)) scores.rust += 2;
  if (/\bOwned\b|\bBorrow\b|\bClone\b/.test(code)) scores.rust += 3;
  if (/\b&mut\s+\w+/.test(code)) scores.rust += 4;
  if (/\bResult</.test(code)) scores.rust += 3;

  // Ruby signals
  if (/^def\s+\w+/m.test(code)) scores.ruby += 3;
  if (/\bend\s*$/.test(code)) scores.ruby += 3;
  if (/\bputs\s+/.test(code)) scores.ruby += 4;
  if (/\battr_accessor\b/.test(code)) scores.ruby += 5;
  if (/\brequire\s+'/.test(code)) scores.ruby += 3;
  if (/\bdo\s*\|/.test(code)) scores.ruby += 4;
  if (/\|[\w,\s]+\|/.test(code)) scores.ruby += 3;
  if (/\.each\s+do/.test(code)) scores.ruby += 4;
  if (/\bnil\b/.test(code)) scores.ruby += 2;
  if (/#.*$/m.test(code) && /\bend\b/.test(code)) scores.ruby += 2;

  // PHP signals
  if (/^<\?php/m.test(code)) scores.php += 6;
  if (/\$\w+\s*=/.test(code)) scores.php += 3;
  if (/\becho\s+/.test(code)) scores.php += 3;
  if (/\bfunction\s+\w+\s*\(/.test(code) && /\$\w+/.test(code)) scores.php += 3;
  if (/\b\$this->\w+/.test(code)) scores.php += 5;
  if (/\barray\s*\(/.test(code)) scores.php += 3;
  if (/\bforeach\s*\(/.test(code) && /\$\w+/.test(code)) scores.php += 4;
  if (/->/.test(code) && /\$\w+/.test(code)) scores.php += 2;
  if (/\bnew\s+\w+\s*\(/.test(code) && /\$\w+/.test(code)) scores.php += 2;

  // C++ signals
  if (/#include\s*</.test(code)) scores["c++"] += 4;
  if (/\bstd::\w+/.test(code)) scores["c++"] += 4;
  if (/\bcout\s*<</.test(code)) scores["c++"] += 5;
  if (/\bcin\s*>>/.test(code)) scores["c++"] += 5;
  if (/\bint\s+main\s*\(/.test(code)) scores["c++"] += 4;
  if (/\bnamespace\s+\w+/.test(code)) scores["c++"] += 4;
  if (/\btemplate\s*</.test(code)) scores["c++"] += 5;
  if (/\bnew\s+\w+\[/.test(code)) scores["c++"] += 3;
  if (/\bdelete\[\]/.test(code)) scores["c++"] += 5;
  if (/\bvector</.test(code)) scores["c++"] += 4;

  // Find highest scoring language
  let topLanguage: DetectedLanguage = "unknown";
  let topScore = 0;

  for (const [lang, score] of Object.entries(scores)) {
    if (lang === "unknown") continue;
    if (score > topScore) {
      topScore = score;
      topLanguage = lang as DetectedLanguage;
    }
  }

  // Require minimum confidence score of 4 to make a call
  // Below that, too uncertain — return unknown
  if (topScore < 4) return "unknown";

  // TypeScript must outscore JavaScript by at least 3 points
  // to avoid JS code with one type annotation being called TS
  if (
    topLanguage === "typescript" &&
    scores.typescript - scores.javascript < 3
  ) {
    return "javascript";
  }

  // Python vs Ruby disambiguation — both use def and end-like patterns
  if (topLanguage === "ruby" && scores.python > 0) {
    if (/self\./.test(code) || /^from\s+\w+\s+import/m.test(code)) {
      return "python";
    }
  }

  return topLanguage;
}

function normalizeRequestedLanguage(language: string): string {
  const normalized = language.trim().toLowerCase();
  if (normalized === "c++" || normalized === "cpp") {
    return "c++";
  }
  return normalized;
}

function promptLanguageLabel(language: string): string {
  const labels: Record<string, string> = {
    javascript: "JavaScript",
    typescript: "TypeScript",
    python: "Python",
    java: "Java",
    go: "Go",
    rust: "Rust",
    ruby: "Ruby",
    php: "PHP",
    "c++": "C++",
    other: "Other",
  };
  return labels[language] ?? language;
}

function parseReviewJsonArray(rawText: string): Finding[] {
  const normalized = rawText.trim();
  if (!normalized) {
    throw new Error("Model returned an empty response.");
  }

  try {
    const parsed = JSON.parse(normalized);
    if (!Array.isArray(parsed)) {
      throw new Error("Model returned JSON that is not an array.");
    }
    return parsed as Finding[];
  } catch {
    const firstBracket = normalized.indexOf("[");
    const lastBracket = normalized.lastIndexOf("]");
    if (firstBracket !== -1 && lastBracket !== -1 && lastBracket > firstBracket) {
      const jsonSlice = normalized.slice(firstBracket, lastBracket + 1);
      return JSON.parse(jsonSlice);
    }

    throw new Error("Model returned invalid JSON array.");
  }
}

function getCompletionText(
  completion: Groq.Chat.Completions.ChatCompletion
): string {
  const content = completion.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("Groq returned no completion text.");
  }

  return Array.isArray(content)
    ? content
        .map((part) => ("text" in part && part.text ? part.text : ""))
        .join("")
    : content;
}

async function runAgent(
  client: Groq,
  systemPrompt: string,
  code: string,
  language: string
): Promise<Finding[]> {
  const completion = await client.chat.completions.create({
    model: "llama-3.3-70b-versatile",
    temperature: 0,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: `Review this ${language} code:\n\n${code}` },
    ],
  });

  const rawText = getCompletionText(completion);
  return parseReviewJsonArray(rawText);
}

async function runSecurityAgent(client: Groq, code: string, language: string) {
  return runAgent(client, SECURITY_PROMPT, code, language);
}

async function runQualityAgent(client: Groq, code: string, language: string) {
  return runAgent(client, QUALITY_PROMPT, code, language);
}

async function runPerformanceAgent(client: Groq, code: string, language: string) {
  return runAgent(client, PERFORMANCE_PROMPT, code, language);
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.title}::${finding.line === null ? "null" : String(finding.line)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(finding);
  }

  return unique;
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

function buildSummary(findings: Finding[]): string {
  if (findings.length === 0) {
    return "No major issues found across security, quality, or performance.";
  }

  const criticalSecurity = findings.filter(
    (finding) => finding.category === "security" && finding.severity === "critical"
  ).length;
  const qualityProblems = findings.filter((finding) => finding.category === "quality").length;
  const performanceProblems = findings.filter(
    (finding) => finding.category === "performance"
  ).length;

  const parts: string[] = [];
  if (criticalSecurity > 0) {
    parts.push(`${criticalSecurity} critical security issue${criticalSecurity === 1 ? "" : "s"}`);
  }
  if (qualityProblems > 0) {
    parts.push(`${qualityProblems} quality problem${qualityProblems === 1 ? "" : "s"}`);
  }
  if (performanceProblems > 0) {
    parts.push(
      `${performanceProblems} performance issue${performanceProblems === 1 ? "" : "s"}`
    );
  }

  if (parts.length === 0) {
    return `Found ${findings.length} issue${findings.length === 1 ? "" : "s"} in the review.`;
  }

  return `Found ${parts.join(" and ")}.`;
}

function calculateScore(findings: Finding[]): number {
  let score = 100;
  for (const finding of findings) {
    if (finding.severity === "critical") {
      score -= 20;
    } else if (finding.severity === "high") {
      score -= 10;
    } else if (finding.severity === "medium") {
      score -= 5;
    } else if (finding.severity === "low") {
      score -= 2;
    }
  }
  return Math.max(0, score);
}

export async function POST(request: Request) {
  let body: ReviewRequest;

  try {
    body = (await request.json()) as ReviewRequest;
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON payload." },
      { status: 400 }
    );
  }

  const code = body.code?.trim();
  const language = body.language?.trim();

  if (!code) {
    return NextResponse.json(
      { error: "Code is required." },
      { status: 400 }
    );
  }

  if (code.length > 10000) {
    return NextResponse.json(
      { error: "Code must be 10000 characters or fewer." },
      { status: 400 }
    );
  }

  if (!language) {
    return NextResponse.json(
      { error: "Language is required." },
      { status: 400 }
    );
  }

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "Server misconfiguration: GROQ_API_KEY is missing." },
      { status: 500 }
    );
  }

  const client = new Groq({ apiKey });
  const requestedLanguage = normalizeRequestedLanguage(language);
  const detectedLanguage = detectLanguage(code);
  const shouldOverrideLanguage =
    requestedLanguage !== "other" &&
    detectedLanguage !== "unknown" &&
    detectedLanguage !== requestedLanguage;
  const effectiveLanguageToken = shouldOverrideLanguage ? detectedLanguage : requestedLanguage;
  const effectiveLanguage = promptLanguageLabel(effectiveLanguageToken);

  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder();
      const send = (data: object) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      };

      const findingsByAgent: {
        security: Finding[];
        quality: Finding[];
        performance: Finding[];
      } = {
        security: [],
        quality: [],
        performance: [],
      };

      const agentResults: {
        security: AgentStatus;
        quality: AgentStatus;
        performance: AgentStatus;
      } = {
        security: "failed",
        quality: "failed",
        performance: "failed",
      };

      const securityPromise = (async () => {
        try {
          const findings = await runSecurityAgent(client, code, effectiveLanguage);
          findingsByAgent.security = findings;
          agentResults.security = "success";
          send({ type: "agent_complete", agent: "security", findings });
        } catch {
          agentResults.security = "failed";
          send({ type: "agent_error", agent: "security", message: "Agent failed" });
        }
      })();

      const qualityPromise = (async () => {
        try {
          const findings = await runQualityAgent(client, code, effectiveLanguage);
          findingsByAgent.quality = findings;
          agentResults.quality = "success";
          send({ type: "agent_complete", agent: "quality", findings });
        } catch {
          agentResults.quality = "failed";
          send({ type: "agent_error", agent: "quality", message: "Agent failed" });
        }
      })();

      const performancePromise = (async () => {
        try {
          const findings = await runPerformanceAgent(client, code, effectiveLanguage);
          findingsByAgent.performance = findings;
          agentResults.performance = "success";
          send({ type: "agent_complete", agent: "performance", findings });
        } catch {
          agentResults.performance = "failed";
          send({ type: "agent_error", agent: "performance", message: "Agent failed" });
        }
      })();

      await Promise.allSettled([securityPromise, qualityPromise, performancePromise]);

      const combinedFindings: Finding[] = [
        ...findingsByAgent.security,
        ...findingsByAgent.quality,
        ...findingsByAgent.performance,
      ];
      const dedupedFindings = dedupeFindings(combinedFindings);
      const sortedFindings = sortBySeverity(dedupedFindings);
      const summary = buildSummary(sortedFindings);
      const score = calculateScore(sortedFindings);

      send({
        type: "complete",
        summary,
        score,
        findings: sortedFindings,
        agentResults,
        ...(shouldOverrideLanguage
          ? {
              languageOverride: {
                requested: requestedLanguage,
                detected: detectedLanguage,
                message: `We detected ${promptLanguageLabel(
                  detectedLanguage
                )} instead of ${promptLanguageLabel(
                  requestedLanguage
                )} — switching automatically`,
              },
            }
          : {}),
      });

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
