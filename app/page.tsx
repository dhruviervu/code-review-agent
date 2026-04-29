"use client";

import { ChangeEvent, DragEvent, FormEvent, useRef, useState } from "react";

const LANGUAGE_OPTIONS = [
  "JavaScript",
  "TypeScript",
  "Python",
  "Java",
  "Go",
  "Rust",
  "C++",
  "Other",
];
const ACCEPTED_CODE_EXTENSIONS = [
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".py",
  ".java",
  ".go",
  ".rs",
  ".cpp",
  ".c",
  ".cs",
  ".php",
  ".rb",
];
const ACCEPTED_CODE_FILES = ACCEPTED_CODE_EXTENSIONS.join(",");

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Category = "security" | "quality" | "performance" | "architecture" | "docs";

type ReviewFinding = {
  id: string;
  severity: Severity;
  category: Category;
  title: string;
  explanation: string;
  suggestion: string;
  line: number | null;
};

type ReviewResponse = {
  summary?: string;
  score?: number;
  findings: ReviewFinding[];
  languageOverride?: {
    requested: string;
    detected: string;
    message: string;
  };
};
type AgentName = "security" | "quality" | "performance";
type AgentUiStatus = "pending" | "success" | "failed";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-300 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
  info: "bg-gray-500/20 text-gray-300 border border-gray-500/40",
};
type StreamEvent =
  | { type: "agent_complete"; agent: AgentName; findings: ReviewFinding[] }
  | { type: "agent_error"; agent: AgentName; message?: string }
  | {
      type: "complete";
      summary?: string;
      score?: number;
      findings?: ReviewFinding[];
      languageOverride?: ReviewResponse["languageOverride"];
    };

export default function Home() {
  const [activeTab, setActiveTab] = useState<"paste" | "upload">("paste");
  const [uploadedFiles, setUploadedFiles] = useState<
    Array<{ name: string; size: number; content: string }>
  >([]);
  const [language, setLanguage] = useState<string>("JavaScript");
  const [code, setCode] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [results, setResults] = useState<ReviewResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);
  const [isReviewComplete, setIsReviewComplete] = useState<boolean>(false);
  const [agentStatus, setAgentStatus] = useState<Record<AgentName, AgentUiStatus>>({
    security: "pending",
    quality: "pending",
    performance: "pending",
  });
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const severityRank: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const generateReport = (reviewResults: ReviewResponse, selectedLanguage: string, date: string) => {
    const severityEmoji: Record<Severity, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🔵",
      info: "⚪",
    };

    const findings = reviewResults.findings;
    const groupedFindings: Record<Severity, ReviewFinding[]> = {
      critical: findings.filter((f) => f.severity === "critical"),
      high: findings.filter((f) => f.severity === "high"),
      medium: findings.filter((f) => f.severity === "medium"),
      low: findings.filter((f) => f.severity === "low"),
      info: findings.filter((f) => f.severity === "info"),
    };

    let md = "# Code Review Report\n";
    md += `**Generated:** ${date}\n`;
    md += `**Language:** ${selectedLanguage}\n\n`;
    md += "---\n\n";
    md += `## Overall Score: ${reviewResults.score ?? 0}/100\n`;
    md += `> ${reviewResults.summary ?? ""}\n\n`;
    md += "---\n\n";

    for (const [severity, severityFindings] of Object.entries(groupedFindings)) {
      if (severityFindings.length === 0) {
        continue;
      }
      const typedSeverity = severity as Severity;
      md += `## ${severityEmoji[typedSeverity]} ${
        typedSeverity.charAt(0).toUpperCase() + typedSeverity.slice(1)
      } (${severityFindings.length})\n\n`;

      for (const finding of severityFindings) {
        md += `### ${finding.title}\n`;
        md += `- **Category:** ${finding.category}\n`;
        if (finding.line) {
          md += `- **Line:** ${finding.line}\n`;
        }
        md += `- **Explanation:** ${finding.explanation}\n`;
        md += `- **Fix:** ${finding.suggestion}\n\n`;
        md += "---\n\n";
      }
    }

    if (reviewResults.findings.length === 0) {
      md += "## ✅ No Issues Found\n";
      md += "The code looks clean with no significant issues detected.\n";
    }

    return md;
  };

  const downloadReport = () => {
    if (!results) {
      return;
    }
    const markdown = generateReport(results, language, new Date().toLocaleDateString());
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `code-review-${new Date().toISOString().split("T")[0]}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadJson = () => {
    if (!results) {
      return;
    }
    const blob = new Blob([JSON.stringify(results, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `code-review-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const readFileContent = (file: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
      reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
      reader.readAsText(file);
    });

  const processFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) {
      return;
    }

    const loadedFiles: Array<{ name: string; size: number; content: string }> = [];
    for (const file of Array.from(files)) {
      const content = await readFileContent(file);
      const totalChars = content.length;
      const nonPrintableChars = Array.from(content).filter((char) => {
        const codePoint = char.charCodeAt(0);
        return codePoint < 32 && codePoint !== 9 && codePoint !== 10 && codePoint !== 13;
      }).length;
      const nonPrintableRatio = totalChars === 0 ? 0 : nonPrintableChars / totalChars;

      if (nonPrintableRatio > 0.1) {
        setErrorMessage(`${file.name} could not be read — binary files are not supported.`);
        continue;
      }

      loadedFiles.push({
        name: file.name,
        size: file.size,
        content,
      });
    }

    setUploadedFiles((previous) => [...previous, ...loadedFiles]);
  };

  const handleFileInputChange = async (event: ChangeEvent<HTMLInputElement>) => {
    try {
      await processFiles(event.target.files);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to read selected files.";
      setErrorMessage(message);
    } finally {
      event.target.value = "";
    }
  };

  const handleDrop = async (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragOver(false);

    try {
      await processFiles(event.dataTransfer.files);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to read dropped files.";
      setErrorMessage(message);
    }
  };

  const removeUploadedFile = (fileName: string, index: number) => {
    setUploadedFiles((previous) =>
      previous.filter((file, fileIndex) => !(file.name === fileName && fileIndex === index))
    );
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setResults(null);
    setIsReviewComplete(false);
    setAgentStatus({
      security: "pending",
      quality: "pending",
      performance: "pending",
    });
    setLoading(true);
    setErrorMessage(null);

    const codeToReview =
      activeTab === "paste"
        ? code
        : uploadedFiles
            .map((file) => `=== ${file.name} ===\n${file.content}`)
            .join("\n\n");

    // Minimum length check
    if (activeTab === "paste" && code.trim().length < 20) {
      setErrorMessage("Please enter at least a few lines of code to review.");
      setLoading(false);
      return;
    }

    try {
      const response = await fetch("/api/review", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code: codeToReview, language }),
      });

      if (!response.ok) {
        let errorMessage = `Review request failed with status ${response.status}`;

        try {
          const errorBody = (await response.json()) as {
            error?: string;
            message?: string;
          };
          const details = errorBody.message ?? errorBody.error;
          if (details) {
            errorMessage = details;
          }
        } catch {
          // Keep fallback status-based message.
        }

        throw new Error(errorMessage);
      }

      if (!response.body) {
        throw new Error("Review stream was not available.");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split("\n\n");
        buffer = events.pop() ?? "";

        for (const eventChunk of events) {
          const line = eventChunk
            .split("\n")
            .find((eventLine) => eventLine.startsWith("data: "));
          if (!line) {
            continue;
          }

          const data = JSON.parse(line.replace("data: ", "")) as StreamEvent;

          if (data.type === "agent_complete" && Array.isArray(data.findings)) {
            setAgentStatus((previous) => ({ ...previous, [data.agent]: "success" }));
            setResults((prev) => {
              const allFindings = [...(prev?.findings ?? []), ...data.findings];
              const sorted = allFindings.sort(
                (a, b) => severityRank[a.severity] - severityRank[b.severity]
              );
              return { ...(prev ?? { findings: [] }), findings: sorted };
            });
          }

          if (data.type === "agent_error") {
            setAgentStatus((previous) => ({ ...previous, [data.agent]: "failed" }));
          }

          if (data.type === "complete") {
            setResults((previous) => ({
              ...(previous ?? {}),
              summary: data.summary,
              score: data.score,
              findings: data.findings ?? previous?.findings ?? [],
              languageOverride: data.languageOverride,
            }));
            setIsReviewComplete(true);
          }
        }
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to review code.";
      setErrorMessage(message);
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 px-4 py-10 text-white">
      <main className="mx-auto w-full max-w-3xl">
        <header className="mb-8 text-center">
          <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Code Review Agent
          </h1>
          <p className="mt-3 text-base text-gray-300 sm:text-lg">
            Paste your code and get an instant senior engineer review
          </p>
        </header>

        <form
          onSubmit={handleSubmit}
          className="space-y-5 rounded-xl border border-gray-800 bg-gray-950/80 p-6 shadow-2xl"
        >
          <div className="rounded-full bg-gray-800 p-1">
            <div className="grid grid-cols-2 gap-1">
              <button
                type="button"
                onClick={() => setActiveTab("paste")}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  activeTab === "paste"
                    ? "bg-indigo-600 text-white"
                    : "bg-gray-700 text-gray-200 hover:bg-gray-600"
                }`}
              >
                Paste Code
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("upload")}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  activeTab === "upload"
                    ? "bg-indigo-600 text-white"
                    : "bg-gray-700 text-gray-200 hover:bg-gray-600"
                }`}
              >
                Upload Files
              </button>
            </div>
          </div>

          <div className="space-y-2">
            <label
              htmlFor="language"
              className="block text-sm font-medium text-gray-200"
            >
              Programming Language
            </label>
            <select
              id="language"
              value={language}
              onChange={(event) => setLanguage(event.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-900 px-4 py-3 text-white outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/40"
            >
              {LANGUAGE_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>

          {activeTab === "paste" ? (
            <div className="space-y-2">
              <label htmlFor="code" className="block text-sm font-medium text-gray-200">
                Code
              </label>
              <textarea
                id="code"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="Paste your code here..."
                className="min-h-[400px] w-full rounded-lg border border-gray-700 bg-gray-900 px-4 py-3 font-mono text-sm text-gray-100 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/40"
                required
              />
              <p
                className={`text-right text-xs ${
                  code.length > 10000
                    ? "text-red-400"
                    : code.length > 8000
                      ? "text-yellow-300"
                      : "text-gray-400"
                }`}
              >
                {code.length} / 10,000
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <input
                ref={fileInputRef}
                type="file"
                accept={ACCEPTED_CODE_FILES}
                multiple
                onChange={handleFileInputChange}
                className="hidden"
              />
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(event) => {
                  event.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={(event) => {
                  event.preventDefault();
                  setIsDragOver(false);
                }}
                onDrop={handleDrop}
                className={`flex min-h-[200px] cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed bg-gray-800 px-4 text-center transition ${
                  isDragOver
                    ? "border-indigo-500"
                    : "border-gray-700 hover:border-indigo-400"
                }`}
              >
                <p className="text-base font-medium text-gray-100">Drop your code files here</p>
                <p className="mt-2 text-sm text-gray-300">or click to browse</p>
              </div>

              {uploadedFiles.length > 0 && (
                <div className="space-y-2">
                  {uploadedFiles.map((file, index) => (
                    <div
                      key={`${file.name}-${index}`}
                      className="flex items-center justify-between rounded-lg border border-gray-700 bg-gray-900 px-3 py-2"
                    >
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-gray-100">{file.name}</p>
                        <p className="text-xs text-gray-400">
                          {(file.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => removeUploadedFile(file.name, index)}
                        className="ml-3 rounded px-2 py-1 text-sm text-gray-300 transition hover:bg-gray-700 hover:text-white"
                        aria-label={`Remove ${file.name}`}
                      >
                        X
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || (activeTab === "upload" && uploadedFiles.length === 0)}
            className="flex w-full items-center justify-center rounded-lg bg-indigo-600 px-5 py-4 text-lg font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-70"
          >
            {loading ? (
              <span className="flex items-center gap-3">
                <svg
                  className="h-5 w-5 animate-spin"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                  aria-hidden="true"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-90"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                  />
                </svg>
                Reviewing...
              </span>
            ) : (
              "Review My Code"
            )}
          </button>
        </form>

        {loading && !isReviewComplete && (
          <section className="mt-6 rounded-xl border border-gray-700 bg-gray-900/60 p-4">
            <div className="flex flex-wrap items-center gap-4 text-sm">
              {(["security", "quality", "performance"] as AgentName[]).map((agent) => {
                const status = agentStatus[agent];
                const label = `${agent.charAt(0).toUpperCase()}${agent.slice(1)} Agent`;
                if (status === "success") {
                  return (
                    <div key={agent} className="flex items-center gap-2 text-green-300">
                      <span aria-hidden="true">✅</span>
                      <span>{label}</span>
                    </div>
                  );
                }
                if (status === "failed") {
                  return (
                    <div key={agent} className="flex items-center gap-2 text-red-300">
                      <span aria-hidden="true">❌</span>
                      <span>{label}</span>
                    </div>
                  );
                }
                return (
                  <div key={agent} className="flex items-center gap-2 text-gray-300">
                    <svg
                      className="h-4 w-4 animate-spin"
                      viewBox="0 0 24 24"
                      fill="none"
                      xmlns="http://www.w3.org/2000/svg"
                      aria-hidden="true"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-90"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                      />
                    </svg>
                    <span>{label}</span>
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {results?.languageOverride && (
          <section className="mt-8 rounded-xl border border-yellow-700/50 bg-yellow-900/50 p-4">
            <p className="flex items-start gap-2 text-sm text-yellow-200">
              <span aria-hidden="true">⚠️</span>
              <span>{results.languageOverride.message}</span>
            </p>
          </section>
        )}

        {errorMessage && (
          <section className="mt-8 rounded-xl border border-red-500/40 bg-red-500/10 p-6">
            <h2 className="text-lg font-semibold text-red-200">Review failed</h2>
            <p className="mt-2 text-sm text-red-100">{errorMessage}</p>
          </section>
        )}

        {results && (
          <section className="mt-8 rounded-xl border border-gray-800 bg-gray-900/60 p-6">
            <h2 className="text-lg font-semibold text-white">Review Results</h2>
            {isReviewComplete && results.summary !== undefined && results.score !== undefined ? (
              <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto] sm:items-center">
                <p className="text-sm text-gray-200">{results.summary}</p>
                <div className="flex items-center gap-2 justify-self-end">
                  <span className="inline-flex items-center justify-center rounded-md border border-indigo-500/40 bg-indigo-500/20 px-3 py-1 text-sm font-semibold text-indigo-200">
                    Score: {results.score}/100
                  </span>
                  <button
                    type="button"
                    onClick={downloadReport}
                    className="inline-flex items-center gap-2 rounded-md bg-gray-700 px-3 py-1 text-sm font-medium text-gray-100 transition hover:bg-gray-600"
                  >
                    <span aria-hidden="true">⬇️</span>
                    Export Report
                  </button>
                  <button
                    type="button"
                    onClick={downloadJson}
                    className="inline-flex items-center gap-2 rounded-md bg-gray-700 px-3 py-1 text-sm font-medium text-gray-100 transition hover:bg-gray-600"
                  >
                    <span aria-hidden="true">⬇️</span>
                    Export JSON
                  </button>
                </div>
              </div>
            ) : (
              <p className="mt-4 text-sm text-gray-300">
                Findings are streaming in as agents complete...
              </p>
            )}

            <div className="mt-6">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-300">
                Findings ({results.findings.length})
              </h3>

              {results.findings.length === 0 ? (
                <p className="mt-3 text-sm text-green-300">
                  No issues found. The submitted code looks clean.
                </p>
              ) : (
                <div className="mt-3 space-y-3">
                  {results.findings.map((finding) => (
                    <article
                      key={finding.id}
                      className="rounded-lg border border-gray-700 bg-gray-950/80 p-4"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded px-2 py-1 text-xs font-semibold uppercase ${SEVERITY_STYLES[finding.severity]}`}
                        >
                          {finding.severity}
                        </span>
                        <span className="rounded border border-gray-600 px-2 py-1 text-xs uppercase text-gray-300">
                          {finding.category}
                        </span>
                        <span className="text-xs text-gray-400">
                          {finding.line === null ? "Line: N/A" : `Line: ${finding.line}`}
                        </span>
                      </div>
                      <h4 className="mt-3 text-base font-semibold text-white">
                        {finding.title}
                      </h4>
                      <p className="mt-2 text-sm text-gray-200">{finding.explanation}</p>
                      <p className="mt-2 text-sm text-indigo-200">
                        Suggestion: {finding.suggestion}
                      </p>
                    </article>
                  ))}
                </div>
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
