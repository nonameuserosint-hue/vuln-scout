/**
 * Kuzushi module wrapper for vuln-scout.
 * Exposes whitebox pentesting commands as ModuleTools.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const COMMANDS_DIR = join(__dirname, "whitebox-pentest", "commands");

function loadCommand(name) {
  try {
    return readFileSync(join(COMMANDS_DIR, `${name}.md`), "utf-8");
  } catch {
    return "";
  }
}

function createTool(cmdName, toolName, description, inputSchema) {
  const commandPrompt = loadCommand(cmdName);
  return {
    name: toolName,
    description,
    inputSchema,
    headless: true,
    async execute(input, ctx) {
      const params = input ?? {};
      const target = params.target ?? ctx.target ?? ".";
      const prompt = `${commandPrompt}\n\nTarget: ${target}`.trim();

      try {
        let text = "";
        for await (const msg of ctx.runtime.query(prompt, {
          systemPrompt: "You are a security researcher performing whitebox penetration testing.",
          tools: ["Read", "Glob", "Grep", "Bash"],
        })) {
          if (msg.type === "result") text = msg.text ?? text;
          else if (msg.type === "assistant" && msg.content) {
            for (const block of msg.content) {
              if (block.type === "text") text += block.text;
            }
          }
        }
        return { ok: true, output: text || "Analysis complete." };
      } catch (err) {
        return { ok: false, output: `VulnScout error: ${err.message ?? err}` };
      }
    },
  };
}

export default {
  id: "vuln-scout",
  displayName: "VulnScout Whitebox Pentesting",
  category: "offense",
  version: "1.4.0",
  description:
    "AI-powered whitebox pentesting with Semgrep, Joern CPG, CodeQL. " +
    "9-language support, STRIDE modeling, evidence-first findings.",
  tools: [
    createTool("full-audit", "vuln-scout:audit",
      "Run a full whitebox security audit — scoping, threat modeling, scanning, verification, and reporting.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
    createTool("scan", "vuln-scout:scan",
      "Run Semgrep + Joern CPG scanning on the target.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
    createTool("trace", "vuln-scout:trace",
      "Trace data flows from sources to sinks for a specific vulnerability.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID or description to trace." },
        },
        required: ["target"],
      }),
    createTool("verify", "vuln-scout:verify",
      "Verify a finding using CPG analysis and dynamic testing.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID to verify." },
        },
        required: ["target"],
      }),
    createTool("sinks", "vuln-scout:sinks",
      "Hunt for dangerous function calls and security-sensitive sinks.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
    createTool("auto-fix", "vuln-scout:fix",
      "Generate security patches for confirmed vulnerabilities.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID to fix." },
        },
        required: ["target"],
      }),
    createTool("report", "vuln-scout:report",
      "Generate a security assessment report (SARIF + Markdown).",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          format: { type: "string", enum: ["sarif", "md", "json"], description: "Report format." },
        },
        required: ["target"],
      }),
  ],
};
