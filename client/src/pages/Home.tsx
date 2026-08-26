/**
 * TraceVeil design reminder: “Calibration Observatory” uses warm paper, Veil Teal,
 * editorial type, evidence margins, sharp instrument-like divisions, and restrained motion.
 */
import { Button } from "@/components/ui/button";
import {
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleCheckBig,
  Clipboard,
  FileCheck2,
  Fingerprint,
  Github,
  LockKeyhole,
  ScanSearch,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useState } from "react";

const artifactRows = [
  { name: "traceveil.sanitized.json", type: "sanitized trace", hash: "e063…8b4b" },
  { name: "traceveil.evidence.json", type: "decision capsule", hash: "d9a8…af31" },
  { name: "traceveil.sarif", type: "review findings", hash: "3d24…e175" },
];

const rawTrace = `gen_ai.input.messages
[{"role":"user","content":"Email alice@example.com.
Use token ghp_abcdefghijklmnopqrstuvwx."}]

http.request.header.authorization
Bearer deeplySensitiveToken12345`;

const sanitizedTrace = `gen_ai.input.messages
[{"role":"user","content":"Email [TRACEVEIL:EMAIL:7b77f1].
Use token [TRACEVEIL:GITHUB_TOKEN:dd1a31]."}]

http.request.header.authorization
[TRACEVEIL:GUARDED_KEY:da49b3]`;

function DecisionStamp({ className = "" }: { className?: string }) {
  return (
    <div className={`decision-stamp ${className}`} aria-label="Verified export decision">
      <CircleCheckBig size={18} strokeWidth={1.8} />
      <span>decision</span>
      <strong>verified</strong>
      <small>export / 03</small>
    </div>
  );
}

export default function Home() {
  const [compiled, setCompiled] = useState(false);
  const [copied, setCopied] = useState(false);

  const runSample = () => {
    setCompiled(true);
    window.setTimeout(() => setCompiled(false), 4200);
  };

  const copyCommand = async () => {
    await navigator.clipboard.writeText(
      "traceveil sanitize otlp-export.json --policy traceveil.toml --out traceveil.sanitized.json --evidence traceveil.evidence.json --sarif traceveil.sarif",
    );
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2200);
  };

  return (
    <div className="min-h-screen bg-[#f5f1e9] text-[#17333a] selection:bg-[#b8ded8]">
      <div className="grain" aria-hidden="true" />
      <header className="relative z-10 border-b border-[#17333a]/15 bg-[#f5f1e9]/92 backdrop-blur-md">
        <div className="page-shell flex h-[70px] items-center justify-between gap-6">
          <a href="#top" className="flex items-center gap-3" aria-label="TraceVeil home">
            <img
              src="/manus-storage/traceveil-mark_b919c5a0.png"
              alt=""
              className="h-10 w-10 object-contain"
            />
            <span className="wordmark"><span>trace</span><span>veil</span><i /></span>
          </a>
          <nav className="hidden items-center gap-7 text-[0.73rem] font-semibold uppercase tracking-[0.13em] text-[#35565b] md:flex">
            <a className="nav-link" href="#proof">
              Evidence model
            </a>
            <a className="nav-link" href="#workflow">
              Workflow
            </a>
            <a className="nav-link" href="#open-source">
              Open source
            </a>
          </nav>
          <a
            href="https://github.com/ateeqdesktop-dot/traceveil"
            className="inline-flex items-center gap-2 text-sm font-semibold text-[#0e6d73] transition-colors hover:text-[#17333a]"
          >
            <Github size={17} strokeWidth={1.8} />
            View repository
          </a>
        </div>
      </header>

      <main id="top" className="relative z-[1]">
        <section className="page-shell hero-grid pt-10 pb-14 md:pt-16 md:pb-24">
          <div className="hero-copy">
            <div className="eyebrow">
              <span className="pulse-dot" />
              Local policy compiler · OTLP GenAI telemetry
            </div>
            <h1>
              Export only the
              <em> evidence</em> you can defend.
            </h1>
            <p className="hero-lede">
              TraceVeil compiles privacy policy into a deterministic, signed decision record before rich
              GenAI telemetry leaves your environment.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button onClick={runSample} className="veil-button group">
                <ScanSearch size={17} />
                Compile local sample
                <ChevronRight className="transition-transform group-hover:translate-x-0.5" size={17} />
              </Button>
              <a className="quiet-link" href="#proof">
                Inspect the proof model <ArrowUpRight size={15} />
              </a>
            </div>
            <div className="hero-notes">
              <span>
                <LockKeyhole size={14} /> no hosted control plane
              </span>
              <span>
                <Fingerprint size={14} /> deterministic evidence
              </span>
              <span>
                <FileCheck2 size={14} /> SARIF + JUnit
              </span>
            </div>
          </div>

          <div className="hero-visual-wrap">
            <div className="visual-caption top-caption">policy boundary / in-process</div>
            <img
              src="/manus-storage/traceveil-hero_ee39245a.png"
              alt="Abstract layered teal veils filtering a telemetry stream"
              className="hero-visual"
            />
            <div className="verification-seal">
              <CircleCheckBig size={25} />
              <div>
                <strong>3 decisions</strong>
                <span>sanitized locally</span>
              </div>
            </div>
            <DecisionStamp className="hero-stamp" />
            <div className="visual-caption bottom-caption">raw trace → policy → safe artifact</div>
          </div>
        </section>

        <section id="workflow" className="border-y border-[#17333a]/15 bg-[#e9e3d8]/72">
          <div className="page-shell py-4">
            <div className="provenance-line" aria-label="TraceVeil processing order">
              <span className="line-label">decision path</span>
              <div className="provenance-step active">
                <i>01</i>
                <b>OTLP export</b>
              </div>
              <div className="connector" />
              <div className="provenance-step active">
                <i>02</i>
                <b>policy match</b>
              </div>
              <div className="connector" />
              <div className="provenance-step active">
                <i>03</i>
                <b>sanitized trace</b>
              </div>
              <div className="connector" />
              <div className="provenance-step">
                <i>04</i>
                <b>evidence capsule</b>
              </div>
            </div>
          </div>
        </section>

        <section className="page-shell py-16 md:py-24">
          <div className="section-heading">
            <div>
              <span className="eyebrow">A working local demonstration</span>
              <h2>One policy. A trace you can share.</h2>
            </div>
            <p>
              Run a deterministic sample to inspect the exact boundary between the content TraceVeil sees and
              the artifact it permits you to export.
            </p>
          </div>

          <div className="instrument-grid mt-10">
            <article className="trace-card raw-card">
              <div className="card-head">
                <span className="state-mark raw" />
                <div>
                  <p>input / transient</p>
                  <h3>Rich agent telemetry</h3>
                </div>
                <span className="mono-tag">OTLP JSON</span>
              </div>
              <pre>{rawTrace}</pre>
              <div className="card-foot">
                <span>Never serialised into evidence</span>
                <span className="danger-count">3 sensitive matches</span>
              </div>
            </article>

            <div className="policy-column">
              <div className={compiled ? "policy-prism compiled" : "policy-prism"}>
                <img src="/manus-storage/traceveil-mark_b919c5a0.png" alt="" />
                <span>policy</span>
                <b>{compiled ? "compiled" : "traceveil.toml"}</b>
              </div>
              <p>configured rules<br />act locally</p>
            </div>

            <article className={compiled ? "trace-card safe-card freshly-compiled" : "trace-card safe-card"}>
              <div className="card-head">
                <span className="state-mark safe" />
                <div>
                  <p>output / exportable</p>
                  <h3>Sanitized evidence trace</h3>
                </div>
                <span className="mono-tag teal">SHA-256 bound</span>
              </div>
              <pre>{sanitizedTrace}</pre>
              <div className="card-foot">
                <span>Same structural context</span>
                <span className="safe-count"><Check size={14} /> 3 decisions recorded</span>
              </div>
            </article>
          </div>
        </section>

        <section id="proof" className="proof-surface">
          <div className="plate-index">NEGATIVE PROOF PLATE / 03</div>
          <div className="page-shell proof-grid py-16 md:py-24">
            <div className="proof-copy">
              <span className="eyebrow light-eyebrow">The difference is verifiability</span>
              <h2>A filter changes data.<br />A proof explains the change.</h2>
              <p>
                Every TraceVeil run binds a reviewed policy, the logical input, the sanitized payload, and the
                exact emitted file. A reviewer gets the decision record, not your prompt history.
              </p>
              <a className="proof-link" href="https://github.com/ateeqdesktop-dot/traceveil/blob/main/docs/architecture.md">
                Read the architecture <ArrowUpRight size={16} />
              </a>
            </div>
            <div className="proof-artifact">
              <img
                src="/manus-storage/traceveil-evidence_5263305c.png"
                alt="Abstract privacy evidence document with a teal verification seal"
              />
              <div className="artifact-card">
                <div className="artifact-title">
                  <ShieldCheck size={18} />
                  <span>traceveil.evidence.json</span>
                </div>
                <dl>
                  <div><dt>policy</dt><dd>4622…434e</dd></div>
                  <div><dt>input</dt><dd>a77c…0c77</dd></div>
                  <div><dt>subject</dt><dd>e063…8b4b</dd></div>
                </dl>
                <div className="artifact-ok"><CircleCheckBig size={16} /> offline verification ready</div>
              </div>
              <DecisionStamp className="evidence-stamp" />
            </div>
          </div>
        </section>

        <section id="open-source" className="page-shell py-16 md:py-24">
          <div className="open-source-head">
            <div>
              <span className="eyebrow">Built for pull requests, not platform lock-in</span>
              <h2>A small, inspectable contract.</h2>
            </div>
            <p>
              Use the CLI directly, wire the composite action into CI, or consume the evidence statement in your
              own release and provenance workflow.
            </p>
          </div>
          <div className="open-source-grid mt-10">
            <div className="command-card">
              <div className="command-card-head">
                <span>terminal / local only</span>
                <button onClick={copyCommand} className="copy-button" aria-label="Copy command">
                  {copied ? <Check size={16} /> : <Clipboard size={16} />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <code>
                <span>$</span> traceveil sanitize otlp-export.json \\
                <br />&nbsp;&nbsp;--policy traceveil.toml \\
                <br />&nbsp;&nbsp;--out traceveil.sanitized.json \\
                <br />&nbsp;&nbsp;--evidence traceveil.evidence.json \\
                <br />&nbsp;&nbsp;--sarif traceveil.sarif
              </code>
            </div>
            <div className="artifact-list">
              {artifactRows.map((artifact) => (
                <div className="artifact-row" key={artifact.name}>
                  <div className="artifact-icon"><FileCheck2 size={18} /></div>
                  <div><strong>{artifact.name}</strong><span>{artifact.type}</span></div>
                  <code>{artifact.hash}</code>
                </div>
              ))}
              <a className="repo-row" href="https://github.com/ateeqdesktop-dot/traceveil">
                <Github size={18} />
                <span>Browse source, policies, tests, and CI</span>
                <ArrowUpRight size={16} />
              </a>
            </div>
          </div>
        </section>

        <section className="page-shell pb-16">
          <div className="closing-card">
            <img src="/manus-storage/traceveil-provenance_dc4b1297.png" alt="Abstract four-stage provenance flow" />
            <div>
              <span className="eyebrow">Open source · MIT</span>
              <h2>Make telemetry privacy a decision someone else can verify.</h2>
            </div>
            <DecisionStamp className="release-stamp" />
            <a className="closing-link" href="https://github.com/ateeqdesktop-dot/traceveil">
              Explore TraceVeil <ArrowUpRight size={18} />
            </a>
          </div>
        </section>
      </main>

      <footer className="border-t border-[#17333a]/15 py-7">
        <div className="page-shell flex flex-col justify-between gap-4 text-xs font-medium text-[#557077] sm:flex-row sm:items-center">
          <span>TraceVeil · local policy evidence for GenAI telemetry</span>
          <span className="inline-flex items-center gap-1.5"><Sparkles size={13} /> Privacy before export</span>
        </div>
      </footer>
    </div>
  );
}
