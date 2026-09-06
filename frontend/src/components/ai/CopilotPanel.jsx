import { useEffect } from 'react';
import { Bot, RefreshCw } from 'lucide-react';
import { useCopilot } from '../../hooks/useCopilot.js';
import { Button } from '../ui/Button.jsx';
import { CodeWindow } from '../security/CodeWindow.jsx';
import { StatusBadge } from '../ui/StatusBadge.jsx';
import { Skeleton } from '../ui/Skeleton.jsx';

function Section({ title, children }) {
  return (
    <section className="border-t border-edge pt-3 first:border-t-0 first:pt-0">
      <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-widest text-slate-500">{title}</h4>
      <div className="whitespace-pre-line text-[13.5px] leading-relaxed text-slate-200">{children}</div>
    </section>
  );
}

/**
 * Structured explanation for ONE deterministic finding via POST /api/ai/explain.
 * The panel is purely presentational: it can never create, suppress, or mutate
 * a finding. Copilot "confidence" is self-assessed explanation quality, NOT a
 * vulnerability verdict.
 */
export function CopilotPanel({ scanId, finding, code, auto = true, className = '' }) {
  const { status, copilot, error, explain } = useCopilot({ scanId, finding, code });

  useEffect(() => {
    if (auto && status === 'idle') explain();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section aria-label="AI Security Copilot" className={`rounded-lg border border-accent-500/25 bg-gradient-to-b from-accent-500/[0.05] to-transparent ${className}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-accent-500/20 text-accent-300" aria-hidden="true">
            <Bot size={14} />
          </span>
          <div className="leading-tight">
            <p className="text-[13px] font-semibold text-slate-100">AI Security Copilot</p>
            <p className="text-[10px] text-slate-500">Detected by VulnLens · explained by AI Copilot</p>
          </div>
        </div>
        {status === 'done' && copilot ? (
          <StatusBadge tone="accent" dot={false} label={`Explanation confidence: ${copilot.confidence || 'medium'}`} />
        ) : null}
      </div>

      {/* Body */}
      <div className="p-4">
        {status === 'loading' ? (
          <div className="flex flex-col gap-3" role="status">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <span className="animate-pulse rounded-full bg-accent-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-accent-300">Analyzing</span>
              Building a security explanation for this finding…
            </div>
            <Skeleton lines={4} />
          </div>
        ) : null}

        {status === 'idle' ? (
          <Button variant="secondary" size="sm" onClick={explain}>
            <Bot size={14} /> Explain with AI Copilot
          </Button>
        ) : null}

        {status === 'unavailable' ? (
          <div role="alert" className="flex flex-col items-start gap-3">
            <div>
              <p className="text-sm font-medium text-slate-200">AI explanation unavailable</p>
              <p className="mt-1 max-w-lg text-[13px] leading-relaxed text-slate-500">
                {error || 'The AI provider could not be reached.'} The deterministic vulnerability finding above
                remains valid — only the explanation could not be generated.
              </p>
            </div>
            <Button variant="secondary" size="sm" onClick={explain}>
              <RefreshCw size={13} /> Retry explanation
            </Button>
          </div>
        ) : null}

        {status === 'done' && copilot ? (
          <div className="flex flex-col gap-3">
            {copilot.explanation ? <Section title="Why this matters">{copilot.explanation}</Section> : null}
            {copilot.impact ? <Section title="Security impact">{copilot.impact}</Section> : null}
            {copilot.attackScenario ? <Section title="Attack scenario">{copilot.attackScenario}</Section> : null}
            {copilot.remediation ? <Section title="Recommended remediation">{copilot.remediation}</Section> : null}
            {copilot.secureExample ? (
              <Section title="Secure example">
                <CodeWindow code={copilot.secureExample} highlights={{}} variant="success" maxHeight="max-h-72" />
              </Section>
            ) : null}
            <p className="border-t border-edge pt-2 text-[10.5px] leading-relaxed text-slate-600">
              Copilot confidence reflects the quality of this explanation. Severity, confidence, and the
              vulnerability verdict remain deterministic VulnLens results and are unaffected by AI.
            </p>
          </div>
        ) : null}
      </div>
    </section>
  );
}
