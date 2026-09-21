import React, { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { Card, Empty, Label } from '../components/ui'
import { useReport } from '../App'
import { reportHtmlUrl, reportJsonUrl, reportPrintUrl } from '../lib/api'
import { shortHash } from '../lib/format'

/**
 * Screen 08 — the deliverable an analyst hands over.
 *
 * A dashboard is what someone looks at; a report is what they give to a person
 * who was not in the room. Every export carries the capture hash, so findings
 * stay tied to a specific piece of evidence.
 */
export default function ExportPage() {
  const { id } = useParams()
  const { report } = useReport()
  const [copied, setCopied] = useState(false)

  if (!report?.report) {
    return (
      <Empty title="Nothing to export">
        <Link to="/" className="text-accent">
          Load a capture first
        </Link>
        .
      </Empty>
    )
  }

  const r = report.report

  return (
    <div className="max-w-[860px]">
      <Link
        to={`/report/${id}`}
        className="font-mono text-[11px] text-ink-3 hover:text-ink no-underline"
      >
        ← back to dashboard
      </Link>

      <h1 className="font-display text-[26px] font-semibold tracking-tight mt-3 mb-1.5">
        Export the forensic report
      </h1>
      <div className="font-mono text-[11.5px] text-ink-3 mb-6 break-all">
        {r.capture?.filename} · {r.counts?.sessions ?? 0} sessions · SHA-256{' '}
        {shortHash(r.capture?.sha256, 32)}
      </div>

      <div className="grid sm:grid-cols-2 gap-3">
        <Card className="p-5">
          <Label className="mb-2">JSON</Label>
          <p className="text-[13.5px] text-ink-2 leading-relaxed mb-4">
            The complete machine-readable document, ready for a SIEM, a ticketing system or a
            data lake. This is also the exact contract the backend and the analysis engine
            speak to each other.
          </p>
          <a
            href={reportJsonUrl(id)}
            download={`mailsentinel-${r.capture?.filename || 'report'}.json`}
            className="inline-block font-mono text-[11px] tracking-[0.08em] uppercase px-3 py-2 rounded border border-line bg-surface-2 text-ink no-underline hover:border-line-2"
          >
            Download JSON
          </a>
        </Card>

        <Card className="p-5">
          <Label className="mb-2">HTML &amp; PDF</Label>
          <p className="text-[13.5px] text-ink-2 leading-relaxed mb-4">
            A self-contained report that opens in any browser with no dependencies, and prints
            to PDF with proper page breaks. Both are rendered from the stored analysis, so
            they are the same document as the JSON.
          </p>

          <div className="flex gap-2 flex-wrap">
            <a
              href={reportHtmlUrl(id)}
              target="_blank"
              rel="noreferrer"
              className="inline-block font-mono text-[11px] tracking-[0.08em] uppercase px-3 py-2 rounded border border-line bg-surface-2 text-ink no-underline hover:border-line-2"
            >
              Open HTML
            </a>
            <a
              href={reportPrintUrl(id)}
              target="_blank"
              rel="noreferrer"
              className="inline-block font-mono text-[11px] tracking-[0.08em] uppercase px-3 py-2 rounded border border-line bg-surface-2 text-ink no-underline hover:border-line-2"
            >
              Save as PDF
            </a>
          </div>

          <p className="text-[12px] text-ink-3 mt-3 leading-relaxed">
            <strong className="font-medium text-ink-2">Save as PDF</strong> opens the report
            and hands it to your browser's print dialogue — choose “Save as PDF” there. The
            page breaks come from the report's own stylesheet, so the result is the same
            document on any machine, with nothing to install.
          </p>
        </Card>
      </div>

      <section className="mt-8">
        <Label className="mb-3">What the report contains</Label>
        <Card className="divide-y divide-line">
          {[
            ['Capture metadata and SHA-256 integrity hash', 'Ties every finding to one specific file.'],
            ['Overall posture grade with score composition', 'Including which rule capped the grade, and why.'],
            ['Per-session handshake and certificate findings', 'Each citing the NIST or RFC clause it enforces.'],
            ['Downgrade and anomaly detections', 'With the reconstructed transcript as evidence.'],
            ['Prioritised remediation list', 'Ordered by severity and by how much traffic each server carried.'],
            ['Model attributions', 'TreeSHAP contributions behind every estimate.'],
            ['Scope and limitations', 'Stated plainly — what a passive sensor cannot see.'],
          ].map(([title, note]) => (
            <div key={title} className="px-4 py-3">
              <div className="text-[14px] font-medium">{title}</div>
              <div className="text-[13px] text-ink-2 mt-0.5">{note}</div>
            </div>
          ))}
        </Card>
      </section>

      <div className="mt-6">
        <button
          type="button"
          className="font-mono text-[11px] tracking-[0.08em] uppercase px-3 py-2 rounded border border-line bg-surface text-ink-2 hover:text-ink"
          onClick={() => {
            navigator.clipboard
              ?.writeText(r.capture?.sha256 || '')
              .then(() => {
                setCopied(true)
                setTimeout(() => setCopied(false), 2000)
              })
              .catch(() => setCopied(false))
          }}
        >
          {copied ? 'Hash copied' : 'Copy evidence hash'}
        </button>
      </div>
    </div>
  )
}
