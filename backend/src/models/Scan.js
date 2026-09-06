import mongoose from 'mongoose';

const findingSchema = new mongoose.Schema(
  {
    // Stable identifier for comparison across scans: `${ruleId}:${line}:${fingerprint}`
    comparisonKey: { type: String, required: true },
    ruleId: { type: String, required: true },
    vulnerabilityType: { type: String, required: true },
    title: { type: String, required: true },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'informational'],
      required: true,
    },
    confidence: { type: Number, min: 0, max: 100, default: 0 },
    description: { type: String, default: '' },
    category: { type: String, default: '' },
    line: { type: Number, default: 0 },
    endLine: { type: Number, default: 0 },
    column: { type: Number, default: 0 },
    affectedCode: { type: String, default: '' },
    filePath: { type: String, default: '' },
    // AI layer enrichment
    ai: {
      explanation: { type: String, default: '' },
      impact: { type: String, default: '' },
      remediation: { type: String, default: '' },
      secureExample: { type: String, default: '' },
      severity: { type: String, default: '' },
      confidence: { type: Number, default: 0 },
      source: { type: String, default: '' }, // 'openrouter' | 'ollama' | 'rule'
    },
    reason: { type: String, default: '' }, // why this was flagged
    // Phase 4C: deterministic evidence engine output (optional, non-breaking)
    verdict: {
      type: String,
      enum: ['CONFIRMED', 'LIKELY', 'POTENTIAL', 'FALSE_POSITIVE'],
      default: undefined,
    },
    evidence: { type: mongoose.Schema.Types.Mixed, default: undefined },
    // Dependency / CVE intelligence fields (Phase 2) — present only on dependency findings
    kind: { type: String, default: 'code' }, // 'code' | 'dependency'
    packageName: { type: String, default: '' },
    installedVersion: { type: String, default: '' },
    cveId: { type: String, default: '' },
    affectedVersionRange: { type: String, default: '' },
    recommendedVersion: { type: String, default: '' },
    dependencyType: { type: String, default: 'transitive' }, // 'direct' | 'transitive'
    advisoryUrl: { type: String, default: '' },
    sourceFile: { type: String, default: '' },
  },
  { _id: true }
);

const scanSchema = new mongoose.Schema(
  {
    project: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      required: true,
      index: true,
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['pending', 'scanning', 'ai', 'completed', 'failed'],
      default: 'pending',
    },
    // Store the code that was submitted (kept only as long as the workflow needs it)
    sourceCode: { type: String, default: '' },
    // Multi-file (project folder) scans retain every submitted file so reports
    // can show a per-file breakdown without re-uploading anything.
    sourceFiles: {
      type: [
        {
          path: { type: String, required: true },
          content: { type: String, required: true },
        },
      ],
      default: undefined,
    },
    language: { type: String, default: 'javascript' },
    fileName: { type: String, default: 'submission.txt' },
    findings: [findingSchema],
    score: { type: Number, default: 0 },
    severityCounts: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      informational: { type: Number, default: 0 },
    },
    // Phase 2: split severity counts so dashboards can distinguish code vs dependency findings.
    codeSeverityCounts: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      informational: { type: Number, default: 0 },
    },
    dependencySeverityCounts: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      informational: { type: Number, default: 0 },
    },
    dependencySummary: {
      total: { type: Number, default: 0 },
      vulnerable: { type: Number, default: 0 },
      direct: { type: Number, default: 0 },
      transitive: { type: Number, default: 0 },
      bySeverity: {
        critical: { type: Number, default: 0 },
        high: { type: Number, default: 0 },
        medium: { type: Number, default: 0 },
        low: { type: Number, default: 0 },
        informational: { type: Number, default: 0 },
      },
    },
    comparisonVersion: { type: Number, default: 0 },
    comparison: {
      previousScanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', default: null },
      previousScore: { type: Number, default: null },
      resolved: { type: Number, default: 0 },
      remaining: { type: Number, default: 0 },
      new: { type: Number, default: 0 },
      delta: { type: Number, default: 0 },
    },
    errorMessage: { type: String, default: '' },
  },
  { timestamps: true }
);

scanSchema.index({ project: 1, createdAt: -1 });

const Scan = mongoose.model('Scan', scanSchema);
export default Scan;
