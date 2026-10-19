"use client";

import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";
import {
  ShieldAlert,
  Activity,
  Terminal,
  Flame,
} from "lucide-react";

// =========================================
// TYPES & INTERFACES FOR SECURITY REPORT
// =========================================
export interface ScanMetadata {
  timestamp: string;
  targetPath: string;
  language: string;
  filesScanned: number;
  totalVulnerabilities: number;
  riskScore: number;
  riskCategory: "CRITICAL" | "MODERATE" | "LOW" | "CLEAN";
}

export interface RuleViolation {
  label: string;
  count: number;
  severity: "HIGH" | "MEDIUM" | "LOW";
  color: string;
}

export interface SecurityPostureMetric {
  label: string;
  value: number; // 0 - 100
  color: string;
}

export interface SeveritySlice {
  label: string;
  value: number;
  color: string;
  count: number;
}

export interface SecurityReportDashboardProps {
  metadata?: ScanMetadata;
  ruleViolations?: RuleViolation[];
  postureMetrics?: SecurityPostureMetric[];
  severityBreakdown?: SeveritySlice[];
}

// Default data mirroring the Perl Code Analyzer's security report
const DEFAULT_METADATA: ScanMetadata = {
  timestamp: "2026-10-19 07:21:00",
  targetPath: "/home/omindu/Documents/Python/scraping-platform",
  language: "PYTHON / MULTI-LANG",
  filesScanned: 48,
  totalVulnerabilities: 38,
  riskScore: 84,
  riskCategory: "CRITICAL",
};

const DEFAULT_RULES: RuleViolation[] = [
  { label: "REGISTRY_MOD", count: 12, severity: "HIGH", color: "bg-red-400" },
  { label: "NET_EXFIL", count: 9, severity: "HIGH", color: "bg-orange-400" },
  { label: "CMD_INJECTION", count: 7, severity: "HIGH", color: "bg-yellow-400" },
  { label: "RAW_SOCKET", count: 6, severity: "MEDIUM", color: "bg-blue-400" },
  { label: "INSECURE_EVAL", count: 4, severity: "LOW", color: "bg-purple-400" },
];

const DEFAULT_POSTURE: SecurityPostureMetric[] = [
  { label: "INJECTION", value: 45, color: "#f87171" },
  { label: "EXFILTRATION", value: 30, color: "#fb923c" },
  { label: "PRIVILEGE", value: 65, color: "#fbbf24" },
  { label: "MALWARE", value: 40, color: "#a78bfa" },
  { label: "INTEGRITY", value: 85, color: "#4ade80" },
];

const DEFAULT_SEVERITY: SeveritySlice[] = [
  { label: "Critical / High", value: 55, color: "#f87171", count: 21 },
  { label: "Medium", value: 30, color: "#fbbf24", count: 11 },
  { label: "Low", value: 15, color: "#4ade80", count: 6 },
];

// =========================================
// 1. BRUTALIST VULNERABILITY BAR CHART
// =========================================
function BrutalistVulnBarChart({ rules = DEFAULT_RULES }: { rules?: RuleViolation[] }) {
  const [hovered, setHovered] = useState<number | null>(null);
  const maxCount = Math.max(...rules.map((r) => r.count), 1);

  return (
    <div className="w-full h-full bg-white dark:bg-zinc-900 border-[3px] border-black dark:border-white shadow-[8px_8px_0px_0px_rgba(0,0,0,1)] dark:shadow-[8px_8px_0px_0px_rgba(255,255,255,1)] relative flex flex-col p-6 transition-colors duration-200">
      <div className="flex items-center justify-between border-b-[3px] border-black dark:border-white pb-3 mb-6">
        <div className="flex items-center gap-2">
          <Flame className="w-6 h-6 text-red-500" />
          <h3 className="font-black uppercase text-xl text-black dark:text-white">
            Top Vulnerability Rules
          </h3>
        </div>
        <span className="text-xs font-mono font-bold uppercase bg-black dark:bg-white text-white dark:text-black px-2 py-0.5">
          Scan Findings
        </span>
      </div>

      <div className="flex justify-between items-end flex-1 gap-2 sm:gap-4 min-h-[160px]">
        {rules.map((item, i) => {
          const heightPercent = Math.round((item.count / maxCount) * 100);
          return (
            <div key={i} className="relative flex-1 h-full flex items-end group">
              <motion.div
                initial={{ height: 0 }}
                animate={{ height: `${heightPercent}%` }}
                transition={{
                  type: "spring",
                  stiffness: 200,
                  damping: 20,
                  delay: i * 0.1,
                }}
                onHoverStart={() => setHovered(i)}
                onHoverEnd={() => setHovered(null)}
                className={cn(
                  "w-full border-[3px] border-black dark:border-white relative z-10 cursor-pointer origin-bottom flex flex-col items-center justify-between p-1 overflow-hidden",
                  item.color
                )}
                whileHover={{ scaleY: 1.08, scaleX: 1.05 }}
                whileTap={{ scaleY: 0.95 }}
              >
                <div className="absolute inset-0 opacity-20 pointer-events-none bg-[radial-gradient(#000_1px,transparent_1px)] dark:bg-[radial-gradient(#fff_1px,transparent_1px)] [background-size:4px_4px]" />
                <span className="relative z-20 font-black text-xs font-mono text-black">
                  {item.count}
                </span>
                <span className="relative z-20 font-bold text-[10px] font-mono text-black truncate w-full text-center">
                  {item.label}
                </span>
              </motion.div>
              <AnimatePresence>
                {hovered === i && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 8 }}
                    className="absolute bottom-full -mb-2 left-1/2 -translate-x-1/2 bg-black dark:bg-white text-white dark:text-black px-3 py-1 text-xs font-black whitespace-nowrap border-[3px] border-black dark:border-white z-30 pointer-events-none shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]"
                  >
                    {item.label}: {item.count} hits ({item.severity})
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ==========================================
// 2. BRUTALIST SECURITY POSTURE RADAR CHART
// ==========================================
function BrutalistPostureRadar({
  metrics = DEFAULT_POSTURE,
}: {
  metrics?: SecurityPostureMetric[];
}) {
  const [hoveredMetric, setHoveredMetric] = useState<string | null>(null);

  const NUM_AXES = metrics.length;
  const RADAR_SIZE = 220;
  const CENTER = RADAR_SIZE / 2;
  const RADIUS = 85;

  const angleToRad = (angle: number) => (Math.PI / 180) * angle;
  const getCoords = (value: number, index: number) => {
    const angle = angleToRad((360 / NUM_AXES) * index - 90);
    const r = (value / 100) * RADIUS;
    return {
      x: CENTER + r * Math.cos(angle),
      y: CENTER + r * Math.sin(angle),
    };
  };

  const pathData =
    metrics.map((d, i) => {
      const coords = getCoords(d.value, i);
      return `${i === 0 ? "M" : "L"} ${coords.x} ${coords.y}`;
    }).join(" ") + " Z";

  const gridLevels = [100, 75, 50, 25];

  return (
    <div className="w-full h-full bg-zinc-50 dark:bg-zinc-900 border-[3px] border-black dark:border-white shadow-[8px_8px_0px_0px_rgba(0,0,0,1)] dark:shadow-[8px_8px_0px_0px_rgba(255,255,255,1)] p-6 flex flex-col sm:flex-row gap-6 relative overflow-hidden transition-colors duration-200">
      {/* LEFT: CHART AREA */}
      <div className="flex-1 flex items-center justify-center relative min-h-[250px]">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-5 dark:opacity-10">
          <span className="text-8xl font-black uppercase text-black dark:text-white">
            AUDIT
          </span>
        </div>

        <svg
          viewBox={`0 0 ${RADAR_SIZE} ${RADAR_SIZE}`}
          className="w-full h-full max-w-[260px] overflow-visible"
        >
          {gridLevels.map((level, lvlIdx) => (
            <path
              key={lvlIdx}
              d={
                metrics.map((_, i) => {
                  const c = getCoords(level, i);
                  return `${i === 0 ? "M" : "L"} ${c.x} ${c.y}`;
                }).join(" ") + " Z"
              }
              fill="none"
              className="stroke-black/15 dark:stroke-white/15"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
          ))}

          {metrics.map((_, i) => {
            const outer = getCoords(100, i);
            return (
              <line
                key={i}
                x1={CENTER}
                y1={CENTER}
                x2={outer.x}
                y2={outer.y}
                className="stroke-black/15 dark:stroke-white/15"
                strokeWidth="2"
              />
            );
          })}

          <motion.path
            d={pathData}
            fill="rgba(239, 68, 68, 0.45)"
            className="stroke-black dark:stroke-white"
            strokeWidth="3.5"
            strokeLinejoin="round"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{
              type: "spring",
              stiffness: 200,
              damping: 20,
              delay: 0.2,
            }}
            style={{ originX: "50%", originY: "50%" }}
          />

          {metrics.map((d, i) => {
            const coords = getCoords(d.value, i);
            const isHovered = hoveredMetric === d.label;

            return (
              <g
                key={i}
                onMouseEnter={() => setHoveredMetric(d.label)}
                onMouseLeave={() => setHoveredMetric(null)}
                className="cursor-pointer"
              >
                <circle cx={coords.x} cy={coords.y} r="20" fill="transparent" />
                <motion.circle
                  cx={coords.x}
                  cy={coords.y}
                  r="6"
                  fill={isHovered ? d.color : "currentColor"}
                  className="fill-white dark:fill-zinc-900 stroke-black dark:stroke-white"
                  strokeWidth="3"
                  animate={{
                    scale: isHovered ? 2 : 1,
                    strokeWidth: isHovered ? 4 : 3,
                  }}
                  transition={{ type: "spring", stiffness: 400, damping: 15 }}
                />
              </g>
            );
          })}
        </svg>
      </div>

      {/* RIGHT: DEFENSE SCORES */}
      <div className="w-full sm:w-48 flex flex-col justify-center gap-2 z-10">
        <div className="flex items-center gap-2 border-b-[3px] border-black dark:border-white pb-2 mb-2">
          <Activity className="w-5 h-5 text-black dark:text-white" />
          <h3 className="font-black uppercase text-lg text-black dark:text-white">
            Defense Health
          </h3>
        </div>
        {metrics.map((item, i) => (
          <motion.div
            key={i}
            onMouseEnter={() => setHoveredMetric(item.label)}
            onMouseLeave={() => setHoveredMetric(null)}
            className="flex items-center justify-between p-2 border-2 border-transparent hover:border-black dark:hover:border-white hover:bg-white dark:hover:bg-zinc-800 cursor-pointer transition-colors"
            animate={{
              x: hoveredMetric === item.label ? 8 : 0,
            }}
          >
            <div className="flex items-center gap-2">
              <div
                className="w-3 h-3 border-2 border-black dark:border-white"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-xs font-bold font-mono text-black dark:text-zinc-200">
                {item.label}
              </span>
            </div>
            <span className="font-black text-sm text-black dark:text-white">
              {item.value}%
            </span>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

// =========================================
// 3. BRUTALIST SEVERITY DONUT CHART
// =========================================
function BrutalistSeverityDonut({
  slices = DEFAULT_SEVERITY,
  totalScore = 84,
  category = "CRITICAL",
}: {
  slices?: SeveritySlice[];
  totalScore?: number;
  category?: string;
}) {
  const [hoveredSlice, setHoveredSlice] = useState<string | null>(null);

  const springConfig = { type: "spring" as const, stiffness: 300, damping: 20 };
  const getPieCoords = (percent: number) => {
    const x = Math.cos(2 * Math.PI * percent);
    const y = Math.sin(2 * Math.PI * percent);
    return [x, y];
  };

  let cumulativePercent = 0;

  return (
    <div className="w-full h-full bg-white dark:bg-zinc-900 border-[3px] border-black dark:border-white shadow-[8px_8px_0px_0px_rgba(0,0,0,1)] dark:shadow-[8px_8px_0px_0px_rgba(255,255,255,1)] p-6 flex flex-col items-center justify-between overflow-hidden relative transition-colors duration-200">
      <div className="absolute inset-0 opacity-[0.07] pointer-events-none z-0 bg-[radial-gradient(#000_1.5px,transparent_1.5px)] dark:bg-[radial-gradient(#fff_1.5px,transparent_1.5px)] [background-size:12px_12px]" />

      <div className="flex items-center justify-between w-full border-b-[3px] border-black dark:border-white pb-3 mb-6 z-10">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-7 h-7 text-red-500" />
          <h3 className="font-black uppercase tracking-tight text-2xl text-black dark:text-white">
            Risk & Severity
          </h3>
        </div>
        <span className="font-black text-xs font-mono uppercase px-2 py-1 bg-red-500 text-white border-2 border-black dark:border-white shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]">
          {category}
        </span>
      </div>

      <div className="z-10 flex flex-col items-center w-full h-full justify-center">
        <div className="relative w-64 h-64 md:w-72 md:h-72 lg:w-80 lg:h-80 xl:w-96 xl:h-96">
          <motion.svg
            viewBox="-1.2 -1.2 2.4 2.4"
            className="-rotate-90 overflow-visible w-full h-full"
            initial={{ rotate: -180, scale: 0 }}
            animate={{ rotate: -90, scale: 1 }}
            transition={{
              type: "spring",
              stiffness: 100,
              damping: 20,
              delay: 0.2,
            }}
          >
            {slices.map((slice) => {
              const startPercent = cumulativePercent;
              const endPercent = cumulativePercent + slice.value / 100;
              cumulativePercent = endPercent;
              const [startX, startY] = getPieCoords(startPercent);
              const [endX, endY] = getPieCoords(endPercent);
              const largeArcFlag = slice.value / 100 > 0.5 ? 1 : 0;
              const pathData = [
                `M ${startX} ${startY}`,
                `A 1 1 0 ${largeArcFlag} 1 ${endX} ${endY}`,
                `L 0 0`,
              ].join(" ");
              const isHovered = hoveredSlice === slice.label;
              const isDimmed = hoveredSlice !== null && !isHovered;

              return (
                <motion.path
                  key={slice.label}
                  d={pathData}
                  fill={slice.color}
                  className="stroke-black dark:stroke-white"
                  strokeWidth="0.04"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  animate={{
                    translateX: isHovered ? (startX + endX) * 0.1 : 0,
                    translateY: isHovered ? (startY + endY) * 0.1 : 0,
                    scale: isHovered ? 1.05 : 1,
                    opacity: isDimmed ? 0.3 : 1,
                    filter: isDimmed ? "grayscale(80%)" : "grayscale(0%)",
                  }}
                  transition={springConfig}
                  onMouseEnter={() => setHoveredSlice(slice.label)}
                  onMouseLeave={() => setHoveredSlice(null)}
                />
              );
            })}
            <motion.circle
              cx="0"
              cy="0"
              r="0.55"
              className="fill-white dark:fill-zinc-900 stroke-black dark:stroke-white"
              strokeWidth="0.04"
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.4, ...springConfig }}
            />
          </motion.svg>
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
            <AnimatePresence mode="popLayout">
              {hoveredSlice ? (
                <motion.div
                  key="hover-content"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ type: "spring", stiffness: 300, damping: 20 }}
                  className="flex flex-col items-center text-center"
                >
                  <span className="text-2xl font-black leading-none text-black dark:text-white">
                    {slices.find((d) => d.label === hoveredSlice)?.count}
                  </span>
                  <span className="text-[10px] font-black uppercase tracking-widest bg-black dark:bg-white text-white dark:text-black px-1.5 py-0.5 mt-1">
                    {hoveredSlice}
                  </span>
                </motion.div>
              ) : (
                <motion.div
                  key="default-content"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ type: "spring", stiffness: 300, damping: 20 }}
                  className="flex flex-col items-center text-center"
                >
                  <span className="text-4xl font-black leading-none text-red-500">
                    {totalScore}
                  </span>
                  <span className="text-[10px] font-bold uppercase tracking-widest text-zinc-500 dark:text-zinc-400 mt-1">
                    RISK SCORE
                  </span>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        <div className="w-full mt-6 grid grid-cols-1 sm:grid-cols-3 gap-2">
          {slices.map((item) => (
            <motion.div
              key={item.label}
              onMouseEnter={() => setHoveredSlice(item.label)}
              onMouseLeave={() => setHoveredSlice(null)}
              animate={{
                opacity: hoveredSlice && hoveredSlice !== item.label ? 0.3 : 1,
                scale: hoveredSlice === item.label ? 1.05 : 1,
              }}
              className="flex items-center justify-between p-2.5 border-2 border-black dark:border-white bg-zinc-50 dark:bg-zinc-800 cursor-pointer transition-colors shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] dark:shadow-[2px_2px_0px_0px_rgba(255,255,255,1)]"
            >
              <div className="flex items-center gap-2">
                <div
                  className="w-3 h-3 border-2 border-black dark:border-white"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-xs font-bold uppercase text-black dark:text-white">
                  {item.label}
                </span>
              </div>
              <span className="font-black text-sm text-black dark:text-white">
                {item.count}
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}

// =========================================
// 4. MAIN SECURITY BENTO DASHBOARD
// =========================================
export default function SecurityReportDashboard({
  metadata = DEFAULT_METADATA,
  ruleViolations = DEFAULT_RULES,
  postureMetrics = DEFAULT_POSTURE,
  severityBreakdown = DEFAULT_SEVERITY,
}: SecurityReportDashboardProps) {
  return (
    <div className="min-h-screen w-full bg-zinc-100 dark:bg-black p-4 md:p-10 font-sans selection:bg-black selection:text-white dark:selection:bg-white dark:selection:text-black flex flex-col transition-colors duration-200">
      {/* Texture Background */}
      <div className="fixed inset-0 pointer-events-none opacity-5 bg-[radial-gradient(#000_1px,transparent_1px)] dark:bg-[radial-gradient(#fff_1px,transparent_1px)] [background-size:24px_24px]" />

      <div className="max-w-7xl w-full mx-auto relative z-10 flex flex-col flex-1">
        {/* Top Header Card */}
        <header className="mb-8 p-6 md:p-8 bg-white dark:bg-zinc-900 border-[3px] border-black dark:border-white shadow-[8px_8px_0px_0px_rgba(0,0,0,1)] dark:shadow-[8px_8px_0px_0px_rgba(255,255,255,1)] flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="flex items-start gap-4">
            {/* Stock Image Thumbnail / Icon Avatar */}
            <div className="relative w-16 h-16 border-[3px] border-black dark:border-white overflow-hidden shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] flex-shrink-0 bg-red-400">
              <img
                src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=200&q=80"
                alt="Cyber Audit"
                className="w-full h-full object-cover"
              />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-red-500 text-white font-black text-xs uppercase px-2 py-0.5 border-2 border-black dark:border-white">
                  Static Security Audit
                </span>
                <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
                  {metadata.timestamp}
                </span>
              </div>
              <h1 className="text-3xl md:text-5xl font-black uppercase tracking-tight text-black dark:text-white">
                Perl Code Security Analyzer
              </h1>
              <p className="font-mono text-xs md:text-sm text-zinc-600 dark:text-zinc-300 mt-1 flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                Target: <span className="font-bold underline">{metadata.targetPath}</span>
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <div className="p-3 border-2 border-black dark:border-white bg-zinc-50 dark:bg-zinc-800 text-center">
              <span className="block text-[10px] font-mono uppercase font-bold text-zinc-500 dark:text-zinc-400">
                Scanned Files
              </span>
              <span className="font-black text-xl text-black dark:text-white">
                {metadata.filesScanned}
              </span>
            </div>
            <div className="p-3 border-2 border-black dark:border-white bg-red-100 dark:bg-red-950/40 text-center">
              <span className="block text-[10px] font-mono uppercase font-bold text-red-600 dark:text-red-400">
                Vulns Found
              </span>
              <span className="font-black text-xl text-red-600 dark:text-red-400">
                {metadata.totalVulnerabilities}
              </span>
            </div>
          </div>
        </header>

        {/* MAIN BENTO GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 auto-rows-[minmax(0,1fr)]">
          {/* COLUMN 1: TOP RULES + DEFENSE POSTURE RADAR */}
          <div className="flex flex-col gap-6">
            <div className="w-full min-h-[380px]">
              <BrutalistVulnBarChart rules={ruleViolations} />
            </div>
            <div className="w-full min-h-[380px]">
              <BrutalistPostureRadar metrics={postureMetrics} />
            </div>
          </div>

          {/* COLUMN 2: FULL HEIGHT SEVERITY & RISK SCORE DONUT */}
          <div className="h-full min-h-[500px] lg:h-auto flex">
            <div className="w-full h-full">
              <BrutalistSeverityDonut
                slices={severityBreakdown}
                totalScore={metadata.riskScore}
                category={metadata.riskCategory}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
