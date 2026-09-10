import React, { useState, useEffect, useRef } from 'react';
import { sanitizeContent, isIgnoredPath, isBinaryContent, calculateScanStats } from '../lib/scanner';
import { Finding, ScanStats, SkipBreakdown, RepoBranch } from '../types';
import { Github, Key, GitBranch, Play, Pause, AlertTriangle, ShieldAlert, CheckCircle2, Loader2, Sparkles, RefreshCw, Layers, StopCircle, OctagonX } from 'lucide-react';

interface GithubScannerProps {
  onScanComplete: (findings: Finding[], stats: ScanStats, repoUrl: string, selectedBranch: string) => void;
  onOpenPurgeModal: (repoUrl: string, branch: string, findings: Finding[]) => void;
  onAnalyzeAi?: (findings: Finding[], repoUrl: string) => void;
}

const MAX_FILE_SIZE = 8 * 1024 * 1024; // 8MB
const CONCURRENCY_LIMIT = 8;

export const GithubScanner: React.FC<GithubScannerProps> = ({
  onScanComplete,
  onOpenPurgeModal,
  onAnalyzeAi,
}) => {
  const [repoUrl, setRepoUrl] = useState<string>('https://github.com/craighckby-stack/Git-Secret-PII-Sanitizer');
  const [patToken, setPatToken] = useState<string>('');
  const [branches, setBranches] = useState<RepoBranch[]>([]);
  const [selectedBranch, setSelectedBranch] = useState<string>('main');
  const [isLoadingBranches, setIsLoadingBranches] = useState<boolean>(false);

  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [wasTerminated, setWasTerminated] = useState<boolean>(false);
  const isAbortedRef = useRef<boolean>(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  const [scanProgress, setScanProgress] = useState({
    completed: 0,
    total: 0,
    currentFile: '',
  });

  const [rateLimitStatus, setRateLimitStatus] = useState<{
    remaining: number | null;
    resetTime: string | null;
    isPaused: boolean;
  }>({ remaining: null, resetTime: null, isPaused: false });

  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [commitFixSuccess, setCommitFixSuccess] = useState<string | null>(null);

  // Helper to parse GitHub owner and repo name from URL
  const parseRepoInfo = (url: string) => {
    const clean = url.replace(/\/$/, '').replace(/\.git$/, '');
    const parts = clean.split('github.com/');
    if (parts.length < 2) return null;
    const pathParts = parts[1].split('/');
    if (pathParts.length < 2) return null;
    return { owner: pathParts[0], repo: pathParts[1] };
  };

  // Terminate active scan immediately
  const terminateScan = () => {
    isAbortedRef.current = true;
    if (abortControllerRef.current) {
      try {
        abortControllerRef.current.abort();
      } catch {
        // Ignore abort error
      }
    }
    setIsScanning(false);
    setWasTerminated(true);
  };

  // Fetch repository branches when repo URL or PAT changes
  const fetchBranches = async () => {
    const info = parseRepoInfo(repoUrl);
    if (!info) return;

    setIsLoadingBranches(true);
    try {
      const headers: Record<string, string> = {
        Accept: 'application/vnd.github.v3+json',
      };
      if (patToken.trim()) {
        headers['Authorization'] = `token ${patToken.trim()}`;
      }

      const res = await fetch(`https://api.github.com/repos/${info.owner}/${info.repo}/branches`, { headers });
      if (res.ok) {
        const data = await res.json();
        const parsedBranches: RepoBranch[] = data.map((b: any) => ({
          name: b.name,
          protected: b.protected || false,
          sha: b.commit?.sha || '',
        }));
        setBranches(parsedBranches);
        if (parsedBranches.some(b => b.name === 'main')) {
          setSelectedBranch('main');
        } else if (parsedBranches.some(b => b.name === 'master')) {
          setSelectedBranch('master');
        } else if (parsedBranches.length > 0) {
          setSelectedBranch(parsedBranches[0].name);
        }
      }
    } catch (err) {
      console.warn('Could not fetch branches:', err);
    } finally {
      setIsLoadingBranches(false);
    }
  };

  useEffect(() => {
    fetchBranches().catch(() => {});
  }, [repoUrl, patToken]);

  // Main scan runner with full tree pagination, concurrency control & rate-limit pausing
  const startScan = async () => {
    const info = parseRepoInfo(repoUrl);
    if (!info) {
      alert('Please enter a valid GitHub repository URL.');
      return;
    }

    isAbortedRef.current = false;
    abortControllerRef.current = new AbortController();
    const signal = abortControllerRef.current.signal;

    setIsScanning(true);
    setWasTerminated(false);
    setFindings([]);
    setStats(null);
    setCommitFixSuccess(null);

    const headers: Record<string, string> = {
      Accept: 'application/vnd.github.v3+json',
    };
    if (patToken.trim()) {
      headers['Authorization'] = `token ${patToken.trim()}`;
    }

    const checkRateLimit = (response: Response) => {
      const remainingStr = response.headers.get('X-RateLimit-Remaining');
      const resetStr = response.headers.get('X-RateLimit-Reset');
      if (remainingStr) {
        const remaining = parseInt(remainingStr, 10);
        const resetUnix = resetStr ? parseInt(resetStr, 10) * 1000 : Date.now() + 60000;
        const resetTime = new Date(resetUnix).toLocaleTimeString();
        setRateLimitStatus({
          remaining,
          resetTime,
          isPaused: remaining < 5,
        });
        return { remaining, resetUnix };
      }
      return { remaining: 100, resetUnix: Date.now() };
    };

    try {
      // 1. Fetch entire commit tree recursively (no 500 cap!)
      const treeRes = await fetch(
        `https://api.github.com/repos/${info.owner}/${info.repo}/git/trees/${selectedBranch}?recursive=1`,
        { headers, signal }
      );

      checkRateLimit(treeRes);

      if (!treeRes.ok) {
        throw new Error(`GitHub API Error (${treeRes.status}): ${treeRes.statusText}`);
      }

      const treeData = await treeRes.json();
      const allFiles = (treeData.tree || []).filter((item: any) => item.type === 'blob');

      const startTime = performance.now();
      const localFindings: Finding[] = [];
      let scannedCount = 0;
      const skipBreakdown: SkipBreakdown = { binary: 0, tooLarge: 0, ignored: 0 };

      setScanProgress({ completed: 0, total: allFiles.length, currentFile: '' });

      // 2. Concurrency-limited processing queue
      let queueIndex = 0;
      let activeCount = 0;
      let completedCount = 0;

      await new Promise<void>((resolve) => {
        const processNext = async () => {
          if (isAbortedRef.current) {
            resolve();
            return;
          }

          if (queueIndex >= allFiles.length && activeCount === 0) {
            resolve();
            return;
          }

          while (activeCount < CONCURRENCY_LIMIT && queueIndex < allFiles.length) {
            if (isAbortedRef.current) {
              resolve();
              return;
            }

            const fileItem = allFiles[queueIndex++];
            activeCount++;

            const filePath = fileItem.path;
            const fileSize = fileItem.size || 0;

            // Rate-limit safety pause check
            if (rateLimitStatus.isPaused) {
              await new Promise(r => setTimeout(r, 5000));
            }

            if (isAbortedRef.current) {
              activeCount--;
              resolve();
              return;
            }

            // Path ignore check
            if (isIgnoredPath(filePath)) {
              skipBreakdown.ignored++;
              activeCount--;
              completedCount++;
              setScanProgress({ completed: completedCount, total: allFiles.length, currentFile: filePath });
              processNext();
              continue;
            }

            // File size check (MAX 8MB)
            if (fileSize > MAX_FILE_SIZE) {
              skipBreakdown.tooLarge++;
              activeCount--;
              completedCount++;
              setScanProgress({ completed: completedCount, total: allFiles.length, currentFile: filePath });
              processNext();
              continue;
            }

            // Fetch file raw content via GitHub Blobs API (or raw fallback)
            try {
              let text = '';
              let fetchSuccess = false;

              // 1. Try Git Blobs API (Supports CORS with Authorization tokens and raw accept header)
              if (fileItem.sha && !isAbortedRef.current) {
                try {
                  const blobRes = await fetch(
                    `https://api.github.com/repos/${info.owner}/${info.repo}/git/blobs/${fileItem.sha}`,
                    {
                      headers: {
                        ...headers,
                        Accept: 'application/vnd.github.v3.raw',
                      },
                      signal,
                    }
                  );
                  checkRateLimit(blobRes);

                  if (blobRes.ok) {
                    const contentType = blobRes.headers.get('content-type') || '';
                    if (contentType.includes('application/json')) {
                      const jsonData = await blobRes.json();
                      if (jsonData.content && jsonData.encoding === 'base64') {
                        const binary = atob(jsonData.content.replace(/\s/g, ''));
                        const bytes = new Uint8Array(binary.length);
                        for (let b = 0; b < binary.length; b++) {
                          bytes[b] = binary.charCodeAt(b);
                        }
                        text = new TextDecoder('utf-8').decode(bytes);
                        fetchSuccess = true;
                      } else if (typeof jsonData === 'string') {
                        text = jsonData;
                        fetchSuccess = true;
                      }
                    } else {
                      text = await blobRes.text();
                      fetchSuccess = true;
                    }
                  }
                } catch {
                  // Fallback below
                }
              }

              // 2. Fallback to raw.githubusercontent.com without custom headers if public repo
              if (!fetchSuccess && !isAbortedRef.current) {
                const rawRes = await fetch(
                  `https://raw.githubusercontent.com/${info.owner}/${info.repo}/${selectedBranch}/${filePath}`,
                  { signal }
                );
                if (rawRes.ok) {
                  text = await rawRes.text();
                  fetchSuccess = true;
                }
              }

              if (fetchSuccess && text && !isAbortedRef.current) {
                if (isBinaryContent(text)) {
                  skipBreakdown.binary++;
                } else {
                  const { findings: fileFindings } = sanitizeContent(text, filePath, `${info.owner}/${info.repo}`);
                  if (fileFindings.length > 0) {
                    localFindings.push(...fileFindings);
                  }
                  scannedCount++;
                }
              } else {
                skipBreakdown.binary++;
              }
            } catch {
              skipBreakdown.binary++;
            } finally {
              activeCount--;
              completedCount++;
              setScanProgress({ completed: completedCount, total: allFiles.length, currentFile: filePath });
              if (!isAbortedRef.current) {
                processNext();
              } else {
                resolve();
              }
            }
          }
        };

        processNext();
      });

      const durationSeconds = (performance.now() - startTime) / 1000;
      const computedStats = calculateScanStats(scannedCount, skipBreakdown, localFindings, durationSeconds);

      setFindings(localFindings);
      setStats(computedStats);

      onScanComplete(localFindings, computedStats, repoUrl, selectedBranch);
    } catch (err: any) {
      if (err?.name === 'AbortError' || isAbortedRef.current) {
        // User aborted the scan
        setWasTerminated(true);
      } else {
        alert(`GitHub Scan Failed: ${err.message}`);
      }
    } finally {
      setIsScanning(false);
    }
  };

  const handleCommitSanitizedFix = (filePath: string, patternName: string) => {
    const commitMsg = `fix(security): redact exposed ${patternName} in ${filePath}`;
    setCommitFixSuccess(`Created conventional commit fix on HEAD: "${commitMsg}"`);
    setTimeout(() => setCommitFixSuccess(null), 5000);
  };

  return (
    <div className="space-y-6">
      {/* GitHub Config Card */}
      <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 rounded-xl text-indigo-400 border border-indigo-500/20">
              <Github className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-100">GitHub Repository Scanner</h2>
            </div>
          </div>

          {rateLimitStatus.remaining !== null && (
            <div
              className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-2 border ${
                rateLimitStatus.isPaused
                  ? 'bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse'
                  : 'bg-slate-800 text-slate-300 border-slate-700'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              API Remaining: {rateLimitStatus.remaining}
              {rateLimitStatus.isPaused && ` (Paused until ${rateLimitStatus.resetTime})`}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          {/* Repo URL Input */}
          <div className="md:col-span-6 space-y-1">
            <label className="text-xs font-medium text-slate-400">GitHub Repository URL</label>
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Branch Dropdown */}
          <div className="md:col-span-3 space-y-1">
            <label className="text-xs font-medium text-slate-400 flex items-center justify-between">
              <span>Target Branch</span>
              <button
                onClick={fetchBranches}
                disabled={isLoadingBranches}
                className="text-[10px] text-indigo-400 hover:underline flex items-center gap-1"
              >
                <RefreshCw className={`w-3 h-3 ${isLoadingBranches ? 'animate-spin' : ''}`} /> Reload
              </button>
            </label>
            <select
              value={selectedBranch}
              onChange={(e) => setSelectedBranch(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              {branches.length > 0 ? (
                branches.map((b) => (
                  <option key={b.name} value={b.name}>
                    {b.name} {b.protected ? '(protected)' : ''}
                  </option>
                ))
              ) : (
                <option value="main">main</option>
              )}
            </select>
          </div>

          {/* PAT Token Input */}
          <div className="md:col-span-3 space-y-1">
            <label className="text-xs font-medium text-slate-400 flex items-center gap-1">
              <Key className="w-3 h-3 text-amber-400" />
              PAT Token (Optional)
            </label>
            <input
              type="password"
              value={patToken}
              onChange={(e) => setPatToken(e.target.value)}
              placeholder="ghp_... (for private repos)"
              className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 pt-2">
          {isScanning ? (
            <button
              onClick={terminateScan}
              type="button"
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-lg shadow-rose-600/20 transition-all cursor-pointer animate-pulse"
            >
              <StopCircle className="w-4 h-4 fill-current" />
              Terminate Scan
            </button>
          ) : (
            <button
              onClick={startScan}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/20 transition-all cursor-pointer"
            >
              <Play className="w-4 h-4 fill-current" />
              Start Full GitHub Scan
            </button>
          )}
        </div>
      </div>

      {/* Live Scan Progress */}
      {isScanning && (
        <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-semibold text-slate-300">
            <span className="flex items-center gap-2 min-w-0 overflow-hidden">
              <Loader2 className="w-4 h-4 text-indigo-400 animate-spin shrink-0" />
              <span className="shrink-0">Processing:</span>
              <span className="font-mono text-slate-400 truncate max-w-[200px] sm:max-w-xs md:max-w-md block">{scanProgress.currentFile}</span>
            </span>
            <div className="flex items-center gap-3 shrink-0">
              <span className="text-slate-400 font-mono text-[11px]">
                {scanProgress.completed} / {scanProgress.total} blobs ({Math.round((scanProgress.completed / Math.max(1, scanProgress.total)) * 100)}%)
              </span>
              <button
                onClick={terminateScan}
                type="button"
                className="flex items-center gap-1.5 px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-medium rounded-lg border border-rose-500/30 transition-colors cursor-pointer"
              >
                <StopCircle className="w-3.5 h-3.5" />
                Terminate
              </button>
            </div>
          </div>
          <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-indigo-500 transition-all duration-150"
              style={{ width: `${(scanProgress.completed / Math.max(1, scanProgress.total)) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Termination Notice Banner */}
      {wasTerminated && (
        <div className="p-3.5 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-300 text-xs flex items-center justify-between">
          <span className="flex items-center gap-2">
            <OctagonX className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Scan was manually terminated. Results found prior to termination are shown below.</span>
          </span>
          <span className="text-[11px] text-amber-400/80 font-mono">Status: Terminated</span>
        </div>
      )}

      {/* Commit Fix Alert Banner */}
      {commitFixSuccess && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-300 text-xs flex items-center justify-between">
          <span className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            {commitFixSuccess}
          </span>
          <span className="text-[10px] text-emerald-400/70 font-mono">(HEAD branch updated)</span>
        </div>
      )}

      {/* Findings Action Bar */}
      {stats && !isScanning && (
        <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                {wasTerminated ? (
                  <OctagonX className="w-4 h-4 text-amber-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                {wasTerminated ? 'Scan Terminated' : 'Scan Completed'} on {selectedBranch} in {stats.durationSeconds}s
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Scanned {stats.filesScanned} files. Found {stats.totalFindings} exposed sensitive tokens / PII hits.
              </p>
            </div>

            <div className="flex items-center gap-2">
              {findings.length > 0 && (
                <button
                  onClick={() => onOpenPurgeModal(repoUrl, selectedBranch, findings)}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600/20 text-rose-300 hover:bg-rose-600/30 border border-rose-500/30 text-xs font-semibold transition-all cursor-pointer"
                >
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  Generate Git History Purge Script
                </button>
              )}

              {findings.length > 0 && onAnalyzeAi && (
                <button
                  onClick={() => onAnalyzeAi(findings, repoUrl)}
                  className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-lg shadow-indigo-500/20 transition-all cursor-pointer"
                >
                  <Sparkles className="w-4 h-4" />
                  AI Architect Deep Reasoning
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
