export type Metric = "logical" | "allocated";
export type SortField =
  | "size"
  | "name"
  | "files"
  | "directories"
  | "modified"
  | "kind";

export interface Progress {
  files: number;
  directories: number;
  symlinks: number;
  logicalBytes: number;
  allocatedBytes: number;
  errors: number;
  elapsedMs: number;
  currentPath: string;
  canceled: boolean;
  finished: boolean;
}

export interface Summary {
  root: string;
  files: number;
  directories: number;
  symlinks: number;
  otherEntries: number;
  logicalBytes: number;
  allocatedBytes: number;
  errors: number;
  hardLinkDuplicates: number;
  elapsedMs: number;
  canceled: boolean;
}

export interface ScanStatus {
  scanId: number;
  phase: "idle" | "scanning" | "complete" | "error";
  progress: Progress | null;
  summary: Summary | null;
  rootId: number | null;
  error: string | null;
}

export interface NodeView {
  id: number;
  parentId: number | null;
  name: string;
  path: string;
  kind: "file" | "directory" | "symlink" | "other";
  logicalSize: number;
  allocatedSize: number;
  fileCount: number;
  directoryCount: number;
  modifiedUnixMs: number | null;
  hidden: boolean;
  isSymlink: boolean;
  mountPoint: boolean;
  hardLinkDuplicate: boolean;
}

export interface ChildPage {
  parent: NodeView;
  items: NodeView[];
  total: number;
  offset: number;
  limit: number;
}

export interface ScanError {
  path: string;
  message: string;
}

export interface ScanTarget {
  label: string;
  path: string;
  detail: string;
}

export interface ServerInfo {
  version: string;
  defaultPath: string;
  cwd: string;
  activeScanId: number | null;
  scanTargets: ScanTarget[];
  platform: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    ...init,
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // Keep the status-based fallback.
    }
    throw new Error(message);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function getInfo(): Promise<ServerInfo> {
  return request<ServerInfo>("/api/info");
}

export function pickFolder(): Promise<{ path: string | null }> {
  return request<{ path: string | null }>("/api/pick-folder", {
    method: "POST",
    body: "{}",
  });
}

export function startScan(options: {
  path: string;
  threads: number;
  followSymlinks: boolean;
  stayOnFilesystem: boolean;
  deduplicateHardLinks: boolean;
}): Promise<{ scanId: number }> {
  return request<{ scanId: number }>("/api/scans", {
    method: "POST",
    body: JSON.stringify(options),
  });
}

export function getScanStatus(scanId: number): Promise<ScanStatus> {
  return request<ScanStatus>(`/api/scans/${scanId}`);
}

export function cancelScan(scanId: number): Promise<void> {
  return request<void>(`/api/scans/${scanId}/cancel`, {
    method: "POST",
    body: "{}",
  });
}

export function getChildren(
  scanId: number,
  options: {
    parentId: number;
    metric: Metric;
    sort: SortField;
    descending: boolean;
    query: string;
    offset: number;
    limit: number;
  },
): Promise<ChildPage> {
  const query = new URLSearchParams({
    parentId: String(options.parentId),
    metric: options.metric,
    sort: options.sort,
    descending: String(options.descending),
    query: options.query,
    offset: String(options.offset),
    limit: String(options.limit),
  });
  return request<ChildPage>(`/api/scans/${scanId}/children?${query}`);
}

export function getLargest(
  scanId: number,
  kind: "file" | "directory",
  metric: Metric,
  limit: number,
): Promise<NodeView[]> {
  const query = new URLSearchParams({
    kind,
    metric,
    limit: String(limit),
  });
  return request<NodeView[]>(`/api/scans/${scanId}/largest?${query}`);
}

export function getErrors(scanId: number): Promise<ScanError[]> {
  return request<ScanError[]>(`/api/scans/${scanId}/errors`);
}

export function openNode(scanId: number, nodeId: number): Promise<void> {
  return request<void>(`/api/scans/${scanId}/open`, {
    method: "POST",
    body: JSON.stringify({ nodeId }),
  });
}

export function revealNode(scanId: number, nodeId: number): Promise<void> {
  return request<void>(`/api/scans/${scanId}/reveal`, {
    method: "POST",
    body: JSON.stringify({ nodeId }),
  });
}
