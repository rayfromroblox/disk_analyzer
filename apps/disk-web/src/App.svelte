<script lang="ts">
  import { onMount } from "svelte";
  import {
    cancelScan as cancelScanRequest,
    getChildren,
    getErrors,
    getInfo,
    getLargest,
    getScanStatus,
    openNode as openNodeRequest,
    pickFolder,
    revealNode as revealNodeRequest,
    startScan,
  } from "./api";
  import type {
    ChildPage,
    Metric,
    NodeView,
    ScanError,
    ScanStatus,
    ScanTarget,
    SortField,
  } from "./api";

  type Phase = "idle" | "starting" | "scanning" | "complete" | "error";
  type Tab = "browse" | "largest" | "errors";

  let version = "";
  let path = "";
  let scanTargets: ScanTarget[] = [];
  let threads = 0;
  let followSymlinks = false;
  let stayOnFilesystem = true;
  let deduplicateHardLinks = true;
  let phase: Phase = "idle";
  let scanId: number | null = null;
  let status: ScanStatus | null = null;
  let page: ChildPage | null = null;
  let treemapItems: NodeView[] = [];
  let largestFiles: NodeView[] = [];
  let largestDirectories: NodeView[] = [];
  let scanErrors: ScanError[] = [];
  let selected: NodeView | null = null;
  let history: NodeView[] = [];
  let activeTab: Tab = "browse";
  let metric: Metric = "allocated";
  let sort: SortField = "size";
  let descending = true;
  let query = "";
  let offset = 0;
  const pageSize = 200;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  let loadGeneration = 0;
  let message = "";
  let busy = false;

  $: progress = status?.progress ?? null;
  $: summary = status?.summary ?? null;
  $: current = page?.parent ?? null;
  $: totalPages = page ? Math.max(1, Math.ceil(page.total / pageSize)) : 1;
  $: currentPage = Math.floor(offset / pageSize) + 1;
  $: canGoBack = history.length > 1;
  $: selectedTarget = scanTargets.find((target) => target.path === path);
  $: analyzeLabel = selectedTarget ? `Analyze ${selectedTarget.label}` : "Analyze this folder";

  onMount(() => {
    let alive = true;
    void (async () => {
      try {
        const info = await getInfo();
        if (!alive) return;
        version = info.version;
        scanTargets = info.scanTargets;
        path = info.defaultPath;
        if (info.activeScanId !== null) {
          scanId = info.activeScanId;
          phase = "starting";
          busy = true;
          schedulePoll(0);
        }
      } catch (error) {
        if (alive) message = String(error);
      }
    })();

    return () => {
      alive = false;
      if (pollTimer) clearTimeout(pollTimer);
      if (searchTimer) clearTimeout(searchTimer);
    };
  });

  async function chooseFolder() {
    try {
      const chosen = await pickFolder();
      if (chosen.path) path = chosen.path;
    } catch (error) {
      message = String(error);
    }
  }

  async function beginScan() {
    if (!path.trim()) {
      message = "Choose a directory first.";
      return;
    }
    if (pollTimer) clearTimeout(pollTimer);
    phase = "starting";
    busy = true;
    message = "";
    status = null;
    page = null;
    history = [];
    selected = null;
    treemapItems = [];
    largestFiles = [];
    largestDirectories = [];
    scanErrors = [];
    activeTab = "browse";
    offset = 0;
    query = "";
    try {
      const started = await startScan({
        path,
        threads: Number(threads) || 0,
        followSymlinks,
        stayOnFilesystem,
        deduplicateHardLinks,
      });
      scanId = started.scanId;
      phase = "scanning";
      schedulePoll(0);
    } catch (error) {
      phase = "error";
      message = String(error);
      busy = false;
    }
  }

  function schedulePoll(delay = 180) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(pollStatus, delay);
  }

  async function pollStatus() {
    if (scanId === null) return;
    try {
      status = await getScanStatus(scanId);
      if (status.phase === "scanning") {
        phase = "scanning";
        schedulePoll();
      } else if (status.phase === "error") {
        phase = "error";
        message = status.error ?? "The scan failed.";
        busy = false;
      } else if (status.phase === "complete" && status.rootId !== null) {
        phase = "complete";
        busy = false;
        await openDirectory(status.rootId, false);
        await Promise.all([loadLargest(), loadErrors()]);
      }
    } catch (error) {
      phase = "error";
      message = String(error);
      busy = false;
    }
  }

  async function cancelScan() {
    if (scanId === null) return;
    try {
      await cancelScanRequest(scanId);
      message = "Finishing cancellation and preserving partial results…";
    } catch (error) {
      message = String(error);
    }
  }

  function childrenRequest(parentId: number, options?: Partial<{
    metric: Metric;
    sort: SortField;
    descending: boolean;
    query: string;
    offset: number;
    limit: number;
  }>) {
    return {
      scanId,
      parentId,
      metric: options?.metric ?? metric,
      sort: options?.sort ?? sort,
      descending: options?.descending ?? descending,
      query: options?.query ?? query,
      offset: options?.offset ?? offset,
      limit: options?.limit ?? pageSize,
    };
  }

  async function refreshDirectory() {
    if (scanId === null || !current) return;
    const activeScanId = scanId;
    const generation = ++loadGeneration;
    try {
      const [nextPage, mapPage] = await Promise.all([
        getChildren(activeScanId, childrenRequest(current.id)),
        getChildren(
          activeScanId,
          childrenRequest(current.id, {
            sort: "size",
            descending: true,
            offset: 0,
            limit: 36,
          }),
        ),
      ]);
      if (generation !== loadGeneration) return;
      page = nextPage;
      treemapItems = mapPage.items.filter((item) => sizeOf(item) > 0);
      selected = null;
    } catch (error) {
      message = String(error);
    }
  }

  async function openDirectory(nodeId: number, pushHistory = true) {
    if (scanId === null) return;
    const activeScanId = scanId;
    offset = 0;
    query = "";
    const generation = ++loadGeneration;
    try {
      const [nextPage, mapPage] = await Promise.all([
        getChildren(activeScanId, childrenRequest(nodeId, { offset: 0, query: "" })),
        getChildren(
          activeScanId,
          childrenRequest(nodeId, {
            sort: "size",
            descending: true,
            query: "",
            offset: 0,
            limit: 36,
          }),
        ),
      ]);
      if (generation !== loadGeneration) return;
      page = nextPage;
      treemapItems = mapPage.items.filter((item) => sizeOf(item) > 0);
      selected = null;
      if (history.length === 0) {
        history = [nextPage.parent];
      } else if (pushHistory && history[history.length - 1]?.id !== nextPage.parent.id) {
        history = [...history, nextPage.parent];
      }
    } catch (error) {
      message = String(error);
    }
  }

  async function goUp() {
    if (!canGoBack) return;
    history = history.slice(0, -1);
    const target = history[history.length - 1];
    await openDirectory(target.id, false);
  }

  async function goToCrumb(index: number) {
    const target = history[index];
    history = history.slice(0, index + 1);
    await openDirectory(target.id, false);
  }

  function queueSearch() {
    offset = 0;
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(refreshDirectory, 180);
  }

  async function setSort(next: SortField) {
    if (sort === next) {
      descending = !descending;
    } else {
      sort = next;
      descending = next !== "name";
    }
    offset = 0;
    await refreshDirectory();
  }

  async function setSizeSort(nextMetric: Metric) {
    if (sort === "size" && metric === nextMetric) {
      descending = !descending;
    } else {
      metric = nextMetric;
      sort = "size";
      descending = true;
    }
    offset = 0;
    await Promise.all([refreshDirectory(), loadLargest()]);
  }

  async function toggleMetric() {
    metric = metric === "allocated" ? "logical" : "allocated";
    offset = 0;
    await Promise.all([refreshDirectory(), loadLargest()]);
  }

  async function changePage(direction: number) {
    if (!page) return;
    const next = Math.max(0, Math.min(page.total - 1, offset + direction * pageSize));
    offset = Math.floor(next / pageSize) * pageSize;
    await refreshDirectory();
  }

  async function activateNode(node: NodeView) {
    if (node.kind === "directory") {
      await openDirectory(node.id);
    } else {
      selected = node;
    }
  }

  async function loadLargest() {
    if (scanId === null) return;
    const activeScanId = scanId;
    try {
      [largestFiles, largestDirectories] = await Promise.all([
        getLargest(activeScanId, "file", metric, 100),
        getLargest(activeScanId, "directory", metric, 100),
      ]);
    } catch (error) {
      message = String(error);
    }
  }

  async function loadErrors() {
    if (scanId === null) return;
    try {
      scanErrors = await getErrors(scanId);
    } catch (error) {
      message = String(error);
    }
  }

  async function openNode(node: NodeView) {
    if (scanId === null) return;
    try {
      await openNodeRequest(scanId, node.id);
    } catch (error) {
      message = String(error);
    }
  }

  async function revealNode(node: NodeView) {
    if (scanId === null) return;
    try {
      await revealNodeRequest(scanId, node.id);
    } catch (error) {
      message = String(error);
    }
  }

  function sizeOf(node: NodeView): number {
    return metric === "allocated" ? node.allocatedSize : node.logicalSize;
  }

  function formatBytes(bytes: number): string {
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if (bytes < 1024) return `${bytes} B`;
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(2)} ${units[unit]}`;
  }

  function formatCount(value: number): string {
    return new Intl.NumberFormat().format(value);
  }

  function formatDate(value: number | null): string {
    if (value === null) return "—";
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
    }).format(new Date(value));
  }

  function kindLabel(kind: NodeView["kind"]): string {
    return kind === "directory" ? "Folder" : kind.charAt(0).toUpperCase() + kind.slice(1);
  }

  function tileStyle(node: NodeView, index: number): string {
    const total = current ? Math.max(1, sizeOf(current)) : 1;
    const percentage = Math.max(7, Math.min(55, (sizeOf(node) / total) * 100));
    const colors = ["#24c7a3", "#3aa8dc", "#7276e8", "#d08b57", "#be638d", "#6eaf78"];
    return `--weight:${percentage}; --tile-color:${colors[index % colors.length]}`;
  }
</script>

<svelte:head>
  <title>Web Disk Analyzer</title>
</svelte:head>

<div class="app-shell">
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark"><span></span></span>
      <div>
        <strong>Disk Analyzer</strong>
        <small>Local-first. Nothing leaves your machine.</small>
      </div>
    </div>
    <div class="top-status" class:running={phase === "scanning" || phase === "starting"} class:done={phase === "complete"}>
      <span class="status-dot"></span>
      {phase === "scanning" || phase === "starting" ? "Scanning" : phase === "complete" ? "Ready" : phase === "error" ? "Error" : "Idle"}
    </div>
  </header>

  <div class="workspace">
    <aside class="sidebar">
      <section>
        <p class="eyebrow">SCAN TARGET</p>
        <label class="path-control">
          <span class="path-icon">⌁</span>
          <input bind:value={path} disabled={busy} aria-label="Directory to scan" />
          <button class="icon-button" on:click={chooseFolder} disabled={busy} title="Browse">…</button>
        </label>
        {#if scanTargets.length}
          <div class="scan-targets" aria-label="Common scan locations">
            {#each scanTargets.slice(0, 5) as target}
              <button
                class:active={path === target.path}
                disabled={busy}
                title={`${target.label} — ${target.detail}`}
                on:click={() => (path = target.path)}
              >{target.label}</button>
            {/each}
          </div>
        {/if}
        {#if phase === "scanning"}
          <button class="primary danger" on:click={cancelScan}>Cancel scan</button>
        {:else}
          <button class="primary" on:click={beginScan} disabled={!path.trim()}>{analyzeLabel}</button>
        {/if}
      </section>

      <section class="settings">
        <p class="eyebrow">ACCURACY</p>
        <label class="toggle-row">
          <span>
            <strong>Stay on filesystem</strong>
            <small>Avoid mounted volumes</small>
          </span>
          <input type="checkbox" bind:checked={stayOnFilesystem} disabled={busy} />
        </label>
        <label class="toggle-row">
          <span>
            <strong>Deduplicate hard links</strong>
            <small>Count allocated blocks once</small>
          </span>
          <input type="checkbox" bind:checked={deduplicateHardLinks} disabled={busy} />
        </label>
        <label class="toggle-row">
          <span>
            <strong>Follow symbolic links</strong>
            <small>Loop detection remains active</small>
          </span>
          <input type="checkbox" bind:checked={followSymlinks} disabled={busy} />
        </label>
        <label class="number-row">
          <span>
            <strong>Workers</strong>
            <small>0 chooses automatically</small>
          </span>
          <input type="number" min="0" max="64" bind:value={threads} disabled={busy} />
        </label>
      </section>

      <section class="size-note">
        <div class="size-key logical"></div>
        <div><strong>Logical</strong><small>Content length applications see</small></div>
        <div class="size-key allocated"></div>
        <div><strong>Allocated</strong><small>Filesystem blocks currently used</small></div>
      </section>

      <div class="sidebar-footer">
        <span>Rust scan engine</span>
        <span>{version ? `v${version}` : ""}</span>
      </div>
    </aside>

    <main class="content">
      {#if message}
        <div class="notice" class:error={phase === "error"}>
          <span>{message}</span>
          <button on:click={() => (message = "")}>×</button>
        </div>
      {/if}

      {#if phase === "idle" || phase === "starting"}
        <section class="empty-state">
          <div class="empty-visual">
            <div class="disk-ring"><span></span></div>
            <div class="scan-line"></div>
          </div>
          <p class="eyebrow">LOCAL · PRIVATE · CROSS-PLATFORM</p>
          <h1>Find what is consuming<br />your storage.</h1>
          <p>Choose a directory or an entire volume. The scanner reports both apparent content size and real allocated storage. It runs on your machine and never sends file data anywhere.</p>
          <div class="empty-features">
            <span>Directory rollups</span><span>Sparse-file aware</span><span>Hard-link safe</span>
          </div>
        </section>
      {:else if phase === "scanning"}
        <section class="scan-view">
          <div class="scanner-visual">
            <div class="scanner-ring"><span></span></div>
          </div>
          <p class="eyebrow">FILESYSTEM DISCOVERY</p>
          <h1>Mapping storage…</h1>
          <p class="current-path">{progress?.currentPath ?? path}</p>
          <div class="indeterminate"><span></span></div>
          <div class="live-stats">
            <article><span>FILES</span><strong>{formatCount(progress?.files ?? 0)}</strong></article>
            <article><span>DIRECTORIES</span><strong>{formatCount(progress?.directories ?? 0)}</strong></article>
            <article><span>LOGICAL</span><strong>{formatBytes(progress?.logicalBytes ?? 0)}</strong></article>
            <article><span>ALLOCATED</span><strong>{formatBytes(progress?.allocatedBytes ?? 0)}</strong></article>
            <article><span>ERRORS</span><strong>{formatCount(progress?.errors ?? 0)}</strong></article>
            <article><span>ELAPSED</span><strong>{((progress?.elapsedMs ?? 0) / 1000).toFixed(1)}s</strong></article>
          </div>
          <p class="scan-hint">A percentage would require reading everything twice, so progress reports live throughput instead.</p>
        </section>
      {:else if phase === "error"}
        <section class="empty-state error-state">
          <div class="error-symbol">!</div>
          <p class="eyebrow">SCAN FAILED</p>
          <h1>We could not read that location.</h1>
          <p>{message || status?.error || "The filesystem returned an unexpected error."}</p>
          <button class="secondary" on:click={beginScan}>Try again</button>
        </section>
      {:else if phase === "complete" && summary}
        <section class="results">
          <div class="result-heading">
            <div>
              <p class="eyebrow">SCAN {summary.canceled ? "PARTIAL" : "COMPLETE"}</p>
              <h1>{summary.canceled ? "Partial results preserved" : "Storage mapped"}</h1>
              <p>{summary.root} · {(summary.elapsedMs / 1000).toFixed(2)} seconds</p>
            </div>
            <div class="heading-actions">
              <button class="metric-toggle" on:click={toggleMetric}>
                Sorting by <strong>{metric}</strong><span>⇄</span>
              </button>
              <button class="secondary compact" on:click={beginScan}>Rescan</button>
            </div>
          </div>

          <div class="summary-grid">
            <article class="accent-green">
              <span>ALLOCATED SPACE</span><strong>{formatBytes(summary.allocatedBytes)}</strong>
              <small>Physical blocks represented by the scan</small>
            </article>
            <article class="accent-blue">
              <span>LOGICAL SIZE</span><strong>{formatBytes(summary.logicalBytes)}</strong>
              <small>Apparent content length</small>
            </article>
            <article>
              <span>FILES</span><strong>{formatCount(summary.files)}</strong>
              <small>{formatCount(summary.directories)} directories</small>
            </article>
            <article class:warn={summary.errors > 0}>
              <span>SCAN COVERAGE</span><strong>{summary.errors === 0 ? "Clean" : `${summary.errors} skipped`}</strong>
              <small>{summary.hardLinkDuplicates} hard-link duplicates avoided</small>
            </article>
          </div>

          <nav class="tabs" aria-label="Result views">
            <button class:active={activeTab === "browse"} on:click={() => (activeTab = "browse")}>Browse</button>
            <button class:active={activeTab === "largest"} on:click={() => (activeTab = "largest")}>Largest</button>
            <button class:active={activeTab === "errors"} on:click={() => (activeTab = "errors")}>
              Errors <span>{summary.errors}</span>
            </button>
          </nav>

          {#if activeTab === "browse" && page}
            <div class="browser-toolbar">
              <button class="icon-button bordered" on:click={goUp} disabled={!canGoBack} title="Parent directory">↑</button>
              <div class="breadcrumbs">
                {#each history as crumb, index}
                  <button on:click={() => goToCrumb(index)} class:current={index === history.length - 1}>{crumb.name || crumb.path}</button>
                  {#if index < history.length - 1}<span>›</span>{/if}
                {/each}
              </div>
              <label class="search-box">
                <span>⌕</span>
                <input bind:value={query} on:input={queueSearch} placeholder="Filter this directory" />
              </label>
            </div>

            <section class="treemap-card">
              <div class="section-heading">
                <div><p class="eyebrow">SPACE MAP</p><h2>Largest children</h2></div>
                <small>Area approximates {metric} size</small>
              </div>
              {#if treemapItems.length}
                <div class="treemap">
                  {#each treemapItems as node, index}
                    <button
                      class="tile"
                      class:file={node.kind !== "directory"}
                      style={tileStyle(node, index)}
                      on:click={() => (selected = node)}
                      on:dblclick={() => activateNode(node)}
                      title={node.path}
                    >
                      <strong>{node.name}</strong>
                      <span>{formatBytes(sizeOf(node))}</span>
                    </button>
                  {/each}
                </div>
              {:else}
                <p class="no-data">This directory has no sized children matching the filter.</p>
              {/if}
            </section>

            <section class="table-card">
              <div class="section-heading table-title">
                <div><p class="eyebrow">DIRECTORY CONTENTS</p><h2>{formatCount(page.total)} entries</h2></div>
                <small>Double-click a folder to descend</small>
              </div>
              <div class="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th><button on:click={() => setSort("kind")}>TYPE</button></th>
                      <th><button on:click={() => setSort("name")}>NAME {sort === "name" ? (descending ? "↓" : "↑") : ""}</button></th>
                      <th><button on:click={() => setSizeSort("logical")}>LOGICAL {sort === "size" && metric === "logical" ? (descending ? "↓" : "↑") : ""}</button></th>
                      <th><button on:click={() => setSizeSort("allocated")}>ALLOCATED {sort === "size" && metric === "allocated" ? (descending ? "↓" : "↑") : ""}</button></th>
                      <th><button on:click={() => setSort("files")}>FILES</button></th>
                      <th><button on:click={() => setSort("modified")}>MODIFIED</button></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each page.items as node}
                      <tr
                        class:selected={selected?.id === node.id}
                        on:click={() => (selected = node)}
                        on:dblclick={() => activateNode(node)}
                      >
                        <td><span class="kind-badge {node.kind}">{node.kind === "directory" ? "DIR" : node.kind === "file" ? "FILE" : node.kind === "symlink" ? "LINK" : "OTHER"}</span></td>
                        <td class="name-cell">
                          <strong>{node.name}</strong>
                          {#if node.mountPoint}<span class="flag">mount</span>{/if}
                          {#if node.hardLinkDuplicate}<span class="flag">hard link</span>{/if}
                        </td>
                        <td>{formatBytes(node.logicalSize)}</td>
                        <td class:active-size={metric === "allocated"}>{formatBytes(node.allocatedSize)}</td>
                        <td>{node.kind === "directory" ? formatCount(node.fileCount) : "—"}</td>
                        <td>{formatDate(node.modifiedUnixMs)}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
              <footer class="pagination">
                <span>Showing {page.total === 0 ? 0 : page.offset + 1}–{Math.min(page.offset + page.items.length, page.total)} of {formatCount(page.total)}</span>
                <div><button on:click={() => changePage(-1)} disabled={currentPage <= 1}>Previous</button><span>{currentPage} / {totalPages}</span><button on:click={() => changePage(1)} disabled={currentPage >= totalPages}>Next</button></div>
              </footer>
            </section>
          {:else if activeTab === "largest"}
            <div class="largest-grid">
              <section class="ranking-card">
                <div class="section-heading"><div><p class="eyebrow">TOP 100</p><h2>Largest files</h2></div></div>
                <div class="ranking-list">
                  {#each largestFiles as node, index}
                    <button on:click={() => (selected = node)}>
                      <span class="rank">{index + 1}</span><span class="ranking-name"><strong>{node.name}</strong><small>{node.path}</small></span><span>{formatBytes(sizeOf(node))}</span>
                    </button>
                  {/each}
                </div>
              </section>
              <section class="ranking-card">
                <div class="section-heading"><div><p class="eyebrow">TOP 100</p><h2>Largest directories</h2></div></div>
                <div class="ranking-list">
                  {#each largestDirectories as node, index}
                    <button on:click={() => (selected = node)} on:dblclick={() => openDirectory(node.id)}>
                      <span class="rank">{index + 1}</span><span class="ranking-name"><strong>{node.name}</strong><small>{node.path}</small></span><span>{formatBytes(sizeOf(node))}</span>
                    </button>
                  {/each}
                </div>
              </section>
            </div>
          {:else if activeTab === "errors"}
            <section class="error-list-card">
              <div class="section-heading"><div><p class="eyebrow">TRANSPARENT COVERAGE</p><h2>Skipped and changed paths</h2></div><small>Up to 100 examples are retained</small></div>
              {#if scanErrors.length === 0}
                <div class="clean-state"><span>✓</span><h3>No filesystem errors</h3><p>Every discovered entry was successfully inspected.</p></div>
              {:else}
                <div class="error-list">
                  {#each scanErrors as error}
                    <article><strong>{error.path}</strong><p>{error.message}</p></article>
                  {/each}
                </div>
              {/if}
            </section>
          {/if}
        </section>
      {/if}
    </main>
  </div>

  {#if selected}
    <aside class="details-drawer">
      <button class="drawer-close" on:click={() => (selected = null)}>×</button>
      <p class="eyebrow">SELECTED {selected.kind.toUpperCase()}</p>
      <h2>{selected.name}</h2>
      <p class="drawer-path">{selected.path}</p>
      <div class="drawer-stats">
        <div><span>Logical</span><strong>{formatBytes(selected.logicalSize)}</strong></div>
        <div><span>Allocated</span><strong>{formatBytes(selected.allocatedSize)}</strong></div>
        {#if selected.kind === "directory"}
          <div><span>Files below</span><strong>{formatCount(selected.fileCount)}</strong></div>
          <div><span>Directories</span><strong>{formatCount(selected.directoryCount)}</strong></div>
        {/if}
        <div><span>Modified</span><strong>{formatDate(selected.modifiedUnixMs)}</strong></div>
        <div><span>Type</span><strong>{kindLabel(selected.kind)}</strong></div>
      </div>
      <div class="drawer-actions">
        {#if selected.kind === "directory"}<button class="primary" on:click={() => openDirectory(selected!.id)}>Browse here</button>{/if}
        <button class="secondary" on:click={() => revealNode(selected!)}>Reveal in file manager</button>
        <button class="ghost" on:click={() => openNode(selected!)}>Open with system</button>
      </div>
    </aside>
    <button class="drawer-scrim" aria-label="Close details" on:click={() => (selected = null)}></button>
  {/if}
</div>
