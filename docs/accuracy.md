# Accuracy and filesystem semantics

Disk usage has several valid meanings. Disk Analyzer retains enough information to show the two meanings that are portable and useful in day-to-day cleanup work.

## Logical size

Logical size is the length reported by file metadata. It describes how many bytes an application sees when reading the complete file. Sparse holes and transparent compression do not reduce it. Each hard-link path displays the file's logical length because each path opens the same complete content.

## Allocated size

Allocated size describes storage assigned by the filesystem:

- Unix platforms use `st_blocks`, whose units are defined as 512 bytes.
- Windows uses `FILE_STANDARD_INFO.AllocationSize` and falls back to `GetCompressedFileSizeW` when handle information is unavailable.
- Hard links are identified by device/volume and inode/file index. Later paths contribute zero additional allocated bytes when deduplication is enabled.
- Directory metadata and symlink storage are included when the operating system reports them.

On Linux, a completed scan with the default hard-link policy should closely match `du -B1 -s PATH`. Logical path totals can be compared with `du --apparent-size --count-links -B1 -s PATH`.

## Why a directory scan may not equal volume usage

No portable directory walker can assign every used volume block to a visible path. Differences can include:

- filesystem metadata, journals, and reserved blocks;
- snapshots and deleted-but-open files;
- copy-on-write reflinks or shared extents;
- inaccessible directories and locked files;
- network filesystem accounting rules;
- files created, removed, truncated, or expanded during the scan.

The UI therefore reports skipped paths instead of hiding them. A scan is a live traversal, not an atomic filesystem snapshot.

## Links and mount points

Symbolic links and Windows reparse points are not followed by default. Following links is opt-in and the walker detects cycles. “Stay on filesystem” is enabled by default so scanning `/` does not silently traverse other mounted volumes; mount-point entries remain visible but their children are not read.

## Progress

An exact percentage requires knowing the number of entries before scanning them, which would require a second traversal. The application instead reports live files, directories, bytes, errors, elapsed time, and the current path.

