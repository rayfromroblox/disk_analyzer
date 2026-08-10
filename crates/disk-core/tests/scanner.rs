use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::time::Duration;

use disk_core::{CancellationToken, EntryKind, ScanConfig, SizeMetric, scan};
use tempfile::tempdir;

fn config(path: &std::path::Path) -> ScanConfig {
    let mut config = ScanConfig::new(path);
    config.threads = 2;
    config.progress_interval = Duration::ZERO;
    config
}

#[test]
fn includes_files_directly_inside_root_and_nested_files() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("root.bin"), vec![1_u8; 17]).unwrap();
    fs::create_dir(fixture.path().join("nested")).unwrap();
    fs::write(fixture.path().join("nested/child.bin"), vec![2_u8; 29]).unwrap();

    let result = scan(config(fixture.path()), CancellationToken::new(), |_| {}).unwrap();

    assert_eq!(result.summary.files, 2);
    assert_eq!(result.summary.logical_bytes, 46);
    assert_eq!(result.node(result.root_id).unwrap().file_count, 2);
    let names: Vec<_> = result
        .largest(Some(EntryKind::File), SizeMetric::Logical, 10)
        .into_iter()
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(names, ["child.bin", "root.bin"]);
}

#[test]
fn aggregates_each_directory_independently() {
    let fixture = tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("a/b")).unwrap();
    fs::write(fixture.path().join("a/one"), vec![0_u8; 10]).unwrap();
    fs::write(fixture.path().join("a/b/two"), vec![0_u8; 20]).unwrap();

    let result = scan(config(fixture.path()), CancellationToken::new(), |_| {}).unwrap();
    let directory_a = result.nodes.iter().find(|node| node.name == "a").unwrap();
    let directory_b = result.nodes.iter().find(|node| node.name == "b").unwrap();

    assert_eq!(directory_a.logical_size, 30);
    assert_eq!(directory_a.file_count, 2);
    assert_eq!(directory_a.directory_count, 1);
    assert_eq!(directory_b.logical_size, 20);
    assert_eq!(directory_b.file_count, 1);
}

#[test]
fn distinguishes_sparse_apparent_and_allocated_size() {
    let fixture = tempdir().unwrap();
    let mut sparse = File::create(fixture.path().join("sparse.bin")).unwrap();
    sparse.seek(SeekFrom::Start(16 * 1024 * 1024)).unwrap();
    sparse.write_all(&[1]).unwrap();

    let result = scan(config(fixture.path()), CancellationToken::new(), |_| {}).unwrap();
    let file = result
        .nodes
        .iter()
        .find(|node| node.name == "sparse.bin")
        .unwrap();

    assert_eq!(file.logical_size, 16 * 1024 * 1024 + 1);
    #[cfg(unix)]
    assert!(file.allocated_size < file.logical_size);
}

#[cfg(unix)]
#[test]
fn counts_hard_link_storage_once_but_preserves_logical_sizes() {
    let fixture = tempdir().unwrap();
    let original = fixture.path().join("original.bin");
    fs::write(&original, vec![7_u8; 8192]).unwrap();
    fs::hard_link(&original, fixture.path().join("linked.bin")).unwrap();

    let result = scan(config(fixture.path()), CancellationToken::new(), |_| {}).unwrap();

    assert_eq!(result.summary.files, 2);
    assert_eq!(result.summary.logical_bytes, 16_384);
    assert_eq!(result.summary.hard_link_duplicates, 1);
    assert_eq!(
        result
            .nodes
            .iter()
            .filter(|node| node.hard_link_duplicate)
            .count(),
        1
    );
}

#[test]
fn preserves_partial_results_when_canceled() {
    let fixture = tempdir().unwrap();
    for index in 0..100 {
        fs::write(fixture.path().join(format!("{index}.bin")), [0_u8; 8]).unwrap();
    }

    let cancel = CancellationToken::new();
    let observer_cancel = cancel.clone();
    let result = scan(config(fixture.path()), cancel, move |progress| {
        if progress.files >= 1 {
            observer_cancel.cancel();
        }
    })
    .unwrap();

    assert!(result.summary.canceled);
    assert!(result.summary.files >= 1);
    assert!(result.summary.files < 100);
}

#[test]
fn an_immediate_cancellation_still_returns_a_valid_root() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("not-visited"), [0_u8; 8]).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    let result = scan(config(fixture.path()), cancellation, |_| {}).unwrap();

    assert!(result.summary.canceled);
    assert!(result.node(result.root_id).is_some());
}

#[test]
fn scanning_a_single_file_returns_that_file_as_the_root() {
    let fixture = tempdir().unwrap();
    let file = fixture.path().join("only.bin");
    fs::write(&file, [3_u8; 37]).unwrap();

    let result = scan(config(&file), CancellationToken::new(), |_| {}).unwrap();

    assert_eq!(result.summary.files, 1);
    assert_eq!(result.summary.logical_bytes, 37);
    assert_eq!(result.node(result.root_id).unwrap().kind, EntryKind::File);
    assert_eq!(result.path_for(result.root_id).unwrap(), file);
}

#[test]
fn does_not_follow_symlinks_by_default() {
    let fixture = tempdir().unwrap();
    fs::create_dir(fixture.path().join("real")).unwrap();
    fs::write(fixture.path().join("real/file"), [1_u8; 4]).unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(
        fixture.path().join("real"),
        fixture.path().join("directory-link"),
    )
    .unwrap();
    #[cfg(windows)]
    if std::os::windows::fs::symlink_dir(
        fixture.path().join("real"),
        fixture.path().join("directory-link"),
    )
    .is_err()
    {
        return;
    }

    let result = scan(config(fixture.path()), CancellationToken::new(), |_| {}).unwrap();

    assert_eq!(result.summary.files, 1);
    assert_eq!(result.summary.symlinks, 1);
}
