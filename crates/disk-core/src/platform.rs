use std::fs::Metadata;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    volume: u64,
    index: u64,
}

#[cfg(unix)]
pub(crate) fn allocated_size(_path: &Path, metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(unix)]
pub(crate) fn device_id(_path: &Path, metadata: &Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.dev())
}

#[cfg(unix)]
pub(crate) fn file_identity(_path: &Path, metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    (metadata.nlink() > 1).then(|| FileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
    })
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
pub(crate) fn allocated_size(path: &Path, metadata: &Metadata) -> u64 {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, SetLastError};
    use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;

    if let Some(information) = standard_information(path) {
        return information.AllocationSize.max(0) as u64;
    }

    let wide = wide_path(path);
    let mut high = 0_u32;
    unsafe {
        SetLastError(ERROR_SUCCESS);
        let low = GetCompressedFileSizeW(wide.as_ptr(), &mut high);
        if low == u32::MAX && GetLastError() != ERROR_SUCCESS {
            metadata.len()
        } else {
            (u64::from(high) << 32) | u64::from(low)
        }
    }
}

#[cfg(windows)]
fn standard_information(
    path: &Path,
) -> Option<windows_sys::Win32::Storage::FileSystem::FILE_STANDARD_INFO> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileStandardInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    let wide = wide_path(path);
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut information = FILE_STANDARD_INFO::default();
        let succeeded = GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut information as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        ) != 0;
        CloseHandle(handle);
        succeeded.then_some(information)
    }
}

#[cfg(windows)]
fn file_information(
    path: &Path,
) -> Option<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::mem::MaybeUninit;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
        OPEN_EXISTING,
    };

    let wide = wide_path(path);
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        let succeeded = GetFileInformationByHandle(handle, information.as_mut_ptr()) != 0;
        CloseHandle(handle);
        succeeded.then(|| information.assume_init())
    }
}

#[cfg(windows)]
pub(crate) fn device_id(path: &Path, _metadata: &Metadata) -> Option<u64> {
    file_information(path).map(|information| u64::from(information.dwVolumeSerialNumber))
}

#[cfg(windows)]
pub(crate) fn file_identity(path: &Path, _metadata: &Metadata) -> Option<FileIdentity> {
    file_information(path).and_then(|information| {
        (information.nNumberOfLinks > 1).then(|| FileIdentity {
            volume: u64::from(information.dwVolumeSerialNumber),
            index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn allocated_size(_path: &Path, metadata: &Metadata) -> u64 {
    metadata.len()
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn device_id(_path: &Path, _metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn file_identity(_path: &Path, _metadata: &Metadata) -> Option<FileIdentity> {
    None
}
