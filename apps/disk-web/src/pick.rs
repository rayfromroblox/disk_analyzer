use std::process::Command;

/// Opens the operating system's native folder picker and blocks until the user closes it.
/// Returns `Ok(None)` when the dialog was canceled.
pub fn choose_directory() -> Result<Option<String>, String> {
    choose_directory_platform()
}

#[cfg(target_os = "macos")]
fn choose_directory_platform() -> Result<Option<String>, String> {
    let output = Command::new("osascript")
        .args([
            "-e",
            "POSIX path of (choose folder with prompt \"Choose a folder to analyze\")",
        ])
        .output()
        .map_err(|error| format!("could not open the macOS folder picker: {error}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((!path.is_empty()).then_some(path))
}

#[cfg(target_os = "windows")]
fn choose_directory_platform() -> Result<Option<String>, String> {
    let script = concat!(
        "Add-Type -AssemblyName System.Windows.Forms; ",
        "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog; ",
        "$dialog.Description = 'Choose a folder to analyze'; ",
        "if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) ",
        "{ [Console]::Out.Write($dialog.SelectedPath) } else { exit 1 }"
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-STA", "-Command", script])
        .output()
        .map_err(|error| format!("could not open the folder picker: {error}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((!path.is_empty()).then_some(path))
}

#[cfg(target_os = "linux")]
fn choose_directory_platform() -> Result<Option<String>, String> {
    const TITLE: &str = "Choose a folder to analyze";

    let zenity = Command::new("zenity")
        .args(["--file-selection", "--directory", "--title", TITLE])
        .output();

    match zenity {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            return Ok((!path.is_empty()).then_some(path));
        }
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("could not open the zenity folder picker: {error}")),
    }

    let kdialog = Command::new("kdialog")
        .args(["--getexistingdirectory", ".", "--title", TITLE])
        .output();

    match kdialog {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            Ok((!path.is_empty()).then_some(path))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
            "No native folder picker was found. Install zenity or kdialog, or type the path directly."
                .to_owned(),
        ),
        Err(error) => Err(format!("could not open the kdialog folder picker: {error}")),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn choose_directory_platform() -> Result<Option<String>, String> {
    Err("The native folder picker is not supported on this platform. Type the path instead.".into())
}
