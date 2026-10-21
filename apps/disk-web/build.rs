use std::fs;
use std::path::Path;

fn main() {
    // rust-embed needs the folder to exist while the crate is compiled. Development builds read
    // assets from disk, so a plain placeholder is enough until `npm run build` has been run.
    let dist = Path::new("ui-dist");
    if !dist.exists() {
        fs::create_dir_all(dist).expect("create ui-dist");
        fs::write(
            dist.join("index.html"),
            "<!doctype html><title>Disk Analyzer</title><p>Build the web UI first: <code>npm install &amp;&amp; npm run build</code>.</p>",
        )
        .expect("write placeholder UI");
    }

    println!("cargo:rerun-if-changed=ui-dist");
}
