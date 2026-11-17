//! File inspection logic. Everything here is metadata / header only.
//! It NEVER decompresses archive content and NEVER decodes image pixels,
//! so a malicious file cannot turn validation itself into the attack.

use serde::Serialize;
use serde_json::json;
use std::io::Cursor;

// Thresholds for zip-bomb heuristics.
const MAX_RATIO: f64 = 100.0; // uncompressed / compressed
const MAX_TOTAL_UNCOMPRESSED: u64 = 1_000_000_000; // 1 GB
const MAX_ENTRIES: usize = 10_000;
const MAX_SINGLE_UNCOMPRESSED: u64 = 500_000_000; // 500 MB

#[derive(Serialize, Clone)]
pub struct Finding {
    pub severity: &'static str, // info | suspicious | malicious
    pub code: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct Report {
    pub file_type: String,
    pub size_bytes: usize,
    pub verdict: String, // clean | suspicious | malicious
    pub findings: Vec<Finding>,
    pub metrics: serde_json::Value,
}

fn finding(sev: &'static str, code: &str, detail: String) -> Finding {
    Finding { severity: sev, code: code.to_string(), detail }
}

/// Signatures commonly embedded to build polyglot / "worm" carriers.
fn scan_embedded_signatures(data: &[u8], skip_leading: usize) -> Vec<Finding> {
    let sigs: &[(&[u8], &str, &str)] = &[
        (b"MZ", "embedded_pe", "Windows PE/DOS executable header"),
        (b"\x7fELF", "embedded_elf", "ELF executable header"),
        (b"PK\x03\x04", "embedded_zip", "nested ZIP archive (polyglot carrier)"),
        (b"<?php", "embedded_php", "PHP script"),
        (b"<script", "embedded_script", "HTML/JS script tag"),
        (b"#!/", "embedded_shebang", "shell script shebang"),
        (b"\xca\xfe\xba\xbe", "embedded_class", "Java class / Mach-O fat binary"),
    ];
    let mut out = Vec::new();
    for (needle, code, what) in sigs {
        // start search past the legitimate magic bytes of the host format
        if let Some(off) = find_subslice(&data[skip_leading.min(data.len())..], needle) {
            let abs = off + skip_leading;
            // A host-format magic at offset 0 is expected; only report when embedded.
            if abs == 0 {
                continue;
            }
            out.push(finding(
                "suspicious",
                code,
                format!("{what} found at offset {abs}"),
            ));
        }
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn detect_type(data: &[u8]) -> &'static str {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        "zip"
    } else if data.starts_with(b"\xff\xd8\xff") {
        "jpeg"
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        "gif"
    } else if data.starts_with(b"%PDF-") {
        "pdf"
    } else {
        "unknown"
    }
}

fn worst(findings: &[Finding]) -> String {
    let mut v = "clean";
    for f in findings {
        match f.severity {
            "malicious" => return "malicious".to_string(),
            "suspicious" => v = "suspicious",
            _ => {}
        }
    }
    v.to_string()
}

pub fn inspect(data: &[u8]) -> Report {
    let ftype = detect_type(data);
    let mut findings = Vec::new();
    let mut metrics = json!({});

    match ftype {
        "zip" => inspect_zip(data, &mut findings, &mut metrics),
        "jpeg" => inspect_jpeg(data, &mut findings, &mut metrics),
        "gif" => inspect_gif(data, &mut findings, &mut metrics),
        "pdf" => inspect_pdf(data, &mut findings, &mut metrics),
        _ => findings.push(finding(
            "suspicious",
            "unknown_type",
            "unrecognized magic bytes; only zip/jpeg/gif are validated".into(),
        )),
    }

    let verdict = worst(&findings);
    Report {
        file_type: ftype.to_string(),
        size_bytes: data.len(),
        verdict,
        findings,
        metrics,
    }
}

fn inspect_zip(data: &[u8], findings: &mut Vec<Finding>, metrics: &mut serde_json::Value) {
    // Reads the central directory only. by_index() does not inflate entry data.
    let reader = Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            findings.push(finding("suspicious", "zip_parse_error", format!("{e}")));
            return;
        }
    };

    let entries = archive.len();
    let mut total_unc: u64 = 0;
    let mut total_comp: u64 = 0;
    let mut max_entry_unc: u64 = 0;
    let mut nested_zip = 0;

    for i in 0..entries {
        let f = match archive.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                findings.push(finding("suspicious", "zip_entry_error", format!("entry {i}: {e}")));
                continue;
            }
        };
        let unc = f.size();
        let comp = f.compressed_size();
        total_unc = total_unc.saturating_add(unc);
        total_comp = total_comp.saturating_add(comp);
        max_entry_unc = max_entry_unc.max(unc);
        let name = f.name().to_lowercase();
        if name.ends_with(".zip") || name.ends_with(".jar") {
            nested_zip += 1;
        }
    }

    let ratio = if total_comp > 0 {
        total_unc as f64 / total_comp as f64
    } else {
        0.0
    };

    *metrics = json!({
        "entries": entries,
        "total_uncompressed": total_unc,
        "total_compressed": total_comp,
        "compression_ratio": ratio,
        "max_entry_uncompressed": max_entry_unc,
        "nested_archives": nested_zip,
    });

    if entries > MAX_ENTRIES {
        findings.push(finding(
            "malicious",
            "zip_too_many_entries",
            format!("{entries} entries exceeds limit {MAX_ENTRIES}"),
        ));
    }
    if ratio > MAX_RATIO {
        findings.push(finding(
            "malicious",
            "zip_bomb_ratio",
            format!("compression ratio {ratio:.1}x exceeds {MAX_RATIO:.0}x"),
        ));
    }
    if total_unc > MAX_TOTAL_UNCOMPRESSED {
        findings.push(finding(
            "malicious",
            "zip_bomb_total_size",
            format!("declared {total_unc} bytes uncompressed exceeds {MAX_TOTAL_UNCOMPRESSED}"),
        ));
    }
    if max_entry_unc > MAX_SINGLE_UNCOMPRESSED {
        findings.push(finding(
            "malicious",
            "zip_bomb_single_entry",
            format!("one entry declares {max_entry_unc} bytes uncompressed"),
        ));
    }
    if nested_zip > 0 {
        findings.push(finding(
            "suspicious",
            "zip_nested_archive",
            format!("{nested_zip} nested archive(s) (recursive bomb vector)"),
        ));
    }
}

fn inspect_jpeg(data: &[u8], findings: &mut Vec<Finding>, metrics: &mut serde_json::Value) {
    // SOI = FFD8, EOI = FFD9. Anything after EOI is appended data.
    let eoi = find_subslice(data, b"\xff\xd9");
    let mut trailing = 0usize;
    match eoi {
        Some(pos) => {
            let end = pos + 2;
            trailing = data.len().saturating_sub(end);
            if trailing > 0 {
                findings.push(finding(
                    "suspicious",
                    "jpeg_trailing_data",
                    format!("{trailing} bytes after EOI marker (possible appended payload)"),
                ));
                // scan the trailing region for executable/script/zip signatures
                for f in scan_embedded_signatures(&data[end..], 0) {
                    findings.push(f);
                }
            }
        }
        None => findings.push(finding(
            "suspicious",
            "jpeg_no_eoi",
            "no EOI marker found (truncated or malformed)".into(),
        )),
    }

    // scan whole buffer (past SOI) for embedded carriers inside APPn/COM segments
    for f in scan_embedded_signatures(data, 2) {
        findings.push(f);
    }

    *metrics = json!({
        "has_eoi": eoi.is_some(),
        "trailing_bytes": trailing,
    });
}

fn inspect_gif(data: &[u8], findings: &mut Vec<Finding>, metrics: &mut serde_json::Value) {
    // GIF trailer byte is 0x3B. Content after the LAST trailer is appended data.
    let last_trailer = data.iter().rposition(|&b| b == 0x3b);
    let mut trailing = 0usize;
    match last_trailer {
        Some(pos) => {
            trailing = data.len().saturating_sub(pos + 1);
            if trailing > 0 {
                findings.push(finding(
                    "suspicious",
                    "gif_trailing_data",
                    format!("{trailing} bytes after trailer (GIFAR / appended payload vector)"),
                ));
                for f in scan_embedded_signatures(&data[pos + 1..], 0) {
                    findings.push(f);
                }
            }
        }
        None => findings.push(finding(
            "suspicious",
            "gif_no_trailer",
            "no trailer byte (0x3B) found".into(),
        )),
    }

    // whole-buffer scan past the 6-byte signature for embedded carriers
    for f in scan_embedded_signatures(data, 6) {
        findings.push(f);
    }

    *metrics = json!({
        "version": String::from_utf8_lossy(&data[0..6.min(data.len())]),
        "trailing_bytes": trailing,
    });
}

/// Grab the first http(s):// URL found, up to the first delimiter.
fn first_url(data: &[u8]) -> Option<String> {
    let start = find_subslice(data, b"http")?;
    let mut end = start;
    while end < data.len() {
        let c = data[end];
        // stop at whitespace, quotes, parens, backslash, or control bytes
        if c <= 0x20 || c == b'"' || c == b'\'' || c == b')' || c == b'(' || c == b'\\' {
            break;
        }
        end += 1;
    }
    let s = String::from_utf8_lossy(&data[start..end]).to_string();
    if s.starts_with("http") && s.len() > 7 {
        Some(s)
    } else {
        None
    }
}

fn inspect_pdf(data: &[u8], findings: &mut Vec<Finding>, metrics: &mut serde_json::Value) {
    let has = |needle: &[u8]| find_subslice(data, needle).is_some();

    let openaction = has(b"/OpenAction");
    let javascript = has(b"/JavaScript") || has(b"/JS");
    let launch = has(b"/Launch");
    let additional = has(b"/AA");
    let embedded = has(b"/EmbeddedFile");
    let uri = has(b"/URI") || has(b"launchURL");
    let auto = openaction || additional; // runs without a click

    if javascript {
        // JS that auto-runs on open is the dangerous combination.
        let sev = if auto { "malicious" } else { "suspicious" };
        findings.push(finding(
            sev,
            "pdf_javascript",
            "embedded JavaScript (/JS /JavaScript)".into(),
        ));
    }
    if openaction {
        findings.push(finding(
            if javascript { "malicious" } else { "suspicious" },
            "pdf_openaction",
            "/OpenAction runs an action automatically when the document opens".into(),
        ));
    }
    if additional {
        findings.push(finding(
            "suspicious",
            "pdf_additional_actions",
            "/AA additional-actions trigger code on events (open/close/focus)".into(),
        ));
    }
    if launch {
        findings.push(finding(
            "malicious",
            "pdf_launch_action",
            "/Launch action can start an external program".into(),
        ));
    }
    if embedded {
        findings.push(finding(
            "suspicious",
            "pdf_embedded_file",
            "/EmbeddedFile carries another file inside the PDF".into(),
        ));
    }
    if uri {
        let detail = match first_url(data) {
            Some(u) => format!("outbound URL action -> {u}"),
            None => "outbound URL action (/URI or launchURL)".into(),
        };
        findings.push(finding("suspicious", "pdf_outbound_url", detail));
    }

    // data after the last %%EOF (incremental-update abuse / appended payload)
    let last_eof = find_last_subslice(data, b"%%EOF");
    let mut trailing = 0usize;
    if let Some(pos) = last_eof {
        let end = pos + 5;
        // allow a single trailing newline
        trailing = data.len().saturating_sub(end);
        if trailing > 2 {
            findings.push(finding(
                "suspicious",
                "pdf_trailing_data",
                format!("{trailing} bytes after the last %%EOF marker"),
            ));
        }
    }

    // embedded executable carriers
    for f in scan_embedded_signatures(data, 5) {
        findings.push(f);
    }

    *metrics = json!({
        "has_openaction": openaction,
        "has_javascript": javascript,
        "has_launch": launch,
        "has_embedded_file": embedded,
        "trailing_bytes": trailing,
    });
}

fn find_last_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}
