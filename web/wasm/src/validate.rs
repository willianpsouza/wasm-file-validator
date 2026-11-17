//! File inspection logic. Header / structural metadata only.
//! It never inflates archive bodies (beyond a bounded 4-byte magic probe per
//! entry) and never decodes image pixels, so a malicious file cannot turn
//! validation itself into the attack.
//!
//! Known limits (see README): this is a structural scanner, not a full parser.
//! It does not decrypt or inflate PDF object streams, does not recurse into
//! nested archives, and relies on ZIP central-directory sizes, which are
//! advisory. Treat verdicts as a fast first filter, not ground truth.

use serde::Serialize;
use serde_json::json;
use std::io::{Cursor, Read};

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
        let mut f = match archive.by_index(i) {
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
        // Detect nested archives by content magic, not just filename — a
        // recursive bomb renamed `payload.bin` must still be flagged. Reading a
        // 4-byte magic inflates at most 4 bytes, so the probe cannot itself bomb.
        let mut magic = [0u8; 4];
        let n = f.read(&mut magic).unwrap_or(0);
        let looks_zip = n >= 4 && (&magic == b"PK\x03\x04" || &magic == b"PK\x05\x06");
        let named_archive = name.ends_with(".zip") || name.ends_with(".jar");
        if looks_zip || named_archive {
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
    // Walk the marker structure to the REAL end-of-image. A bare search for the
    // EOI byte pair (\xff\xd9) is wrong: it occurs inside EXIF thumbnails and
    // entropy-coded scan data, which would miscompute the trailing offset.
    let end = jpeg_end(data);
    let mut trailing = 0usize;
    match end {
        Some(e) => {
            trailing = data.len().saturating_sub(e);
            if trailing > 0 {
                findings.push(finding(
                    "suspicious",
                    "jpeg_trailing_data",
                    format!("{trailing} bytes after EOI marker (possible appended payload)"),
                ));
                for f in scan_embedded_signatures(&data[e..], 0) {
                    findings.push(f);
                }
            }
        }
        None => findings.push(finding(
            "suspicious",
            "jpeg_no_eoi",
            "no valid EOI reached (truncated or malformed)".into(),
        )),
    }

    // scan whole buffer (past SOI) for carriers embedded inside APPn/COM segments
    for f in scan_embedded_signatures(data, 2) {
        findings.push(f);
    }

    *metrics = json!({
        "has_eoi": end.is_some(),
        "trailing_bytes": trailing,
    });
}

/// Walk JPEG markers from SOI and return the offset just past EOI, or None if
/// the stream is malformed / never reaches EOI. Segment lengths are honored so
/// FFD9 bytes inside thumbnails or scan data are not mistaken for the end.
fn jpeg_end(data: &[u8]) -> Option<usize> {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }
    let mut i = 2;
    while i < data.len() {
        if data[i] != 0xFF {
            return None; // not aligned on a marker -> malformed
        }
        // skip fill bytes (runs of 0xFF)
        while i < data.len() && data[i] == 0xFF {
            i += 1;
        }
        if i >= data.len() {
            return None;
        }
        let marker = data[i];
        i += 1;
        match marker {
            0xD9 => return Some(i),            // EOI
            0x01 | 0xD0..=0xD7 => continue,    // TEM / RSTn: no payload
            0xDA => {
                // SOS: skip the header, then scan entropy data to the next marker
                if i + 1 >= data.len() {
                    return None;
                }
                let len = ((data[i] as usize) << 8) | data[i + 1] as usize;
                if len < 2 {
                    return None;
                }
                i += len;
                while i + 1 < data.len() {
                    if data[i] == 0xFF {
                        let b = data[i + 1];
                        if b == 0x00 || (0xD0..=0xD7).contains(&b) {
                            i += 2; // byte-stuffing / restart marker: part of the scan
                            continue;
                        }
                        break; // a real marker starts here
                    }
                    i += 1;
                }
            }
            _ => {
                // marker segment with a 2-byte length
                if i + 1 >= data.len() {
                    return None;
                }
                let len = ((data[i] as usize) << 8) | data[i + 1] as usize;
                if len < 2 {
                    return None;
                }
                i += len;
            }
        }
    }
    None
}

fn inspect_gif(data: &[u8], findings: &mut Vec<Finding>, metrics: &mut serde_json::Value) {
    // Walk the block structure to the REAL trailer. The trailer byte 0x3B also
    // occurs as ordinary image/data bytes, so a last-0x3B search miscomputes the
    // trailing offset (false positives and missed appended payloads).
    let end = gif_end(data);
    let mut trailing = 0usize;
    match end {
        Some(e) => {
            trailing = data.len().saturating_sub(e);
            if trailing > 0 {
                findings.push(finding(
                    "suspicious",
                    "gif_trailing_data",
                    format!("{trailing} bytes after trailer (GIFAR / appended payload vector)"),
                ));
                for f in scan_embedded_signatures(&data[e..], 0) {
                    findings.push(f);
                }
            }
        }
        None => findings.push(finding(
            "suspicious",
            "gif_no_trailer",
            "no valid trailer reached (truncated or malformed)".into(),
        )),
    }

    for f in scan_embedded_signatures(data, 6) {
        findings.push(f);
    }

    *metrics = json!({
        "version": String::from_utf8_lossy(&data[0..6.min(data.len())]),
        "has_trailer": end.is_some(),
        "trailing_bytes": trailing,
    });
}

/// Walk GIF blocks and return the offset just past the trailer (0x3B), or None
/// if malformed. Skips color tables and sub-block streams so a 0x3B data byte is
/// never mistaken for the trailer.
fn gif_end(data: &[u8]) -> Option<usize> {
    if data.len() < 13 || !(data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return None;
    }
    // Logical Screen Descriptor: 7 bytes at 6..13; packed flags at byte 10.
    let packed = data[10];
    let mut i = 13usize;
    if packed & 0x80 != 0 {
        i += 3 * (1usize << ((packed & 0x07) + 1)); // global color table
    }
    while i < data.len() {
        match data[i] {
            0x3B => return Some(i + 1), // trailer
            0x21 => {
                // extension: introducer + label, then sub-blocks
                i += 2;
                i = gif_skip_subblocks(data, i)?;
            }
            0x2C => {
                // image descriptor: 10 bytes (separator + 9), optional local table
                if i + 10 > data.len() {
                    return None;
                }
                let lpacked = data[i + 9];
                i += 10;
                if lpacked & 0x80 != 0 {
                    i += 3 * (1usize << ((lpacked & 0x07) + 1));
                }
                if i >= data.len() {
                    return None;
                }
                i += 1; // LZW minimum code size
                i = gif_skip_subblocks(data, i)?;
            }
            _ => return None, // malformed
        }
    }
    None
}

/// Skip a GIF sub-block stream (length-prefixed blocks ending with a 0 length).
fn gif_skip_subblocks(data: &[u8], mut i: usize) -> Option<usize> {
    loop {
        if i >= data.len() {
            return None;
        }
        let len = data[i] as usize;
        i += 1;
        if len == 0 {
            return Some(i); // block terminator
        }
        i += len;
    }
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
    // Normalize PDF name hex escapes (/J#61vaScript -> /JavaScript) before
    // matching, so simple name obfuscation does not evade the scan.
    let norm = normalize_pdf_names(data);
    let has = |needle: &[u8]| find_subslice(&norm, needle).is_some();

    let openaction = has(b"/OpenAction");
    let javascript = has(b"/JavaScript") || has(b"/JS");
    let launch = has(b"/Launch");
    let additional = has(b"/AA");
    let embedded = has(b"/EmbeddedFile");
    let uri = has(b"/URI") || has(b"launchURL");
    let auto = openaction || additional; // runs without a click

    // Object streams / Flate-compressed content cannot be seen by a header scan;
    // flag that blind spot so an obfuscated payload is not silently "clean".
    let compressed = has(b"/ObjStm") || has(b"/FlateDecode");

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
    if compressed && !(javascript || launch || openaction || additional || embedded) {
        findings.push(finding(
            "suspicious",
            "pdf_compressed_streams",
            "compressed object streams present; a header scan cannot inspect their \
             contents — decompress and re-check server-side"
                .into(),
        ));
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
        "has_compressed_streams": compressed,
        "trailing_bytes": trailing,
    });
}

/// Decode PDF name hex escapes (`#XX`) across the buffer so obfuscated names
/// match. Non-escape bytes are copied unchanged.
fn normalize_pdf_names(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'#' && i + 2 < data.len() {
            if let (Some(h), Some(l)) = (hexval(data[i + 1]), hexval(data[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn find_last_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn codes(r: &Report) -> Vec<String> {
        r.findings.iter().map(|f| f.code.clone()).collect()
    }

    // ---- helpers ----
    #[test]
    fn detect_type_covers_all() {
        assert_eq!(detect_type(b"PK\x03\x04rest"), "zip");
        assert_eq!(detect_type(b"\xff\xd8\xffmore"), "jpeg");
        assert_eq!(detect_type(b"GIF89a..."), "gif");
        assert_eq!(detect_type(b"GIF87a..."), "gif");
        assert_eq!(detect_type(b"%PDF-1.7"), "pdf");
        assert_eq!(detect_type(b"random"), "unknown");
    }

    #[test]
    fn subslice_and_url_helpers() {
        assert_eq!(find_subslice(b"hello", b"ll"), Some(2));
        assert_eq!(find_subslice(b"hello", b"zz"), None);
        assert_eq!(find_subslice(b"hi", b""), None);
        assert_eq!(find_last_subslice(b"a.b.c", b"."), Some(3));
        assert_eq!(
            first_url(b"stuff launchURL(\"https://evil.test/x\") end").as_deref(),
            Some("https://evil.test/x")
        );
        assert_eq!(first_url(b"no url here"), None);
    }

    #[test]
    fn unknown_type_flagged() {
        let r = inspect(b"not a known file");
        assert_eq!(r.file_type, "unknown");
        assert_eq!(r.verdict, "suspicious");
        assert!(codes(&r).contains(&"unknown_type".to_string()));
    }

    // ---- jpeg ----
    // FF D8 (SOI) · FF E0 len=7 APP0 "JFIF\0" · FF D9 (EOI)
    const JPEG_MIN: &[u8] = b"\xff\xd8\xff\xe0\x00\x07JFIF\x00\xff\xd9";

    #[test]
    fn jpeg_clean() {
        let r = inspect(JPEG_MIN);
        assert_eq!(r.file_type, "jpeg");
        assert_eq!(r.verdict, "clean");
        assert!(r.findings.is_empty());
    }

    #[test]
    fn jpeg_polyglot_with_appended_zip() {
        let mut data = JPEG_MIN.to_vec();
        data.extend_from_slice(b"PK\x03\x04payload"); // appended after EOI
        let r = inspect(&data);
        let c = codes(&r);
        assert!(c.contains(&"jpeg_trailing_data".to_string()));
        assert!(c.contains(&"embedded_zip".to_string()));
    }

    #[test]
    fn jpeg_internal_eoi_in_segment_is_not_the_end() {
        // APP1 (len=5) whose payload contains an FF D9 byte pair, then the real
        // EOI. A naive first-FFD9 search would stop inside the segment.
        let data = b"\xff\xd8\xff\xe1\x00\x05\xff\xd9\x00\xff\xd9";
        let r = inspect(data);
        assert_eq!(r.verdict, "clean", "internal FFD9 must be skipped");
        assert!(!codes(&r).contains(&"jpeg_trailing_data".to_string()));
    }

    #[test]
    fn jpeg_missing_eoi() {
        let r = inspect(b"\xff\xd8\xff\xe0 no end marker");
        assert!(codes(&r).contains(&"jpeg_no_eoi".to_string()));
    }

    // ---- gif ----
    // "GIF89a" · LSD 7 bytes (packed=0 -> no global color table) · trailer 0x3B
    const GIF_MIN: &[u8] = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b";

    #[test]
    fn gif_clean() {
        let r = inspect(GIF_MIN);
        assert_eq!(r.file_type, "gif");
        assert_eq!(r.verdict, "clean");
    }

    #[test]
    fn gif_gifar_trailing_pe() {
        let mut data = GIF_MIN.to_vec();
        data.extend_from_slice(b"MZ\x90\x00 fake exe");
        let r = inspect(&data);
        let c = codes(&r);
        assert!(c.contains(&"gif_trailing_data".to_string()));
        assert!(c.contains(&"embedded_pe".to_string()));
    }

    #[test]
    fn gif_trailing_count_correct_with_3b_in_payload() {
        // Appended payload that itself contains 0x3B. A last-0x3B search would
        // undercount the trailing bytes; the structural walk finds the real end.
        let mut data = GIF_MIN.to_vec();
        let payload = b"junk\x3bmore"; // 9 bytes, contains a 0x3B
        data.extend_from_slice(payload);
        let r = inspect(&data);
        assert!(codes(&r).contains(&"gif_trailing_data".to_string()));
        assert_eq!(r.metrics["trailing_bytes"], payload.len());
    }

    // ---- pdf ----
    #[test]
    fn pdf_malicious_openaction_js() {
        let data = b"%PDF-1.7\n<< /OpenAction 5 0 R >>\n<< /S /JavaScript /JS (app.launchURL(\"http://127.0.0.1:8080\")) >>\n%%EOF\n";
        let r = inspect(data);
        assert_eq!(r.file_type, "pdf");
        assert_eq!(r.verdict, "malicious");
        let c = codes(&r);
        assert!(c.contains(&"pdf_javascript".to_string()));
        assert!(c.contains(&"pdf_openaction".to_string()));
        assert!(c.contains(&"pdf_outbound_url".to_string()));
    }

    #[test]
    fn pdf_launch_and_embedded_and_trailing() {
        let data = b"%PDF-1.7\n<< /Launch >> /EmbeddedFile /AA\n%%EOF\nTRAILINGBYTES";
        let r = inspect(data);
        let c = codes(&r);
        assert_eq!(r.verdict, "malicious"); // launch is malicious
        assert!(c.contains(&"pdf_launch_action".to_string()));
        assert!(c.contains(&"pdf_embedded_file".to_string()));
        assert!(c.contains(&"pdf_additional_actions".to_string()));
        assert!(c.contains(&"pdf_trailing_data".to_string()));
    }

    #[test]
    fn pdf_benign() {
        let data = b"%PDF-1.7\n<< /Type /Catalog >>\n%%EOF\n";
        let r = inspect(data);
        assert_eq!(r.verdict, "clean");
    }

    #[test]
    fn pdf_hex_obfuscated_name_detected() {
        // /JavaScript written as /J#61vaScript (# hex escape) must still match.
        let data = b"%PDF-1.7\n<< /OpenAction 1 0 R >> << /S /J#61vaScript >>\n%%EOF\n";
        let r = inspect(data);
        assert_eq!(r.verdict, "malicious");
        assert!(codes(&r).contains(&"pdf_javascript".to_string()));
    }

    #[test]
    fn pdf_compressed_streams_caveat() {
        let data = b"%PDF-1.7\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream xx endstream\n%%EOF\n";
        let r = inspect(data);
        assert!(codes(&r).contains(&"pdf_compressed_streams".to_string()));
    }

    // ---- zip ----
    fn make_zip(entries: &[(&str, usize)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, size) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(&vec![0u8; *size]).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    fn make_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, content) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(content).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn zip_nested_detected_by_magic_not_name() {
        let inner = make_zip(&[("a.txt", 20)]); // a real archive
        let outer = make_zip_bytes(&[("payload.bin", &inner)]); // misleading name
        let r = inspect(&outer);
        assert!(
            codes(&r).contains(&"zip_nested_archive".to_string()),
            "nested archive must be caught by magic, not extension"
        );
    }

    #[test]
    fn zip_clean_small() {
        let z = make_zip(&[("a.txt", 50)]);
        let r = inspect(&z);
        assert_eq!(r.file_type, "zip");
        assert_eq!(r.verdict, "clean");
    }

    #[test]
    fn zip_bomb_ratio_detected() {
        // 2 MB of zeros deflates to a few hundred bytes -> ratio >> 100x
        let z = make_zip(&[("zeros.bin", 2_000_000)]);
        let r = inspect(&z);
        assert_eq!(r.verdict, "malicious");
        assert!(codes(&r).contains(&"zip_bomb_ratio".to_string()));
    }

    #[test]
    fn zip_nested_archive_flagged() {
        let z = make_zip(&[("inner.zip", 10), ("doc.jar", 10)]);
        let r = inspect(&z);
        assert!(codes(&r).contains(&"zip_nested_archive".to_string()));
    }

    #[test]
    fn zip_parse_error() {
        // valid magic but truncated/garbage central directory
        let r = inspect(b"PK\x03\x04\x00\x00garbage");
        assert_eq!(r.file_type, "zip");
        assert!(codes(&r).iter().any(|c| c.starts_with("zip_")));
    }
}
