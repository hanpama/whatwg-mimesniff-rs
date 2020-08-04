// The algorithm uses at most sniffLen bytes to make its decision.
const SNIFF_LEN: usize = 512;

/**
detect_content_type implements the algorithm described
at https://mimesniff.spec.whatwg.org/ to determine the
Content-Type of the given data. It considers at most the
first 512 bytes of data. detect_content_type always returns
a valid MIME type: if it cannot determine a more specific one, it
returns "application/octet-stream".
*/
pub fn detect_content_type(data: &[u8]) -> &'static str {
    let mut data = data;
    if data.len() > SNIFF_LEN {
        data = &data[..SNIFF_LEN];
    }

    // Index of the first non-whitespace byte in data.
    let mut first_non_ws = 0;
    while first_non_ws < data.len() && is_ws(data[first_non_ws]) {
        first_non_ws += 1;
    }

    for sig in SNIFF_SIGNATURES {
        let ct = sig.sig_match(data, first_non_ws);
        match ct {
            Some(ct) => return ct,
            _ => {}
        }
    }

    return "application/octet-stream"; // fallback;
}

/**
isWS reports whether the provided byte is a whitespace byte (0xWS)
as defined in https://mimesniff.spec.whatwg.org/#terminology.
*/
fn is_ws(b: u8) -> bool {
    match b {
        b'\t' | b'\n' | b'\x0c' | b'\r' | b' ' => true,
        _ => false,
    }
}

/**
is_tt reports whether the provided byte is a tag-terminating byte (0xTT)
as defined in https://mimesniff.spec.whatwg.org/#terminology.
*/
fn is_tt(b: u8) -> bool {
    match b {
        b' ' | b'>' => true,
        _ => false,
    }
}

/**
 * Data matching the table in section 6.
 * */
const SNIFF_SIGNATURES: &[SniffSig] = &[
    SniffSig::HTML(HTMLSig(b"<!DOCTYPE HTML")),
    SniffSig::HTML(HTMLSig(b"<HTML")),
    SniffSig::HTML(HTMLSig(b"<HEAD")),
    SniffSig::HTML(HTMLSig(b"<SCRIPT")),
    SniffSig::HTML(HTMLSig(b"<IFRAME")),
    SniffSig::HTML(HTMLSig(b"<H1")),
    SniffSig::HTML(HTMLSig(b"<DIV")),
    SniffSig::HTML(HTMLSig(b"<FONT")),
    SniffSig::HTML(HTMLSig(b"<TABLE")),
    SniffSig::HTML(HTMLSig(b"<A")),
    SniffSig::HTML(HTMLSig(b"<STYLE")),
    SniffSig::HTML(HTMLSig(b"<TITLE")),
    SniffSig::HTML(HTMLSig(b"<B")),
    SniffSig::HTML(HTMLSig(b"<BODY")),
    SniffSig::HTML(HTMLSig(b"<BR")),
    SniffSig::HTML(HTMLSig(b"<P")),
    SniffSig::HTML(HTMLSig(b"<!--")),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"<?xml",
        skip_ws: true,
        ct: "text/xml; charset=utf-8",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"%PDF-",
        ct: "application/pdf",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"%!PS-Adobe-",
        ct: "application/postsript",
    }),
    // UTF BOMs.
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFE\xFF\x00\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-16be",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFF\xFE\x00\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-16le",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\x00",
        pat: b"\xEF\xBB\xBF\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-8",
    }),

    // Image types
    // For posterity, we originally returned "image/vnd.microsoft.icon" from
    // https://tools.ietf.org/html/draft-ietf-websec-mime-sniff-03#section-7
    // https://codereview.appspot.com/4746042
    // but that has since been replaced with "image/x-icon" in Section 6.2
    // of https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern
    SniffSig::Exact(ExactSig {
        sig: b"\x00\x00\x01\x00",
        ct: "image/x-icon",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"\x00\x00\x02\x00",
        ct: "image/x-icon",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"BM",
        ct: "image/bmp",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"GIF87a",
        ct: "image/gif",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"GIF89a",
        ct: "image/gif",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WEBPVP",
        skip_ws: false,
        ct: "image/webp",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"\x89PNG\x0D\x0A\x1A\x0A",
        ct: "image/png",
    }),
    SniffSig::Exact(ExactSig {
        sig: b"\xFF\xD8\xFF",
        ct: "image/jpeg",
    }),

    // Audio and Video types
    // Enforce the pattern match ordering as prescribed in
    // https://mimesniff.spec.whatwg.org/#matching-an-audio-or-video-type-pattern
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF",
        pat: b".snd",
        skip_ws: false,
        ct: "audio/basic",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"FORM\x00\x00\x00\x00AIFF",
        skip_ws: false,
        ct: "audio/aiff",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF",
        pat: b"ID3",
        skip_ws: false,
        ct: "audio/mpeg",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"OggS\x00",
        skip_ws: false,
        ct: "application/ogg",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"MThd\x00\x00\x00\x06",
        skip_ws: false,
        ct: "audio/midi",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00AVI ",
        skip_ws: false,
        ct: "video/avi",
    }),
    SniffSig::Masked(MaskedSig {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WAVE",
        skip_ws: false,
        ct: "audio/wave",
    }),
    // 6.2.0.2. video/mp4
    SniffSig::MP4(MP4Sig{}),
    // 6.2.0.3. video/webm
    SniffSig::Exact(ExactSig{
        sig: b"\x1A\x45\xDF\xA3",
        ct: "video/webm",
    }),

    // Font types
    SniffSig::Masked(MaskedSig{
        // // 34 NULL bytes followed by the string "LP"
        pat: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
        // 34 NULL bytes followed by \xF\xF
        mask: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
        skip_ws: false,
        ct: "application/vnd.ms-fontobject",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"\x00\x01\x00\x00",
        ct: "font/ttf",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"OTTO",
        ct: "font/otf",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"ttcf",
        ct: "font/collection",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"wOFF",
        ct: "font/woff",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"wOF2",
        ct: "font/woff2",
    }),

    // Archive types
    SniffSig::Exact(ExactSig{
        sig: b"\x1F\x8B\x08",
        ct: "application/x-gzip",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"PK\x03\x04",
        ct: "application/zip",
    }),
    // RAR's signatures are incorrectly defined by the MIME spec as per
	//    https://github.com/whatwg/mimesniff/issues/63
	// However, RAR Labs correctly defines it at:
	//    https://www.rarlab.com/technote.htm#rarsign
	// so we use the definition from RAR Labs.
    // TODO: do whatever the spec ends up doing.
    SniffSig::Exact(ExactSig{
        sig: b"Rar!\x1A\x07\x00", // RAR v1.5-v4.0
        ct: "application/x-rar-compressed",
    }),
    SniffSig::Exact(ExactSig{
        sig: b"Rar!\x1A\x07\x01\x00", // RAR v5+
        ct: "application/x-rar-compressed",
    }),

    SniffSig::Exact(ExactSig{
        sig: b"\x00\x61\x73\x6D",
        ct:  "application/wasm",
    }),

    SniffSig::Text(TextSig{}), // should be last
];

#[derive(Debug)]
enum SniffSig {
    Exact(ExactSig),
    Masked(MaskedSig),
    HTML(HTMLSig),
    MP4(MP4Sig),
    Text(TextSig),
}

impl SniffSig {
    fn sig_match(&self, b: &[u8], first_non_ws: usize) -> Option<&'static str> {
        match self {
            SniffSig::Exact(sig) => sig.sig_match(b, first_non_ws),
            SniffSig::Masked(sig) => sig.sig_match(b, first_non_ws),
            SniffSig::HTML(sig) => sig.sig_match(b, first_non_ws),
            SniffSig::MP4(sig) => sig.sig_match(b, first_non_ws),
            SniffSig::Text(sig) => sig.sig_match(b, first_non_ws),
        }
    }
}

#[derive(Debug)]
struct ExactSig {
    sig: &'static [u8],
    ct: &'static str,
}
impl ExactSig {
    fn sig_match(&self, b: &[u8], _first_non_ws: usize) -> Option<&'static str> {
        if b.starts_with(self.sig) {
            return Some(self.ct);
        }
        return None;
    }
}

#[derive(Debug)]
struct MaskedSig {
    mask: &'static [u8],
    pat: &'static [u8],
    skip_ws: bool,
    ct: &'static str,
}
impl MaskedSig {
    fn sig_match(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        // pattern matching algorithm section 6
        // https://mimesniff.spec.whatwg.org/#pattern-matching-algorithm
        let mut data = data;
        if self.skip_ws {
            data = &data[first_non_ws..];
        }
        if self.pat.len() != self.mask.len() {
            return None;
        }
        if data.len() < self.pat.len() {
            return None;
        }
        for i in 0..self.pat.len() {
            let masked_data = data[i] & self.mask[i];
            if masked_data != self.pat[i] {
                return None;
            }
        }
        return Some(self.ct);
    }
}

#[derive(Debug)]
struct HTMLSig(&'static [u8]);

impl HTMLSig {
    fn sig_match(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        let data = &data[first_non_ws..];

        let h = self.0;
        if data.len() < h.len() + 1 {
            return None;
        }
        for i in 0..h.len() {
            let mut db = data[i];
            let b = h[i];
            if b'A' <= b && b <= b'Z' {
                db &= 0xDF;
            }
            if b != db {
                return None;
            }
        }
        // Next byte must be a tag-terminating byte(0xTT).
        if !is_tt(data[h.len()]) {
            return None;
        }
        return Some("text/html; charset=utf-8");
    }
}

#[derive(Debug)]
struct MP4Sig {}
impl MP4Sig {
    fn sig_match(&self, data: &[u8], _first_non_ws: usize) -> Option<&'static str> {
        // https://mimesniff.spec.whatwg.org/#signature-for-mp4
        // c.f. section 6.2.1
        if data.len() < 12 {
            return None;
        }
        let box_size = decode_big_endian_utf32(&data[..4]) as usize;

        if data.len() < box_size || box_size % 4 != 0 {
            return None;
        }
        if !data[4..8].eq(b"ftyp") {
            return None;
        }
        let mut st = 8;
        while st < box_size {
            if st == 12 {
                // Ignores the four bytes that correspond to the version number of the "major brand".
                continue;
            }
            if data[st..st + 3].eq(b"mp4") {
                return Some("video/mp4");
            }
            st += 4;
        }

        return None;
    }
}

#[derive(Debug)]
struct TextSig {}
impl TextSig {
    fn sig_match(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        // c.f. section 5, step 4.
        let data = &data[first_non_ws..];
        for b in data {
            let b = *b;
            if b <= 0x08 || b == 0x0B || (0x0E <= b && b <= 0x1A) || (0x1C <= b && b <= 0x1F) {
                return None;
            }
        }
        return Some("text/plain; charset=utf-8");
    }
}

fn decode_big_endian_utf32(b: &[u8]) -> u32 {
    (b[3] as u32) | (b[2] as u32) << 8 | (b[1] as u32) << 16 | (b[0] as u32) << 24
}

#[cfg(test)]
mod tests {
    struct SniffTest(
        &'static str,  // desc
        &'static [u8], // data
        &'static str,  // content-type
    );
    impl SniffTest {
        fn desc(&self) -> &'static str {
            self.0
        }
        fn data(&self) -> &'static [u8] {
            self.1
        }
        fn content_type(&self) -> &'static str {
            self.2
        }
    }

    static SNIFF_TESTS: &[SniffTest] = &[
        // Some nonsense.
        SniffTest("Empty", b"", "text/plain; charset=utf-8"),
        SniffTest("Binary", &[1, 2, 3], "application/octet-stream"),

        SniffTest("HTML document #1", b"<HtMl><bOdY>blah blah blah</body></html>", "text/html; charset=utf-8"),
        SniffTest("HTML document #2", b"<HTML></HTML>", "text/html; charset=utf-8"),
        SniffTest("HTML document #3 (leading whitespace)", b"   <!DOCTYPE HTML>...", "text/html; charset=utf-8"),
        SniffTest("HTML document #4 (leading CRLF)", b"\r\n<html>...", "text/html; charset=utf-8"),

        SniffTest("Plain text", "This is not HTML. It has ☃ though.".as_bytes(), "text/plain; charset=utf-8"),
        // This is not HTML. It has ☃ though.

        SniffTest("XML", b"\n<?xml!", "text/xml; charset=utf-8"),

        // Image types.
        SniffTest("Windows icon", b"\x00\x00\x01\x00", "image/x-icon"),
        SniffTest("Windows cursor", b"\x00\x00\x02\x00", "image/x-icon"),
        SniffTest("BMP image", b"BM...", "image/bmp"),
        SniffTest("GIF 87a", b"GIF87a", "image/gif"),
        SniffTest("GIF 89a", b"GIF89a...", "image/gif"),
        SniffTest("WEBP image", b"RIFF\x00\x00\x00\x00WEBPVP", "image/webp"),
        SniffTest("PNG image", b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
        SniffTest("JPEG image", b"\xFF\xD8\xFF", "image/jpeg"),

	    // Audio types.
        SniffTest("MIDI audio", b"MThd\x00\x00\x00\x06\x00\x01", "audio/midi"),
        SniffTest("MP3 audio/MPEG audio", b"ID3\x03\x00\x00\x00\x00\x0f", "audio/mpeg"),
        SniffTest("WAV audio #1", b"RIFFb\xb8\x00\x00WAVEfmt \x12\x00\x00\x00\x06", "audio/wave"),
        SniffTest("WAV audio #2", b"RIFF,\x00\x00\x00WAVEfmt \x12\x00\x00\x00\x06", "audio/wave"),
        SniffTest("AIFF audio #1", b"FORM\x00\x00\x00\x00AIFFCOMM\x00\x00\x00\x12\x00\x01\x00\x00\x57\x55\x00\x10\x40\x0d\xf3\x34", "audio/aiff"),

        SniffTest("OGG audio", b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x7e\x46\x00\x00\x00\x00\x00\x00\x1f\xf6\xb4\xfc\x01\x1e\x01\x76\x6f\x72", "application/ogg"),
        SniffTest("Must not match OGG", b"owow\x00", "application/octet-stream"),
        SniffTest("Must not match OGG", b"oooS\x00", "application/octet-stream"),
        SniffTest("Must not match OGG", b"oggS\x00", "application/octet-stream"),

	    // Video types.
        SniffTest("MP4 video", b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat", "video/mp4"),
	    SniffTest("AVI video #1", "RIFF,O\n\x00AVI LISTÀ".as_bytes(), "video/avi"),
        SniffTest("AVI video #2", "RIFF,\n\x00\x00AVI LISTÀ".as_bytes(), "video/avi"),

        // Font types.
        // ("MS.FontObject", b"\x00\x00")),
        SniffTest("TTF sample  I", b"\x00\x01\x00\x00\x00\x17\x01\x00\x00\x04\x01\x60\x4f", "font/ttf"),
	    SniffTest("TTF sample II", b"\x00\x01\x00\x00\x00\x0e\x00\x80\x00\x03\x00\x60\x46", "font/ttf"),

        SniffTest("OTTO sample  I", b"\x4f\x54\x54\x4f\x00\x0e\x00\x80\x00\x03\x00\x60\x42\x41\x53\x45", "font/otf"),

        SniffTest("woff sample  I", b"\x77\x4f\x46\x46\x00\x01\x00\x00\x00\x00\x30\x54\x00\x0d\x00\x00", "font/woff"),
        SniffTest("woff2 sample", b"\x77\x4f\x46\x32\x00\x01\x00\x00\x00", "font/woff2"),
        SniffTest("wasm sample", b"\x00\x61\x73\x6d\x01\x00", "application/wasm"),

        // Archive types
        SniffTest("RAR v1.5-v4.0", b"Rar!\x1A\x07\x00", "application/x-rar-compressed"),
        SniffTest("RAR v5+", b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
        SniffTest("Incorrect RAR v1.5-v4.0", b"Rar \x1A\x07\x00", "application/octet-stream"),
        SniffTest("Incorrect RAR v5+", b"Rar \x1A\x07\x01\x00", "application/octet-stream"),
    ];

    #[test]
    fn test_detect_content_type() {
        use super::detect_content_type;

        for tt in SNIFF_TESTS {
            let ct = detect_content_type(tt.data());
            if !ct.eq(tt.content_type()) {
                panic!(format!(
                    "{}: detect_content_type = {}, want {}",
                    tt.desc(),
                    ct,
                    tt.content_type(),
                ));
            }
        }
    }
}
