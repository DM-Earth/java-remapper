use std::{
    collections::HashSet,
    ffi::OsStr,
    io::{BufRead, BufReader, Read, Seek, Write},
    path::{Path, PathBuf},
};

use remapper::{Context, Index};
use zip::{DateTime, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::Error;

const META_INF: &str = "META-INF";

pub(crate) fn remap_jar<R, W>(
    src: &mut ZipArchive<R>,
    dst: &mut ZipWriter<W>,
    index: &Index,
    cx: &mut Context,
) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let mut parents = HashSet::new();
    let mut classes = Vec::new();
    collect_files(&mut *src, dst, index, &mut parents, &mut classes)?;
    cx.populate_inherency(classes.iter().map(|(_, cl, _)| cl));
    remap_classes(dst, &classes, index, cx)?;

    // finalize directories
    let mut meta_inf_over = false;
    for dir in &parents {
        if !meta_inf_over && dir == Path::new(META_INF) {
            meta_inf_over = true;
            continue;
        }
        dst.add_directory_from_path(
            dir,
            // unneeded for directories
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
    }

    Ok(())
}

fn collect_files<R, W>(
    src: &mut ZipArchive<R>,
    dst: &mut ZipWriter<W>,
    index: &Index,
    parents: &mut HashSet<PathBuf>,
    classes: &mut Vec<(PathBuf, Box<[u8]>, SimpleFileOptions)>,
) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let mut meta_inf_over = false;
    for id in 0..src.len() {
        let mut file = src.by_index(id)?;
        let Some(path) = file.enclosed_name() else {
            continue;
        };
        let parent = path.parent();

        if file.is_dir() {
            if !meta_inf_over && path == Path::new(META_INF) {
                meta_inf_over = true;
                dst.add_directory(file.name(), file.options())?;
                continue;
            }
        } else {
            let ext = path.extension().and_then(OsStr::to_str);

            if path.starts_with(Path::new(META_INF)) {
                match ext {
                    Some("SF" | "DSA" | "RSA" | "EC") => continue,
                    // typically MANIFEST.MF
                    Some("MF") => {
                        dst.start_file(
                            file.name(),
                            file.options()
                                .last_modified_time(DateTime::default_for_write()),
                        )?;
                        process_manifest(BufReader::new(&mut file), &mut *dst, index)?;
                        continue;
                    }
                    _ => (),
                }
            }

            if ext == Some("class")
                && let Some(name) = make_bin_name(&path)
            {
                let mut buf = Vec::with_capacity(file.size() as usize);
                file.read_to_end(&mut buf)?;
                let mapped_name = index.remap_class_name(&name);
                let path = PathBuf::from(format!("{mapped_name}.class"));
                if let Some(parent) = path.parent() {
                    for p in parent.ancestors() {
                        parents.insert(p.to_owned());
                    }
                }
                classes.push((path, buf.into_boxed_slice(), file.options()));
            } else {
                dst.raw_copy_file(file)?;
                if let Some(parent) = parent {
                    for p in parent.ancestors() {
                        parents.insert(p.to_owned());
                    }
                }
            }
        }
    }
    Ok(())
}

fn remap_classes<W>(
    dst: &mut ZipWriter<W>,
    classes: &[(PathBuf, Box<[u8]>, SimpleFileOptions)],
    index: &Index,
    cx: &Context,
) -> Result<(), Error>
where
    W: Write + Seek,
{
    let mut buf = Vec::new();
    let mut remap_buf = remapper::Buffer::new();
    for (path, src, opts) in classes {
        buf.clear();
        remapper::remap(src, &mut buf, index, &mut remap_buf, cx)?;
        dst.start_file_from_path(path, opts.last_modified_time(DateTime::default_for_write()))?;
        dst.write_all(&buf)?;
    }
    Ok(())
}

const MANIFEST_LINE_LIMIT: usize = 72;

struct ManifestReader<R> {
    src: R,
    pending: Option<String>,
}

impl<R: BufRead> ManifestReader<R> {
    fn new(src: R) -> Self {
        Self { src, pending: None }
    }

    fn read_physical(&mut self) -> Result<Option<String>, Error> {
        if let Some(line) = self.pending.take() {
            return Ok(Some(line));
        }
        let mut line = String::new();
        if self.src.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(Some(line))
    }

    fn read_logical(&mut self) -> Result<Option<String>, Error> {
        let Some(mut line) = self.read_physical()? else {
            return Ok(None);
        };
        while let Some(next) = self.read_physical()? {
            if let Some(continuation) = next.strip_prefix(' ') {
                line.push_str(continuation);
            } else {
                self.pending = Some(next);
                break;
            }
        }
        Ok(Some(line))
    }

    fn read_section(&mut self) -> Result<(bool, Vec<(String, String)>), Error> {
        let mut attrs = Vec::new();
        let mut saw_line = false;
        while let Some(line) = self.read_logical()? {
            saw_line = true;
            if line.is_empty() {
                break;
            }
            if let Some((key, val)) = split_attribute(&line) {
                attrs.push((key.to_owned(), val.to_owned()));
            }
        }
        Ok((saw_line, attrs))
    }
}

fn process_manifest<R, W>(src: R, mut dst: W, index: &Index) -> Result<(), Error>
where
    R: BufRead,
    W: Write,
{
    let mut read = ManifestReader::new(src);
    let mut wrote_any = false;

    loop {
        let (saw_line, attrs) = read.read_section()?;
        if !saw_line {
            break;
        }
        if attrs.is_empty() {
            continue;
        }

        let is_entry = attrs[0].0 == "Name";
        if !wrote_any && !is_entry {
            for (key, val) in &attrs {
                match key.as_str() {
                    "Signature-Version" => (),
                    "Main-Class" | "Premain-Class" | "Agent-Class" | "Launcher-Agent-Class" => {
                        write_manifest_attribute(&mut dst, key, &remap_class_reference(val, index))?
                    }
                    _ => write_manifest_attribute(&mut dst, key, val)?,
                }
            }
            wrote_any = true;
            continue;
        }

        // A section with nothing left once stale integrity metadata is
        // stripped carries no information, so omit it entirely.
        let retained: Vec<_> = attrs
            .iter()
            .skip(usize::from(is_entry))
            .filter(|(key, _)| !is_stale_integrity_attr(key))
            .collect();
        if retained.is_empty() {
            continue;
        }

        if wrote_any {
            dst.write_all(b"\r\n")?;
        }
        if is_entry {
            write_manifest_attribute(&mut dst, "Name", &remap_entry_name(&attrs[0].1, index))?;
        }
        for (key, val) in retained {
            write_manifest_attribute(&mut dst, key, val)?;
        }
        wrote_any = true;
    }

    Ok(())
}

fn split_attribute(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    if key.is_empty() || key.contains(char::is_whitespace) {
        return None;
    }
    // The specification separates the key and value with one space, which is
    // not part of the value; tolerate manifests that omit it.
    Some((key, value.strip_prefix(' ').unwrap_or(value)))
}

fn is_stale_integrity_attr(key: &str) -> bool {
    key.contains("Digest") || key == "Magic"
}

fn remap_class_reference(val: &str, index: &Index) -> String {
    let orig = val.replace('.', "/");
    index.remap_class_name(&orig).replace('/', ".")
}

fn remap_entry_name(val: &str, index: &Index) -> String {
    if let Some(name) = val
        .strip_suffix(".class")
        .and_then(|name| make_bin_name(Path::new(name)))
    {
        format!("{}.class", index.remap_class_name(&name))
    } else {
        val.to_owned()
    }
}

fn write_manifest_attribute<W: Write>(mut dst: W, key: &str, value: &str) -> Result<(), Error> {
    let line = format!("{key}: {value}");
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut first = true;
    while start < bytes.len() {
        let budget = if first {
            MANIFEST_LINE_LIMIT
        } else {
            MANIFEST_LINE_LIMIT - 1
        };
        let mut end = (start + budget).min(bytes.len());
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        debug_assert!(end > start, "line limit must exceed one code point");
        if !first {
            dst.write_all(b" ")?;
        }
        dst.write_all(&bytes[start..end])?;
        dst.write_all(b"\r\n")?;
        start = end;
        first = false;
    }
    Ok(())
}

fn make_bin_name(path: &Path) -> Option<String> {
    let mut iter = path.components().peekable();
    let mut out = String::with_capacity(path.as_os_str().len());
    while let Some(next) = iter.next() {
        match next {
            std::path::Component::CurDir => (),
            std::path::Component::Normal(s) => {
                let s = s.to_str()?;
                if iter.peek().is_some() {
                    out.push_str(s);
                    out.push('/');
                } else {
                    out.push_str(s.strip_suffix(".class").unwrap_or(s));
                }
            }
            _ => return None,
        }
    }
    Some(out)
}
