use std::{
    collections::HashSet,
    ffi::OsStr,
    io::{BufRead, BufReader, Read, Seek, Write},
    path::{Path, PathBuf},
};

use remapper::{Context, Index};
use smol_str::ToSmolStr as _;
use zip::{DateTime, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::Error;

const META_INF: &str = "META-INF";

pub(crate) fn remap_jar<R, W>(
    mut src: ZipArchive<R>,
    mut dst: &mut ZipWriter<W>,
    index: &Index,
    cx: &mut Context,
) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let mut parents = HashSet::new();
    // (raw name, classfile)
    let mut classes: Vec<(String, Box<[u8]>, SimpleFileOptions)> = Vec::new();

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
                        process_manifest(BufReader::new(&mut file), &mut dst, index)?;
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
                classes.push((name, buf.into_boxed_slice(), file.options()));
            } else {
                dst.start_file(file.name(), file.options())?;
                std::io::copy(&mut file, &mut dst)?;
                if let Some(parent) = parent {
                    for p in parent.ancestors() {
                        parents.insert(p.to_owned());
                    }
                }
            }
        }
    }

    cx.populate_inherency(classes.iter().map(|(_, cl, _)| cl));

    let mut wbuf = Vec::new();
    let mut rbuf = remapper::Buffer::new();
    for (orig, src, opts) in &classes {
        wbuf.clear();
        let mapped_name = index.remap_class_name(orig);
        let path = PathBuf::from(format!("{mapped_name}.class"));
        if let Some(parent) = path.parent() {
            for p in parent.ancestors() {
                parents.insert(p.to_owned());
            }
        }
        remapper::remap(src, &mut wbuf, index, &mut rbuf, &*cx)?;
        dst.start_file_from_path(
            &path,
            opts.last_modified_time(DateTime::default_for_write()),
        )?;
        dst.write_all(&wbuf)?;
    }

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

fn process_manifest<R, W>(src: R, mut dst: W, index: &Index) -> Result<(), Error>
where
    R: BufRead,
    W: Write,
{
    let mut read = src.lines();
    while let Some(line) = read.next().transpose()?
        // truncate at empty lines
        && let Some((key, val)) = line.split_once(": ")
    {
        match key {
            "Main-Class" | "Launcher-Agent-Class" => {
                let orig = val.replace('.', "/");
                let remapped = index.remap_class_name(&orig).replace('/', ".");
                writeln!(dst, "{key}: {remapped}")?
            }
            // ommitted
            "Signature-Version" => (),
            _ => writeln!(dst, "{key}: {val}")?,
        }
    }
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let name = if let Some(line) = read.next().transpose()?
            && let Some(("Name", val)) = line.split_once(": ")
        {
            if let Some(cl) = val
                .strip_suffix(".class")
                .and_then(|cl| make_bin_name(Path::new(cl)))
            {
                let remapped = index.remap_class_name(&cl);
                format!("{}.class", remapped)
            } else {
                val.to_owned()
            }
        } else {
            break;
        };
        while let Some(line) = read.next().transpose()?
            && let Some((key, val)) = line.split_once(": ")
        {
            if !(key.contains("Digest") || matches!(key, "Magic")) {
                buf.push((key.to_smolstr(), val.to_owned()))
            }
        }
        if !buf.is_empty() {
            writeln!(dst, "\nName: {name}")?;
            for (key, val) in &buf {
                writeln!(dst, "{key}: {val}")?
            }
        }
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
