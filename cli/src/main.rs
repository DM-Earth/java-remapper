//! CLI for bytecode reampping.

use std::{
    fmt::Display,
    io::{BufReader, Read as _, Write as _, stdin, stdout},
    path::PathBuf,
};

use remapper::{Context, Index};
use zip::{ZipArchive, ZipWriter};

mod jar;

#[non_exhaustive]
enum MappingFormat {
    Tiny2,
}

struct Args {
    fmt: MappingFormat,
    mapping_path: PathBuf,
    input: Input,
    output: Option<PathBuf>,
}

enum Input {
    Class(Option<PathBuf>),
    Jar(PathBuf),
}

#[derive(Debug)]
enum Error {
    MissingMapping,
    MissingOutput,
    NonUtf8,
    MissingInput,
    StdinUnsupported,
    UnknownArg(String),
    Io(std::io::Error),
    Bytecode(remapper::Error),
    Zip(zip::result::ZipError),

    MappingParse(Box<dyn std::error::Error>),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MissingMapping => write!(f, "missing mapping file"),
            Error::MissingOutput => write!(f, "missing output file"),
            Error::UnknownArg(arg) => write!(f, "unknown argument: {arg}"),
            Error::Io(error) => write!(f, "I/O error: {error}"),
            Error::Bytecode(error) => write!(f, "bytecode parsing error: {error}"),
            Error::NonUtf8 => write!(f, "not an UTF-8 argument"),
            Error::MappingParse(error) => write!(f, "mapping parsing error: {error}"),
            Error::Zip(err) => write!(f, "zip manipulation error: {err}"),
            Error::MissingInput => write!(f, "missing input file"),
            Error::StdinUnsupported => write!(f, "stdin is not supported for the requested format"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            Error::Bytecode(error) => Some(error),
            Error::MappingParse(error) => Some(&**error),
            Error::Zip(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<remapper::Error> for Error {
    fn from(value: remapper::Error) -> Self {
        Self::Bytecode(value)
    }
}

impl From<zip::result::ZipError> for Error {
    fn from(value: zip::result::ZipError) -> Self {
        Self::Zip(value)
    }
}

#[cold]
fn print_help() {
    const MSG: &str = include_str!("../help.txt");
    println!("{}", MSG);
    std::process::exit(0)
}

fn parse_args(raw: impl IntoIterator<Item = impl Into<std::ffi::OsString>>) -> Result<Args, Error> {
    let mut fmt = None;
    let mut mapping_path = None;
    let mut output = None;
    let mut input = Input::Class(None);

    let raw = clap_lex::RawArgs::new(raw);
    let mut cursor = raw.cursor();
    raw.next(&mut cursor);
    while let Some(arg) = raw.next(&mut cursor) {
        if let Some((long, _)) = arg.to_long() {
            let long = long.map_err(|_| Error::NonUtf8)?;
            match long {
                "tiny2" => {
                    fmt = Some(MappingFormat::Tiny2);
                    let val = raw
                        .next(&mut cursor)
                        .map(|p| p.to_value_os())
                        .ok_or(Error::MissingMapping)?;
                    mapping_path = Some(val.into());
                }
                "class" => {
                    let val = raw.next(&mut cursor).ok_or(Error::MissingInput)?;
                    input = if val.is_stdio() {
                        Input::Class(None)
                    } else {
                        Input::Class(Some(val.to_value_os().into()))
                    }
                }
                "jar" => {
                    let val = raw.next(&mut cursor).ok_or(Error::MissingInput)?;
                    input = if val.is_stdio() {
                        return Err(Error::StdinUnsupported);
                    } else {
                        Input::Jar(val.to_value_os().into())
                    }
                }
                "output" => {
                    let val = raw.next(&mut cursor).ok_or(Error::MissingOutput)?;
                    if !val.is_stdio() {
                        output = Some(val.to_value_os().into());
                    }
                }
                "help" => print_help(),
                myth => return Err(Error::UnknownArg(format!("--{myth}"))),
            }
        } else if let Some(fs) = arg.to_short() {
            for flag in fs {
                let flag = flag.map_err(|_| Error::NonUtf8)?;
                match flag {
                    'h' => print_help(),
                    'o' => {
                        let val = raw.next(&mut cursor).ok_or(Error::MissingOutput)?;
                        if !val.is_stdio() {
                            output = Some(val.to_value_os().into());
                        }
                    }
                    myth => return Err(Error::UnknownArg(format!("-{myth}"))),
                }
            }
        }
    }

    Ok(Args {
        fmt: fmt.ok_or(Error::MissingMapping)?,
        mapping_path: mapping_path.ok_or(Error::MissingMapping)?,
        output,
        input,
    })
}

fn main() -> Result<(), Error> {
    let args = parse_args(std::env::args_os())?;
    let index: Index = match args.fmt {
        MappingFormat::Tiny2 => mapping_serde_tiny2::from_reader(BufReader::new(
            std::fs::File::open(&args.mapping_path)?,
        ))
        .map_err(|err| Error::MappingParse(Box::new(err)))?
        .unwrap(),
    };

    let mut cx = Context::new();
    match &args.input {
        Input::Class(path) => {
            let mut src = Vec::new();
            match path {
                Some(path) => std::fs::File::open(path)?.read_to_end(&mut src),
                None => stdin().read_to_end(&mut src),
            }?;
            cx.populate_inherency([&src]);
            let mut dst = Vec::with_capacity(src.len());
            let mut buf = remapper::Buffer::new();
            remapper::remap(&src, &mut dst, &index, &mut buf, &cx)?;
            if let Some(output) = args.output {
                std::fs::write(output, dst)?;
            } else {
                let mut stdout = stdout();
                stdout.write_all(&dst)?;
            }
        }
        Input::Jar(path) => {
            let file = std::fs::File::open(path)?;
            let archive = ZipArchive::new(file)?;
            if let Some(out) = &args.output {
                let mut dst = ZipWriter::new(std::fs::File::create(out)?);
                dst.set_raw_comment(archive.comment().into())?;
                jar::remap_jar(archive, &mut dst, &index, &mut cx)?;
                dst.finish()?;
            } else {
                let mut dst = ZipWriter::new_stream(stdout());
                dst.set_raw_comment(archive.comment().into())?;
                jar::remap_jar(archive, &mut dst, &index, &mut cx)?;
                dst.finish()?;
            }
        }
    }
    Ok(())
}
