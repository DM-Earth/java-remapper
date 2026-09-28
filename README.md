# java-remapper

Remap names in JVM bytecode (`.class` files) using Java deobfuscation mappings.
Class, field, and method names, along with descriptors, signatures, annotations,
inner classes, and local variables, are rewritten in place. Bytecode
instructions are left untouched—only the constant pool and class metadata are
updated.

## Library

Build an `Index` from a mapping source, then call `remap`:

```rust
use java_remapper::{Buffer, Context, Index, remap};

fn remap_class(index: &Index, src: &[u8]) -> Result<Vec<u8>, java_remapper::Error> {
    // Optional: record superclass/interface relationships so inherited members
    // can be resolved. Pass every class that belongs to the same unit.
    let mut cx = Context::new();
    cx.populate_inherency([src]);

    // A `Buffer` can be reused across calls.
    let mut buf = Buffer::new();
    let mut dst = Vec::new();
    remap(src, &mut dst, index, &mut buf, &cx)?;
    Ok(dst)
}
```

`Index` implements `mapping_serde::Deserialize`, so it can be built from any
format supported by the [mapping-serde] ecosystem (Tiny1/Tiny2, Enigma,
Proguard).

## CLI

The `java-remapper-cli` binary reads a class file or JAR from a path or stdin
and writes the remapped result to a path or stdout.

```
Usage: java-remapper-cli [OPTION]...

      --tiny2  FILE use the FILE as mapping file, in Tiny2 format
      --class  FILE input class file from FILE
      --jar    FILE input JAR file from FILE
  -o, --output FILE output into FILE
  -h, --help        give this help
```

## Feature flags

Hash maps used internally are selected by feature flags.

- `ahash` _(default)_: use `ahash`.
- `fx-hash`: use `rustc-hash` instead. Enable it with
  `default-features = false, features = ["fx-hash"]`.

If neither is enabled, the standard library hasher is used. If both are
enabled, `fx-hash` takes precedence.

[mapping-serde]: https://docs.rs/java-mapping-serde
