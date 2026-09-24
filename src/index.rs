use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    marker::PhantomData,
    num::NonZero,
    pin::Pin,
};

use classfile::ConstantPoolEntry;
use mapping_serde::{Deserialize, Deserializer, de::Visitor};
use simd_cesu8::mutf8;
use smol_str::SmolStr;

use crate::RandomState;

/// Naming mapping.
#[derive(Debug)]
pub struct Index {
    pub(crate) classes: HashMap<SmolStr, Class, RandomState>,
    dyn_resolver: DynResolver,
}

/// Auxiliary information about the classes being remapped.
#[derive(Default, Debug, Clone)]
pub struct Context {
    pub(crate) inherency: HashMap<SmolStr, Vec<SmolStr>, RandomState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Class {
    /// Mapped name.
    pub(crate) name: Option<SmolStr>,
    pub(crate) methods: HashMap<DescKey, Method, RandomState>,
    /// Mapped field names.
    pub(crate) fields: HashMap<SmolStr, SmolStr, RandomState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DescKey {
    /// Original name.
    pub(crate) name: SmolStr,
    /// Original descriptor.
    pub(crate) desc: SmolStr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Method {
    /// Mapped name.
    pub(crate) name: Option<SmolStr>,
    /// Mapped local variable array.
    pub(crate) lv: Vec<Option<SmolStr>>,
}

impl Index {
    /// Builds an index from a flat deserializer.
    #[allow(clippy::missing_errors_doc)]
    pub fn from_deserializer<'de, D>(mut deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Checker<D>(PhantomData<D>);
        impl<'de, D: Deserializer<'de>> Checker<D> {
            const CHECK: () = assert!(
                D::FLAT_CLASSES,
                "index should be built from a flat deserializer"
            );
        }
        let _: () = Checker::<D>::CHECK;

        let mut index = Self {
            classes: HashMap::default(),
            dyn_resolver: Default::default(),
        };
        while deserializer
            .deserialize_class(RootVisitor(&mut index))?
            .is_some()
        {}

        Ok(index)
    }

    pub(crate) fn remap_class_name_tracked<'a>(
        &'a self,
        src: &'a str,
        changed: &mut bool,
    ) -> &'a str {
        self.classes
            .get(src)
            .and_then(|c| c.name.as_deref())
            .or_else(|| self.dyn_resolver.resolve(src, self))
            .inspect(|_| *changed = true)
            .unwrap_or(src)
    }

    /// Remaps the given class name `src` to the desired value.
    pub fn remap_class_name<'a>(&'a self, src: &'a str) -> &'a str {
        self.remap_class_name_tracked(src, &mut false)
    }

    fn remap_field_name_inner<'s, 'a>(
        &'s self,
        class: &'a str,
        orig: &str,
        protection: &mut HashSet<&'a str>,
        cx: &Context,
    ) -> Option<&'s SmolStr> {
        if !protection.insert(class) {
            return None;
        }
        self.classes
            .get(class)
            .and_then(|cl| cl.fields.get(orig))
            .or_else(|| {
                for cl in cx.inherency.get(class)? {
                    if let Some(dst) = self.remap_field_name(cl, orig, cx) {
                        return Some(dst);
                    }
                }
                None
            })
    }

    pub(crate) fn remap_field_name<'s>(
        &'s self,
        class: &str,
        orig: &str,
        cx: &Context,
    ) -> Option<&'s SmolStr> {
        let mut protection = HashSet::with_capacity(4);
        self.remap_field_name_inner(class, orig, &mut protection, cx)
    }

    fn remap_method_name_inner<'s, 'a>(
        &'s self,
        class: &'a str,
        orig: &DescKey,
        protection: &mut HashSet<&'a str>,
        cx: &Context,
    ) -> Option<&'s Method> {
        if !protection.insert(class) {
            return None;
        }
        self.classes
            .get(class)
            .and_then(|cl| cl.methods.get(orig))
            .or_else(|| {
                for cl in cx.inherency.get(class)? {
                    if let Some(dst) = self.remap_method_name(cl, orig, cx) {
                        return Some(dst);
                    }
                }
                None
            })
    }

    pub(crate) fn remap_method_name<'s>(
        &'s self,
        class: &str,
        orig: &DescKey,
        cx: &Context,
    ) -> Option<&'s Method> {
        let mut protection = HashSet::with_capacity(4);
        self.remap_method_name_inner(class, orig, &mut protection, cx)
    }
}

impl Clone for Index {
    fn clone(&self) -> Self {
        Self {
            classes: self.classes.clone(),
            dyn_resolver: Default::default(),
        }
    }
}

impl Context {
    /// Creates an empty remapper context.
    pub fn new() -> Self {
        Self::default()
    }

    fn populate_inherency_inner(
        &mut self,
        buf: &[u8],
        cp_cap: &mut usize,
    ) -> Result<(), classfile::Error> {
        let reader = classfile::Reader::new(buf);
        let (_, mut reader) = reader.header()?;
        let mut cp: Vec<Option<ConstantPoolEntry<'_>>> = Vec::with_capacity(*cp_cap);
        while let Some((idx, entry)) = reader.next().transpose()? {
            cp.resize(idx.get() as usize, None);
            cp.push(Some(entry));
        }
        *cp_cap = (*cp_cap).max(cp.len());
        let reader = reader.finish()?;
        let (metadata, mut reader) = reader.metadata()?;
        let Some(this) = class_name_from_cp(&cp, metadata.this_class) else {
            return Ok(());
        };
        let mut parents = Vec::new();
        if let Some(p) = metadata.super_class
            && let Some(p) = class_name_from_cp(&cp, p)
        {
            parents.push(p);
        }
        while let Some(p) = reader.next().transpose()? {
            if let Some(p) = class_name_from_cp(&cp, p) {
                parents.push(p);
            }
        }
        if !parents.is_empty() {
            self.inherency.insert(this, parents);
        }
        Ok(())
    }

    /// Populate inherency information from given class files.
    pub fn populate_inherency<I, B>(&mut self, iter: I)
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut cp_cap = 0;
        for buf in iter {
            let _ = self.populate_inherency_inner(buf.as_ref(), &mut cp_cap);
        }
    }
}

#[derive(Debug, Default)]
struct DynResolver {
    // SAFETY: do not remove entries
    map: scc::HashMap<SmolStr, Pin<Box<str>>, RandomState>,
}

impl DynResolver {
    fn resolve<'a>(&'a self, req: &str, index: &Index) -> Option<&'a str> {
        // avoid unneeded requests
        for c in req.chars().rev() {
            match c {
                '0'..='9' => (),
                '$' => break,
                _ => return None,
            }
        }

        if let Some(target) = self.map.get_sync(req) {
            Some(unsafe { &*std::ptr::from_ref(&**target) })
        } else if let Some((base, suffix)) = req.rsplit_once('$') {
            let mut changed = false;
            let base_mapped = index.remap_class_name_tracked(base, &mut changed);
            if !changed {
                return None;
            }
            let mapped = Pin::new(format!("{}${}", base_mapped, suffix).into_boxed_str());
            let result = unsafe { &*std::ptr::from_ref(&*mapped) };
            drop(self.map.insert_sync(req.into(), mapped));
            Some(result)
        } else {
            None
        }
    }
}

fn class_name_from_cp(cp: &[Option<ConstantPoolEntry<'_>>], idx: NonZero<u16>) -> Option<SmolStr> {
    class_from_cp(cp, idx).and_then(|idx| name_from_cp(cp, idx))
}

fn class_from_cp(cp: &[Option<ConstantPoolEntry<'_>>], idx: NonZero<u16>) -> Option<NonZero<u16>> {
    if let Some(Some(ConstantPoolEntry::Class(cl))) = cp.get(idx.get() as usize) {
        Some(*cl)
    } else {
        None
    }
}

fn name_from_cp(cp: &[Option<ConstantPoolEntry<'_>>], idx: NonZero<u16>) -> Option<SmolStr> {
    if let Some(Some(ConstantPoolEntry::Utf8(enc))) = cp.get(idx.get() as usize)
        && let Ok(decoded) = mutf8::decode(enc.0)
    {
        Some(decoded.into())
    } else {
        None
    }
}

impl<'de> Deserialize<'de> for Index {
    const IS_CONDITIONAL: bool = false;

    fn deserialize<D>(deserializer: D) -> Result<Option<Self>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_deserializer(deserializer).map(Some)
    }
}

struct RootVisitor<'a>(&'a mut Index);

impl<'de> Visitor<'de> for RootVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "classes")
    }

    fn visit_comment<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: mapping_serde::de::Error,
    {
        Ok(())
    }

    fn visit_class<'b, A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: mapping_serde::de::ClassAccess<'de, 'b>,
    {
        let entry = self
            .0
            .classes
            .entry(access.src().into())
            .or_insert_with(|| Class {
                name: access.dst().next().map(Into::into),
                methods: HashMap::default(),
                fields: HashMap::default(),
            });
        let mut content = access.content();
        while content.deserialize_any(ClassVisitor(entry))?.is_some() {}
        Ok(())
    }
}

struct ClassVisitor<'a>(&'a mut Class);

impl<'de> Visitor<'de> for ClassVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "fields and methods")
    }

    fn visit_comment<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: mapping_serde::de::Error,
    {
        Ok(())
    }

    fn visit_field<'b, A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: mapping_serde::de::FieldAccess<'de, 'b>,
    {
        if let Some(dst) = access.dst().next() {
            self.0.fields.insert(access.src().into(), dst.into());
        }
        Ok(())
    }

    fn visit_method<'b, A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: mapping_serde::de::MethodAccess<'de, 'b>,
    {
        let entry = self
            .0
            .methods
            .entry(DescKey {
                name: access.src().into(),
                desc: access.desc().unwrap_or_default().into(),
            })
            .or_insert_with(|| Method {
                name: access.dst().next().map(Into::into),
                lv: Vec::new(),
            });
        let mut content = access.content();
        while content.deserialize_any(MethodVisitor(entry))?.is_some() {}
        Ok(())
    }
}

struct MethodVisitor<'a>(&'a mut Method);

impl<'de> Visitor<'de> for MethodVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "method args and vars")
    }

    fn visit_comment<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: mapping_serde::de::Error,
    {
        Ok(())
    }

    fn visit_method_arg<'b, A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: mapping_serde::de::MethodArgAccess<'de, 'b>,
    {
        if let Some(i) = access.lv_index()
            && let Some(dst) = access.dst().and_then(|mut it| it.next())
        {
            self.0.lv.resize(i + 1, None);
            self.0.lv[i] = Some(dst.into());
        }
        Ok(())
    }

    fn visit_method_var<'b, A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: mapping_serde::de::MethodVarAccess<'de, 'b>,
    {
        if let Some(i) = access.lv_index()
            && let Some(dst) = access.dst().and_then(|mut it| it.next())
        {
            self.0.lv.resize(i + 1, None);
            self.0.lv[i] = Some(dst.into());
        }
        Ok(())
    }
}
