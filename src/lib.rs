//! Java classfile remapper library.

use std::{borrow::Cow, collections::HashMap, num::NonZero, sync::OnceLock};

use classfile::{
    Attribute, ConstantPoolEntry, FieldHeader, MethodHeader, ModifiedUtf8, Reader, Writer,
    attributes::{
        self, Annotation, CodeReader, CodeWriter, ConstantPoolIndex, ElementValue, EnclosingMethod,
        InnerClassesReader, InnerClassesWriter, LocalVariableTableReader, LocalVariableTableWriter,
        LocalVariableTypeTableReader, LocalVariableTypeTableWriter, ParamAnnotations, RecordReader,
        RuntimeInvisibleAnnotationsReader, RuntimeInvisibleAnnotationsWriter,
        RuntimeInvisibleParamAnnotationsReader, RuntimeInvisibleParamAnnotationsWriter,
        RuntimeInvisibleTypeAnnotationsReader, RuntimeInvisibleTypeAnnotationsWriter,
        RuntimeVisibleAnnotationsReader, RuntimeVisibleAnnotationsWriter,
        RuntimeVisibleParamAnnotationsReader, RuntimeVisibleParamAnnotationsWriter,
        RuntimeVisibleTypeAnnotationsReader, RuntimeVisibleTypeAnnotationsWriter, TypedAnnotation,
    },
};
use java_bin_name::{
    ClassSignature, FieldType, MethodDescriptor, MethodSignature, ReducedClassTypeSignature,
    TypeArgument, TypeParameter, TypeSignature,
};
use simd_cesu8::mutf8;
use smol_str::{SmolStr, ToSmolStr as _};

use crate::index::{DescKey, Method};

mod index;

pub use index::{Context, Index};

pub use classfile::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AttributeKind {
    Code,
    InnerClasses,
    EnclosingMethod,
    Signature,
    LocalVariableTable,
    LocalVariableTypeTable,
    RuntimeVisibleAnnotations,
    RuntimeInvisibleAnnotations,
    RuntimeVisibleParameterAnnotations,
    RuntimeInvisibleParameterAnnotations,
    RuntimeVisibleTypeAnnotations,
    RuntimeInvisibleTypeAnnotations,
    AnnotationDefault,
    Record,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
enum RemapKind {
    #[default]
    None,
    /// Name of a class.
    ClassName,
    /// Simple name of an inner class.
    InnerClassName,
    /// Name of a field.
    FieldName,
    /// Type (descriptor) of a field, or anything else holding a field descriptor.
    FieldType,
    /// Name of a method.
    MethodName,
    /// Descriptor of a method.
    MethodDescriptor,
    /// Name of a local variable.
    LocalVarName,
    /// Signature of a field.
    FieldSignature,
    /// Signature of a method.
    MethodSignature,
    /// Signature of a class.
    ClassSignature,
}

#[derive(Debug, Clone, Default)]
struct ConstState {
    /// Matching attribute. This is only useful for the `Utf8` entry pointed by an attribute.
    matched_attr: Option<AttributeKind>,
    /// Whether the entry is modified.
    modified: bool,

    remaps: HashMap<SmolStr, NonZero<u16>>,
    kinds: HashMap<RemapKind, Option<NonZero<u16>>>,
}

fn remap_state_raw(
    remaps: &mut HashMap<SmolStr, NonZero<u16>>,
    appends: &mut ConstPoolAppends,
    remapped: SmolStr,
) -> NonZero<u16> {
    match remaps.entry(remapped.clone()) {
        std::collections::hash_map::Entry::Occupied(occupied) => *occupied.get(),
        std::collections::hash_map::Entry::Vacant(vacant) => {
            let idx = appends
                .start
                .checked_add(appends.entries.len() as u16)
                .expect("constant pool overflowed");
            appends.entries.push(remapped);
            vacant.insert(idx);
            idx
        }
    }
}

impl ConstState {
    fn remap<F>(
        &mut self,
        kind: RemapKind,
        appends: &mut ConstPoolAppends,
        f: F,
    ) -> Option<NonZero<u16>>
    where
        F: FnOnce() -> Option<SmolStr>,
    {
        if matches!(
            kind,
            RemapKind::None
            // names below can be varied
                | RemapKind::InnerClassName
                | RemapKind::FieldName
                | RemapKind::MethodName
                | RemapKind::LocalVarName
        ) {
            return f().map(|remapped| remap_state_raw(&mut self.remaps, appends, remapped));
        }
        match self.kinds.entry(kind) {
            std::collections::hash_map::Entry::Occupied(ke) => *ke.get(),
            std::collections::hash_map::Entry::Vacant(ke) => {
                let idx = f().map(|remapped| remap_state_raw(&mut self.remaps, appends, remapped));
                ke.insert(idx);
                idx
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CowAttribute<'a> {
    name_index: NonZero<u16>,
    info: Cow<'a, [u8]>,
}

impl CowAttribute<'_> {
    fn as_attr(&self) -> Attribute<'_> {
        Attribute {
            name_index: self.name_index,
            info: &self.info,
        }
    }
}

impl<'a> From<Attribute<'a>> for CowAttribute<'a> {
    fn from(value: Attribute<'a>) -> Self {
        Self {
            name_index: value.name_index,
            info: Cow::Borrowed(value.info),
        }
    }
}

/// Auxiliary buffer for a remapper.
#[derive(Debug)]
pub struct Buffer<'a> {
    attribute_matcher: &'static HashMap<Box<[u8]>, AttributeKind>,

    classes: Vec<NonZero<u16>>,
    field_refs: Vec<(NonZero<u16>, NonZero<u16>)>,
    method_refs: Vec<(NonZero<u16>, NonZero<u16>)>,

    // dyns
    dynamic_fields: Vec<NonZero<u16>>,
    dynamic_methods: Vec<NonZero<u16>>,
    method_types: Vec<NonZero<u16>>,

    // stores
    const_pool: ConstPoolBuffer<'a>,
    interfaces: Vec<NonZero<u16>>,
    fields: Vec<(FieldHeader, Vec<CowAttribute<'a>>)>,
    methods: Vec<(MethodHeader, Vec<CowAttribute<'a>>)>,
    attrs: Vec<CowAttribute<'a>>,
}

/// Buffer of a constant pool.
/// States and entries are indexed through their raw id, which is retrived directly from the class file.
#[derive(Debug)]
struct ConstPoolBuffer<'a> {
    states: Vec<ConstState>,
    entries: Vec<Option<ConstantPoolEntry<'a>>>,
    appends: ConstPoolAppends,
}

#[derive(Debug)]
struct ConstPoolAppends {
    start: NonZero<u16>,
    entries: Vec<SmolStr>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum AttrContext<'a> {
    Class(Option<&'a str>),
    Field,
    Method(Option<&'a Method>),
    RecordComponent,
    #[default]
    None,
}

impl Buffer<'_> {
    /// Creates a new buffer.
    #[allow(clippy::missing_panics_doc)]
    pub fn new() -> Self {
        static ATTRIBUTE_MATCHER_STATIC: OnceLock<HashMap<Box<[u8]>, AttributeKind>> =
            OnceLock::new();

        Self {
            attribute_matcher: ATTRIBUTE_MATCHER_STATIC.get_or_init(|| {
                HashMap::from_iter(
                    [
                        (mutf8::encode(attributes::NAME_CODE), AttributeKind::Code),
                        (
                            mutf8::encode(attributes::NAME_INNER_CLASSES),
                            AttributeKind::InnerClasses,
                        ),
                        (
                            mutf8::encode(attributes::NAME_ENCLOSING_METHOD),
                            AttributeKind::EnclosingMethod,
                        ),
                        (
                            mutf8::encode(attributes::NAME_SIGNATURE),
                            AttributeKind::Signature,
                        ),
                        (
                            mutf8::encode(attributes::NAME_LOCAL_VARIABLE_TABLE),
                            AttributeKind::LocalVariableTable,
                        ),
                        (
                            mutf8::encode(attributes::NAME_LOCAL_VARIABLE_TYPE_TABLE),
                            AttributeKind::LocalVariableTypeTable,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RUNTIME_VISIBLE_ANNOTATIONS),
                            AttributeKind::RuntimeVisibleAnnotations,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RUNTIME_INVISIBLE_ANNOTATIONS),
                            AttributeKind::RuntimeInvisibleAnnotations,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RUNTIME_VISIBLE_PARAM_ANNOTATIONS),
                            AttributeKind::RuntimeVisibleParameterAnnotations,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RUNTIME_INVISIBLE_PARAM_ANNOTATIONS),
                            AttributeKind::RuntimeInvisibleParameterAnnotations,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RUNTIME_VISIBLE_TYPE_ANNOTATIONS),
                            AttributeKind::RuntimeVisibleTypeAnnotations,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RUNTIME_INVISIBLE_TYPE_ANNOTATIONS),
                            AttributeKind::RuntimeInvisibleTypeAnnotations,
                        ),
                        (
                            mutf8::encode(attributes::NAME_ANNOTATION_DEFAULT),
                            AttributeKind::AnnotationDefault,
                        ),
                        (
                            mutf8::encode(attributes::NAME_RECORD),
                            AttributeKind::Record,
                        ),
                    ]
                    .into_iter()
                    .map(|(a, b)| (a.into(), b)),
                )
            }),

            classes: Vec::new(),
            field_refs: Vec::new(),
            method_refs: Vec::new(),
            dynamic_fields: Vec::new(),
            dynamic_methods: Vec::new(),
            method_types: Vec::new(),

            const_pool: ConstPoolBuffer {
                states: Vec::new(),
                entries: Vec::new(),
                appends: ConstPoolAppends {
                    start: NonZero::new(1).unwrap(),
                    entries: Vec::new(),
                },
            },
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attrs: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.classes.clear();
        self.field_refs.clear();
        self.method_refs.clear();

        self.dynamic_fields.clear();
        self.dynamic_methods.clear();
        self.method_types.clear();

        self.const_pool.states.clear();
        self.const_pool.entries.clear();
        self.const_pool.appends.start = NonZero::new(1).unwrap();
        self.const_pool.appends.entries.clear();

        self.interfaces.clear();
        self.fields.clear();
        self.methods.clear();
        self.attrs.clear();
    }
}

impl ConstPoolBuffer<'_> {
    fn remap_attribute(
        &mut self,
        attr: &mut CowAttribute<'_>,
        index: &Index,
        attr_cx: AttrContext<'_>,
        cx: &Context,
    ) {
        let _ = self.try_remap_attribute(attr, index, attr_cx, cx);
    }

    fn try_remap_attribute(
        &mut self,
        attr: &mut CowAttribute<'_>,
        index: &Index,
        attr_cx: AttrContext<'_>,
        cx: &Context,
    ) -> Result<(), Error> {
        let Some(kind) = self
            .states
            .get(attr.name_index.get() as usize)
            .and_then(|s| s.matched_attr)
        else {
            return Ok(());
        };

        match kind {
            AttributeKind::Code => {
                let reader = CodeReader::new(&*attr.info);
                let mut buf = Vec::new();
                let writer = CodeWriter::new(&mut buf);
                let (body, mut reader) = reader.body()?;
                let mut writer = writer.set_body(&body)?;
                while let Some(entry) = reader.next().transpose()? {
                    writer.push(&entry)?;
                }
                let mut reader = reader.finish()?;
                let mut writer = writer.finish()?;
                while let Some(nested) = reader.next().transpose()? {
                    let mut nested = CowAttribute::from(nested);
                    self.try_remap_attribute(&mut nested, index, attr_cx, cx)?;
                    writer.push(&nested.as_attr())?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::InnerClasses => {
                let mut reader = InnerClassesReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = InnerClassesWriter::new(&mut buf)?;
                while let Some(mut class) = reader.next().transpose()? {
                    // The simple name is a part of the mapped name of the inner class.
                    let inner_name = self.remap_inner_name(index, class.inner_info_idx);
                    if let (Some(name_idx), Some(inner_name)) = (class.inner_name_idx, inner_name) {
                        class.inner_name_idx = Some(self.remap_utf8(
                            name_idx,
                            RemapKind::InnerClassName,
                            move |_| Some(inner_name),
                        ));
                    }
                    writer.push(&class)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::EnclosingMethod => {
                let EnclosingMethod {
                    class_idx,
                    method_idx,
                } = EnclosingMethod::read(&*attr.info)?;
                // The `Class` entry referred by `class_idx` is rewritten in place, and the
                // enclosing method is a `NameAndType` entry, which is rewritten here.
                if let Some(method_idx) = method_idx {
                    self.remap_name_and_type(index, class_idx, method_idx, true, cx);
                }
            }
            AttributeKind::Signature => {
                let ConstantPoolIndex(idx) = ConstantPoolIndex::read(&*attr.info)?;
                let remapped = match attr_cx {
                    AttrContext::Class(_) => {
                        self.remap_utf8(idx, RemapKind::ClassSignature, |sig| {
                            remap_class_sig(index, sig).ok().flatten()
                        })
                    }
                    AttrContext::Method(_) => {
                        self.remap_utf8(idx, RemapKind::MethodSignature, |sig| {
                            remap_method_sig(index, sig).ok().flatten()
                        })
                    }
                    AttrContext::Field | AttrContext::RecordComponent => {
                        self.remap_utf8(idx, RemapKind::FieldSignature, |sig| {
                            remap_field_sig(index, sig).ok().flatten()
                        })
                    }
                    AttrContext::None => idx,
                };
                attr.info = Cow::Owned(remapped.get().to_be_bytes().to_vec());
            }
            AttributeKind::LocalVariableTable => {
                if let AttrContext::Method(method) = attr_cx {
                    let mut reader = LocalVariableTableReader::new(&*attr.info)?;
                    let mut buf = Vec::new();
                    let mut writer = LocalVariableTableWriter::new(&mut buf)?;
                    while let Some(mut entry) = reader.next().transpose()? {
                        entry.desc_idx = self.remap_field_type(index, entry.desc_idx);
                        if let Some(name) = method
                            .and_then(|method| method.lv.get(entry.index as usize))
                            .and_then(Option::as_ref)
                        {
                            entry.name_idx =
                                self.remap_utf8(entry.name_idx, RemapKind::LocalVarName, |_| {
                                    Some(name.clone())
                                });
                        }
                        writer.push(&entry)?;
                    }
                    writer.finish()?;
                    attr.info = Cow::Owned(buf);
                }
            }
            AttributeKind::LocalVariableTypeTable => {
                if let AttrContext::Method(method) = attr_cx {
                    let mut reader = LocalVariableTypeTableReader::new(&*attr.info)?;
                    let mut buf = Vec::new();
                    let mut writer = LocalVariableTypeTableWriter::new(&mut buf)?;
                    while let Some(mut entry) = reader.next().transpose()? {
                        entry.signature_idx = self.remap_utf8(
                            entry.signature_idx,
                            RemapKind::FieldSignature,
                            |sig| remap_field_sig(index, sig).ok().flatten(),
                        );
                        if let Some(name) = method
                            .and_then(|method| method.lv.get(entry.index as usize))
                            .and_then(Option::as_ref)
                        {
                            entry.name_idx =
                                self.remap_utf8(entry.name_idx, RemapKind::LocalVarName, |_| {
                                    Some(name.clone())
                                });
                        }
                        writer.push(&entry)?;
                    }
                    writer.finish()?;
                    attr.info = Cow::Owned(buf);
                }
            }
            AttributeKind::RuntimeVisibleAnnotations => {
                let mut reader = RuntimeVisibleAnnotationsReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = RuntimeVisibleAnnotationsWriter::new(&mut buf)?;
                while let Some(mut entry) = reader.next().transpose()? {
                    self.remap_annotation(index, &mut entry);
                    writer.push(&entry)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::RuntimeInvisibleAnnotations => {
                let mut reader = RuntimeInvisibleAnnotationsReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = RuntimeInvisibleAnnotationsWriter::new(&mut buf)?;
                while let Some(mut entry) = reader.next().transpose()? {
                    self.remap_annotation(index, &mut entry);
                    writer.push(&entry)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::RuntimeVisibleParameterAnnotations => {
                let mut reader = RuntimeVisibleParamAnnotationsReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = RuntimeVisibleParamAnnotationsWriter::new(&mut buf)?;
                while let Some(mut entry) = reader.next().transpose()? {
                    self.remap_param_annotations(index, &mut entry);
                    writer.push(&entry)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::RuntimeInvisibleParameterAnnotations => {
                let mut reader = RuntimeInvisibleParamAnnotationsReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = RuntimeInvisibleParamAnnotationsWriter::new(&mut buf)?;
                while let Some(mut entry) = reader.next().transpose()? {
                    self.remap_param_annotations(index, &mut entry);
                    writer.push(&entry)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::RuntimeVisibleTypeAnnotations => {
                let mut reader = RuntimeVisibleTypeAnnotationsReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = RuntimeVisibleTypeAnnotationsWriter::new(&mut buf)?;
                while let Some(mut entry) = reader.next().transpose()? {
                    self.remap_typed_annotation(index, &mut entry);
                    writer.push(&entry)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::RuntimeInvisibleTypeAnnotations => {
                let mut reader = RuntimeInvisibleTypeAnnotationsReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                let mut writer = RuntimeInvisibleTypeAnnotationsWriter::new(&mut buf)?;
                while let Some(mut entry) = reader.next().transpose()? {
                    self.remap_typed_annotation(index, &mut entry);
                    writer.push(&entry)?;
                }
                writer.finish()?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::AnnotationDefault => {
                let mut value = ElementValue::read(&*attr.info)?;
                self.remap_element_value(index, &mut value);
                let mut buf = Vec::new();
                value.write(&mut buf)?;
                attr.info = Cow::Owned(buf);
            }
            AttributeKind::Record => {
                let mut reader = RecordReader::new(&*attr.info)?;
                let mut buf = Vec::new();
                while let Some(mut entry) = reader.next().transpose()? {
                    if let AttrContext::Class(class) = attr_cx {
                        (entry.name_idx, entry.desc_idx) =
                            self.remap_field(index, class, entry.name_idx, entry.desc_idx, cx);
                    }
                    let mut attrs = Vec::with_capacity(entry.attributes.len());
                    for sub in &*entry.attributes {
                        let mut sub = CowAttribute::from(*sub);
                        self.try_remap_attribute(
                            &mut sub,
                            index,
                            AttrContext::RecordComponent,
                            cx,
                        )?;
                        attrs.push(sub);
                    }
                    // Encodes a record component the same way as `ComponentInfo` does.
                    buf.extend_from_slice(&entry.name_idx.get().to_be_bytes());
                    buf.extend_from_slice(&entry.desc_idx.get().to_be_bytes());
                    buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
                    for sub in &attrs {
                        buf.extend_from_slice(&sub.name_index.get().to_be_bytes());
                        buf.extend_from_slice(&(sub.info.len() as u32).to_be_bytes());
                        buf.extend_from_slice(&sub.info);
                    }
                }
                attr.info = Cow::Owned(buf);
            }
        }
        Ok(())
    }

    fn remap_class_info(&mut self, index: &Index, idx: NonZero<u16>) {
        if let Some(state) = self.states.get_mut(idx.get() as usize)
            && !state.modified
            && let Some(Some(ConstantPoolEntry::Class(ni))) = self.entries.get(idx.get() as usize)
        {
            state.modified = true;
            let dst = self.remap_class_name(index, *ni);
            self.entries[idx.get() as usize] = Some(ConstantPoolEntry::Class(dst));
        }
    }

    #[must_use]
    fn remap_class_name(&mut self, index: &Index, nid: NonZero<u16>) -> NonZero<u16> {
        self.remap_utf8(nid, RemapKind::ClassName, |name| {
            let mut changed = false;
            let mapped = index.remap_class_name_tracked(name, &mut changed);
            changed.then_some(mapped).map(Into::into)
        })
    }

    /// Simple name of the mapped name of the inner class at `idx`, if it is mapped.
    fn remap_inner_name(&mut self, index: &Index, idx: NonZero<u16>) -> Option<SmolStr> {
        let Some(Some(ConstantPoolEntry::Class(name_idx))) = self.entries.get(idx.get() as usize)
        else {
            return None;
        };
        let name_idx = *name_idx;
        let remapped = self.remap_class_name(index, name_idx);
        if remapped == name_idx {
            return None;
        }
        let name = self.utf8(remapped)?;
        Some(
            name.rsplit_once('$')
                .map_or(&*name, |(_, simple)| simple)
                .to_smolstr(),
        )
    }

    /// Remaps the `Utf8` entry at `idx` with `f`, appending the result to the constant pool.
    ///
    /// The result is cached per kind, so one entry used in several roles gets remapped
    /// individually for each of them.
    fn remap_utf8<F>(&mut self, idx: NonZero<u16>, kind: RemapKind, f: F) -> NonZero<u16>
    where
        F: FnOnce(&str) -> Option<SmolStr>,
    {
        let i = idx.get() as usize;
        let Some(Some(ConstantPoolEntry::Utf8(src))) = self.entries.get(i) else {
            return idx;
        };
        let Ok(decoded) = mutf8::decode(src.0) else {
            return idx;
        };
        let Some(state) = self.states.get_mut(i) else {
            return idx;
        };
        state
            .remap(kind, &mut self.appends, || f(&decoded))
            .unwrap_or(idx)
    }

    /// Decodes the `Utf8` entry at `idx`.
    fn utf8(&self, idx: NonZero<u16>) -> Option<Cow<'_, str>> {
        match self.entries.get(idx.get() as usize) {
            Some(Some(ConstantPoolEntry::Utf8(name))) => mutf8::decode(name.0).ok(),
            _ => None,
        }
    }

    fn class_name(&self, idx: NonZero<u16>) -> Option<Cow<'_, str>> {
        self.entries
            .get(idx.get() as usize)
            .and_then(Option::as_ref)
            .and_then(|entry| match entry {
                ConstantPoolEntry::Class(ni) => {
                    self.entries.get(ni.get() as usize).and_then(Option::as_ref)
                }
                _ => None,
            })
            .and_then(|entry| match entry {
                ConstantPoolEntry::Utf8(name) => mutf8::decode(name.0).ok(),
                _ => None,
            })
    }

    fn remap_field_name_and_type(
        &mut self,
        index: &Index,
        class: NonZero<u16>,
        ntid: NonZero<u16>,
        cx: &Context,
    ) {
        self.remap_name_and_type(index, class, ntid, false, cx);
    }

    fn remap_method_name_and_type(
        &mut self,
        index: &Index,
        class: NonZero<u16>,
        ntid: NonZero<u16>,
        cx: &Context,
    ) {
        self.remap_name_and_type(index, class, ntid, true, cx);
    }

    /// Rewrites the `NameAndType` entry at `ntid` with the mapped name and descriptor.
    fn remap_name_and_type(
        &mut self,
        index: &Index,
        class_idx: NonZero<u16>,
        ntid: NonZero<u16>,
        method: bool,
        cx: &Context,
    ) {
        let idx = ntid.get() as usize;
        if self.states.get(idx).is_none_or(|state| state.modified) {
            return;
        }
        let Some(Some(ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        })) = self.entries.get(idx)
        else {
            return;
        };
        let (name_index, descriptor_index) = (*name_index, *descriptor_index);
        self.states[idx].modified = true;
        let class = self.class_name(class_idx).map(SmolStr::from);
        let (name_index, descriptor_index) = if method {
            let (_, name_index, descriptor_index) =
                self.remap_method(index, class.as_deref(), name_index, descriptor_index, cx);
            (name_index, descriptor_index)
        } else {
            self.remap_field(index, class.as_deref(), name_index, descriptor_index, cx)
        };
        self.entries[idx] = Some(ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        });
    }

    /// Rewrites the `MethodType` entry at `idx` with the mapped descriptor.
    fn remap_method_type(&mut self, index: &Index, idx: NonZero<u16>) {
        let i = idx.get() as usize;
        let Some(Some(ConstantPoolEntry::MethodType(desc_idx))) = self.entries.get(i) else {
            return;
        };
        let desc_idx = *desc_idx;
        let remapped = self.remap_utf8(desc_idx, RemapKind::MethodDescriptor, |desc| {
            remap_method_desc(index, desc).ok().flatten()
        });
        self.entries[i] = Some(ConstantPoolEntry::MethodType(remapped));
    }

    fn remap_annotation(&mut self, index: &Index, annotation: &mut Annotation<'_>) {
        annotation.type_idx = self.remap_field_type(index, annotation.type_idx);
        for (_, value) in annotation.pairs.to_mut() {
            self.remap_element_value(index, value);
        }
    }

    fn remap_param_annotations(&mut self, index: &Index, annotation: &mut ParamAnnotations<'_>) {
        for value in annotation.0.to_mut() {
            self.remap_annotation(index, value);
        }
    }

    fn remap_typed_annotation(&mut self, index: &Index, annotation: &mut TypedAnnotation<'_>) {
        annotation.type_idx = self.remap_field_type(index, annotation.type_idx);
        for (_, value) in annotation.pairs.to_mut() {
            self.remap_element_value(index, value);
        }
    }

    fn remap_element_value(&mut self, index: &Index, entry: &mut ElementValue<'_>) {
        match entry {
            ElementValue::Enum {
                type_name_idx,
                // TODO: is this truly useless here?
                const_name_idx: _,
            } => *type_name_idx = self.remap_field_type(index, *type_name_idx),
            // `Class` entries are rewritten in place, so nothing has to be written back here.
            ElementValue::Class(_) => (),
            ElementValue::Annotation(annotation) => self.remap_annotation(index, annotation),
            ElementValue::Array(values) => {
                for value in values.to_mut() {
                    self.remap_element_value(index, value);
                }
            }
            ElementValue::Const { .. } => (),
        }
    }

    /// Remaps the field descriptor at `di`, returning the index of the mapped descriptor.
    fn remap_field_type(&mut self, index: &Index, di: NonZero<u16>) -> NonZero<u16> {
        self.remap_utf8(di, RemapKind::FieldType, |desc| {
            remap_field_type(index, desc).ok().flatten()
        })
    }

    fn remap_field(
        &mut self,
        index: &Index,
        class: Option<&str>,
        ni: NonZero<u16>,
        di: NonZero<u16>,
        cx: &Context,
    ) -> (NonZero<u16>, NonZero<u16>) {
        let desc_idx = self.remap_utf8(di, RemapKind::FieldType, |desc| {
            remap_field_type(index, desc).ok().flatten()
        });
        let Some(name) = self.utf8(ni) else {
            return (ni, desc_idx);
        };
        let Some(dst) = class.and_then(|cl| index.remap_field_name(cl, &name, cx)) else {
            return (ni, desc_idx);
        };
        let name_idx = self.remap_utf8(ni, RemapKind::FieldName, |_| Some(dst.clone()));
        (name_idx, desc_idx)
    }

    fn remap_method<'i>(
        &mut self,
        index: &'i Index,
        class: Option<&str>,
        ni: NonZero<u16>,
        di: NonZero<u16>,
        cx: &Context,
    ) -> (Option<&'i Method>, NonZero<u16>, NonZero<u16>) {
        let desc_idx = self.remap_utf8(di, RemapKind::MethodDescriptor, |desc| {
            remap_method_desc(index, desc).ok().flatten()
        });
        let (Some(name), Some(desc)) = (self.utf8(ni), self.utf8(di)) else {
            return (None, ni, desc_idx);
        };
        let Some(dst) = class.and_then(|cl| {
            index.remap_method_name(
                cl,
                &DescKey {
                    name: name.to_smolstr(),
                    desc: desc.to_smolstr(),
                },
                cx,
            )
        }) else {
            return (None, ni, desc_idx);
        };
        let name_idx = self.remap_utf8(ni, RemapKind::MethodName, |_| dst.name.clone());
        (Some(dst), name_idx, desc_idx)
    }
}

fn remap_field_type_raw<'a>(
    index: &'a Index,
    src: FieldType<'a>,
    changed: &mut bool,
) -> FieldType<'a> {
    match src {
        FieldType::Primitive(val) => FieldType::Primitive(val),
        FieldType::Class(cl) => FieldType::Class(index.remap_class_name_tracked(cl, changed)),
        FieldType::Array(ty) => {
            FieldType::Array(Box::new(remap_field_type_raw(index, *ty, changed)))
        }
    }
}

fn remap_field_type(
    index: &Index,
    src: &str,
) -> Result<Option<SmolStr>, java_bin_name::UnknownTypeTag> {
    let ty = java_bin_name::parse::<'_, FieldType<'_>>(src)?;
    let mut changed = false;
    let mapped = remap_field_type_raw(index, ty, &mut changed);
    Ok(changed.then(|| mapped.to_smolstr()))
}

fn remap_method_desc(
    index: &Index,
    src: &str,
) -> Result<Option<SmolStr>, java_bin_name::InvalidMethodDescriptor> {
    let mut desc = java_bin_name::parse::<'_, MethodDescriptor<'_>>(src)?;
    let mut changed = false;
    for param in &mut desc.params {
        let mapped = remap_field_type_raw(
            index,
            std::mem::replace(
                param,
                FieldType::Primitive(java_bin_name::PrimitiveType::Byte),
            ),
            &mut changed,
        );
        *param = mapped;
    }
    match &mut desc.ret {
        java_bin_name::MethodReturnDescriptor::Void => (),
        java_bin_name::MethodReturnDescriptor::Type(ty) => {
            let mapped = remap_field_type_raw(
                index,
                std::mem::replace(ty, FieldType::Primitive(java_bin_name::PrimitiveType::Byte)),
                &mut changed,
            );
            *ty = mapped;
        }
    }
    Ok(changed.then(|| desc.to_smolstr()))
}

fn remap_type_sig<'a>(
    index: &'a Index,
    src: TypeSignature<'a>,
    changed: &mut bool,
) -> TypeSignature<'a> {
    match src {
        TypeSignature::Class { sig, suffix } => TypeSignature::Class {
            sig: ReducedClassTypeSignature {
                name: index.remap_class_name_tracked(sig.name, changed),
                args: {
                    let mut args = sig.args;
                    remap_type_args(index, &mut args, changed);
                    args
                },
            },
            suffix: suffix.map(|suffix| ReducedClassTypeSignature {
                name: index.remap_class_name_tracked(suffix.name, changed),
                args: {
                    let mut args = suffix.args;
                    remap_type_args(index, &mut args, changed);
                    args
                },
            }),
        },
        TypeSignature::Array(sig) => {
            TypeSignature::Array(Box::new(remap_type_sig(index, *sig, changed)))
        }
        nice => nice,
    }
}

fn remap_type_arg<'a>(
    index: &'a Index,
    src: TypeArgument<'a>,
    changed: &mut bool,
) -> TypeArgument<'a> {
    TypeArgument {
        kind: src.kind,
        signature: remap_type_sig(index, src.signature, changed),
    }
}

fn remap_type_args<'a>(
    index: &'a Index,
    args: &mut [Option<Box<TypeArgument<'a>>>],
    changed: &mut bool,
) {
    for op in args {
        if let Some(arg) = op.take() {
            *op = Some(Box::new(remap_type_arg(index, *arg, changed)))
        }
    }
}

fn remap_type_param<'a>(
    index: &'a Index,
    src: TypeParameter<'a>,
    changed: &mut bool,
) -> TypeParameter<'a> {
    TypeParameter {
        name: src.name,
        bound_class: src
            .bound_class
            .map(|sig| remap_type_sig(index, sig, changed)),
        bound_interface: {
            let mut impls = src.bound_interface;
            for sig in &mut impls {
                *sig = remap_type_sig(
                    index,
                    std::mem::replace(
                        sig,
                        TypeSignature::Primitive(java_bin_name::PrimitiveType::Byte),
                    ),
                    changed,
                );
            }
            impls
        },
    }
}

fn remap_method_sig(
    index: &Index,
    src: &str,
) -> Result<Option<SmolStr>, java_bin_name::InvalidMethodSignature> {
    let mut sig: MethodSignature<'_> = java_bin_name::parse(src)?;
    let mut changed = false;
    sig.params = sig
        .params
        .into_iter()
        .map(|p| remap_type_param(index, p, &mut changed))
        .collect();
    sig.args = sig
        .args
        .into_iter()
        .map(|sig| remap_type_sig(index, sig, &mut changed))
        .collect();
    sig.result = match sig.result {
        java_bin_name::MethodReturnSignature::Type(sig) => {
            java_bin_name::MethodReturnSignature::Type(remap_type_sig(index, sig, &mut changed))
        }
        nice => nice,
    };
    sig.throws = sig
        .throws
        .into_iter()
        .map(|sig| remap_type_sig(index, sig, &mut changed))
        .collect();
    Ok(changed.then(|| sig.to_smolstr()))
}

fn remap_class_sig(
    index: &Index,
    src: &str,
) -> Result<Option<SmolStr>, java_bin_name::InvalidClassSignature> {
    let mut sig: ClassSignature<'_> = java_bin_name::parse(src)?;
    let mut changed = false;
    sig.params = sig
        .params
        .into_iter()
        .map(|p| remap_type_param(index, p, &mut changed))
        .collect();
    sig.extends = remap_type_sig(index, sig.extends, &mut changed);
    sig.impls = sig
        .impls
        .into_iter()
        .map(|p| remap_type_sig(index, p, &mut changed))
        .collect();
    Ok(changed.then(|| sig.to_smolstr()))
}

fn remap_field_sig(
    index: &Index,
    src: &str,
) -> Result<Option<SmolStr>, java_bin_name::UnknownTypeTag> {
    let sig: TypeSignature<'_> = java_bin_name::parse(src)?;
    let mut changed = false;
    let sig = remap_type_sig(index, sig, &mut changed);
    Ok(changed.then(|| sig.to_smolstr()))
}

impl Default for Buffer<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Remaps the given bytecode with the index.
#[allow(clippy::missing_panics_doc)]
pub fn remap<'a>(
    src: &'a [u8],
    dst: &mut Vec<u8>,
    index: &Index,
    buf: &mut Buffer<'a>,
    cx: &Context,
) -> Result<(), Error> {
    buf.clear();
    let reader = Reader::new(src);

    let (header, mut reader) = reader.header()?;

    while let Some((idx, entry)) = reader.next().transpose()? {
        match entry {
            ConstantPoolEntry::Class(_) => buf.classes.push(idx),
            ConstantPoolEntry::FieldRef {
                class_index,
                name_and_type_index,
            } => buf.field_refs.push((class_index, name_and_type_index)),
            ConstantPoolEntry::MethodRef {
                class_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::InterfaceMethodRef {
                class_index,
                name_and_type_index,
            } => buf.method_refs.push((class_index, name_and_type_index)),
            ConstantPoolEntry::Dynamic {
                name_and_type_index,
                ..
            } => buf.dynamic_fields.push(name_and_type_index),
            ConstantPoolEntry::InvokeDynamic {
                name_and_type_index,
                ..
            } => buf.dynamic_methods.push(name_and_type_index),
            ConstantPoolEntry::MethodType(_) => buf.method_types.push(idx),
            _ => (),
        }

        buf.const_pool
            .states
            .resize(idx.get() as usize, Default::default());
        buf.const_pool.states.push(
            if let ConstantPoolEntry::Utf8(m) = &entry
                && let Some(&kind) = buf.attribute_matcher.get(m.0)
            {
                ConstState {
                    matched_attr: Some(kind),
                    ..Default::default()
                }
            } else {
                Default::default()
            },
        );

        buf.const_pool.appends.start = buf
            .const_pool
            .appends
            .start
            .checked_add(entry.space())
            .expect("constant pool overflowed");
        buf.const_pool.entries.resize(idx.get() as usize, None);
        buf.const_pool.entries.push(Some(entry));
    }
    let reader = reader.finish()?;

    let (metadata, mut reader) = reader.metadata()?;
    // Class infos are rewritten in place at the end, so `Class` entries still hold their
    // original names while the references below are remapped.
    let this_class = buf
        .const_pool
        .class_name(metadata.this_class)
        .map(SmolStr::from);
    let this_class = this_class.as_deref();

    for &(ci, nti) in &buf.field_refs {
        buf.const_pool.remap_field_name_and_type(index, ci, nti, cx);
    }
    for &(ci, nti) in &buf.method_refs {
        buf.const_pool
            .remap_method_name_and_type(index, ci, nti, cx);
    }
    for &nti in &buf.dynamic_fields {
        buf.const_pool
            .remap_name_and_type(index, metadata.this_class, nti, false, cx);
    }
    for &nti in &buf.dynamic_methods {
        buf.const_pool
            .remap_name_and_type(index, metadata.this_class, nti, true, cx);
    }
    for &idx in &buf.method_types {
        buf.const_pool.remap_method_type(index, idx);
    }

    while let Some(idx) = reader.next().transpose()? {
        buf.interfaces.push(idx);
    }
    let mut reader = reader.finish()?;

    while let Some(mut fr) = reader.next().transpose()? {
        let mut header = *fr.header();
        (header.name_index, header.descriptor_index) = buf.const_pool.remap_field(
            index,
            this_class,
            header.name_index,
            header.descriptor_index,
            cx,
        );
        let mut attrs = Vec::with_capacity(fr.len());
        while let Some(attr) = fr.next().transpose()? {
            let mut attr = CowAttribute::from(attr);
            buf.const_pool
                .remap_attribute(&mut attr, index, AttrContext::Field, cx);
            attrs.push(attr);
        }
        buf.fields.push((header, attrs));
    }

    let mut reader = reader.finish()?;
    while let Some(mut mr) = reader.next().transpose()? {
        let mut header = *mr.header();
        let (this_method, name_index, descriptor_index) = buf.const_pool.remap_method(
            index,
            this_class,
            header.name_index,
            header.descriptor_index,
            cx,
        );
        header.name_index = name_index;
        header.descriptor_index = descriptor_index;
        let mut attrs = Vec::with_capacity(mr.len());
        while let Some(attr) = mr.next().transpose()? {
            let mut attr = CowAttribute::from(attr);
            buf.const_pool
                .remap_attribute(&mut attr, index, AttrContext::Method(this_method), cx);
            attrs.push(attr);
        }
        buf.methods.push((header, attrs));
    }

    let mut reader = reader.finish()?;
    while let Some(attr) = reader.next().transpose()? {
        let mut attr = CowAttribute::from(attr);
        buf.const_pool
            .remap_attribute(&mut attr, index, AttrContext::Class(this_class), cx);
        buf.attrs.push(attr);
    }
    drop(reader);

    // Class names are appended to the constant pool, so the `Class` entries have to be
    // rewritten at last, after every other reference resolved its class by the original name.
    for &idx in &buf.classes {
        buf.const_pool.remap_class_info(index, idx);
    }

    let writer = Writer::new(dst);
    let mut writer = writer.set_header(&header)?;

    for entry in buf.const_pool.entries.iter().flatten() {
        writer.push(entry)?;
    }
    for remapped in &buf.const_pool.appends.entries {
        let encoded = mutf8::encode(remapped);
        writer.push(&ConstantPoolEntry::Utf8(ModifiedUtf8(&encoded)))?;
    }

    let writer = writer.finish()?;
    let mut writer = writer.set_metadata(&metadata)?;

    for &idx in &buf.interfaces {
        writer.push(idx)?;
    }

    let mut writer = Some(writer.finish()?);
    for (header, attrs) in &buf.fields {
        let mut wi = writer.take().unwrap().set_header(header)?;
        for attr in attrs {
            wi.push(&attr.as_attr())?;
        }
        writer = Some(wi.finish()?)
    }

    let mut writer = Some(writer.unwrap().finish()?);
    for (header, attrs) in &buf.methods {
        let mut wi = writer.take().unwrap().set_header(header)?;
        for attr in attrs {
            wi.push(&attr.as_attr())?;
        }
        writer = Some(wi.finish()?)
    }

    let mut writer = writer.unwrap().finish()?;
    for attr in &buf.attrs {
        writer.push(&attr.as_attr())?;
    }

    writer.finish()?;
    Ok(())
}
