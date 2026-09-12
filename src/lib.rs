//! Java classfile remapper library.

use std::{collections::HashMap, num::NonZero, sync::OnceLock};

use classfile::{
    Attribute, ConstantPoolEntry, FieldHeader, MethodHeader, ModifiedUtf8, Reader, Writer,
    attributes::{
        self, Annotation, CodeReader, ConstantPoolIndex, ElementValue, InnerClassesReader,
        LocalVariableTableReader, ParamAnnotations, RecordReader,
        RuntimeInvisibleAnnotationsReader, RuntimeInvisibleParamAnnotationsReader,
        RuntimeInvisibleTypeAnnotationsReader, RuntimeVisibleAnnotationsReader,
        RuntimeVisibleParamAnnotationsReader, RuntimeVisibleTypeAnnotationsReader, TypedAnnotation,
    },
};
use java_bin_name::{
    ClassSignature, FieldType, MethodDescriptor, MethodSignature, ReducedClassTypeSignature,
    TypeParameter, TypeSignature,
};
use simd_cesu8::mutf8;
use smol_str::{SmolStr, ToSmolStr as _};

mod index;

pub use index::Index;

use crate::index::{Class, Method};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AttributeKind {
    Code,
    InnerClasses,
    Signature,
    LocalVariableTable,
    RuntimeVisibleAnnotations,
    RuntimeInvisibleAnnotations,
    RuntimeVisibleParameterAnnotations,
    RuntimeInvisibleParameterAnnotations,
    RuntimeVisibleTypeAnnotations,
    RuntimeInvisibleTypeAnnotations,
    Record,
}

#[derive(Debug, Clone, Default)]
struct ConstState {
    /// Matching attribute. This is only useful for the `Utf8` entry pointed by an attribute.
    matched_attr: Option<AttributeKind>,
    /// The remapped value.
    remapped: Option<Option<SmolStr>>,
}

/// Auxiliary buffer for a remapper.
#[derive(Debug)]
pub struct Buffer<'a> {
    attribute_matcher: &'static HashMap<Box<[u8]>, AttributeKind>,

    classes: Vec<NonZero<u16>>,
    field_refs: Vec<(NonZero<u16>, NonZero<u16>)>,
    method_refs: Vec<(NonZero<u16>, NonZero<u16>)>,

    // stores
    const_pool: ConstPoolBuffer<'a>,
    interfaces: Vec<NonZero<u16>>,
    fields: Vec<(FieldHeader, Vec<Attribute<'a>>)>,
    methods: Vec<(MethodHeader, Vec<Attribute<'a>>)>,
    attrs: Vec<Attribute<'a>>,
}

/// Buffer of a constant pool.
/// States and entries are indexed through their raw id, which is retrived directly from the class file.
#[derive(Debug, Default)]
struct ConstPoolBuffer<'a> {
    states: Vec<ConstState>,
    entries: Vec<Option<ConstantPoolEntry<'a>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum AttrContext<'a> {
    Class(Option<&'a Class>),
    Field,
    Method(Option<&'a Method>),
    RecordComponent,
    #[default]
    None,
}

impl Buffer<'_> {
    /// Creates a new buffer.
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
                            mutf8::encode(attributes::NAME_SIGNATURE),
                            AttributeKind::Signature,
                        ),
                        (
                            mutf8::encode(attributes::NAME_LOCAL_VARIABLE_TABLE),
                            AttributeKind::LocalVariableTable,
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

            const_pool: Default::default(),
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

        self.const_pool.states.clear();
        self.const_pool.entries.clear();
        self.interfaces.clear();
        self.fields.clear();
        self.methods.clear();
        self.attrs.clear();
    }

    fn remap_attribute(&mut self, attr: &Attribute<'_>, index: &Index, cx: AttrContext<'_>) {
        let _ = self.try_remap_attribute(attr, index, cx);
    }

    fn try_remap_attribute(
        &mut self,
        attr: &Attribute<'_>,
        index: &Index,
        cx: AttrContext<'_>,
    ) -> Result<(), classfile::Error> {
        let Some(kind) = self
            .const_pool
            .states
            .get(attr.name_index.get() as usize)
            .and_then(|s| s.matched_attr)
        else {
            return Ok(());
        };

        match kind {
            AttributeKind::Code => {
                let reader = CodeReader::new(attr.info);
                let (_, reader) = reader.body()?;
                let mut reader = reader.finish()?;
                while let Some(attr) = reader.next().transpose()? {
                    self.try_remap_attribute(&attr, index, AttrContext::None)?;
                }
            }
            AttributeKind::InnerClasses => {
                let mut reader = InnerClassesReader::new(attr.info)?;
                while let Some(class) = reader.next().transpose()? {
                    self.const_pool
                        .remap_class_info(index, class.inner_info_idx);
                    if let Some(idx) = class.outer_info_idx {
                        self.const_pool.remap_class_info(index, idx);
                    }
                    if let Some(name_idx) = class.inner_name_idx
                        && let Some(Some(ConstantPoolEntry::Class(src_idx))) = self
                            .const_pool
                            .entries
                            .get(class.inner_info_idx.get() as usize)
                        && let Ok([src, dst]) = self
                            .const_pool
                            .states
                            .get_disjoint_mut([src_idx.get() as usize, name_idx.get() as usize])
                        && dst.remapped.is_none()
                        && let Some(remapped) = &src.remapped
                    {
                        dst.remapped = Some(
                            remapped
                                .as_deref()
                                .map(|s| s.rsplit_once('$').map_or(s, |(_, b)| b))
                                .map(Into::into),
                        )
                    }
                }
            }
            AttributeKind::Signature => {
                let ConstantPoolIndex(idx) = ConstantPoolIndex::read(attr.info)?;
                if let Some(Some(ConstantPoolEntry::Utf8(rsig))) =
                    self.const_pool.entries.get(idx.get() as usize)
                    && let Ok(rsig) = mutf8::decode(rsig.0)
                {
                    match cx {
                        AttrContext::Class(_) => {
                            if let Some(dst) = self.const_pool.states.get_mut(idx.get() as usize)
                                && dst.remapped.is_none()
                                && let Ok(remapped) = remap_class_sig(index, &rsig)
                            {
                                dst.remapped = Some(remapped);
                            }
                        }
                        AttrContext::Method(_) => {
                            if let Some(dst) = self.const_pool.states.get_mut(idx.get() as usize)
                                && dst.remapped.is_none()
                                && let Ok(remapped) = remap_method_sig(index, &rsig)
                            {
                                dst.remapped = Some(remapped);
                            }
                        }
                        AttrContext::Field | AttrContext::RecordComponent => {
                            if let Some(dst) = self.const_pool.states.get_mut(idx.get() as usize)
                                && dst.remapped.is_none()
                                && let Ok(remapped) = remap_field_sig(index, &rsig)
                            {
                                dst.remapped = Some(remapped);
                            }
                        }
                        AttrContext::None => (),
                    }
                }
            }
            AttributeKind::LocalVariableTable => {
                if let AttrContext::Method(method) = cx {
                    let mut reader = LocalVariableTableReader::new(attr.info)?;
                    while let Some(entry) = reader.next().transpose()? {
                        if let Ok([name_state, desc_state]) =
                            self.const_pool.states.get_disjoint_mut([
                                entry.name_idx.get() as usize,
                                entry.desc_idx.get() as usize,
                            ])
                            && let Some(Some(ConstantPoolEntry::Utf8(desc))) =
                                self.const_pool.entries.get(entry.desc_idx.get() as usize)
                            && let Ok(desc) = mutf8::decode(desc.0)
                        {
                            desc_state.remapped =
                                Some(remap_field_type(index, &desc).ok().flatten());
                            name_state.remapped = Some(
                                if let Some(method) = method
                                    && let Some(var) =
                                        method.lv.get(entry.index as usize).and_then(Option::as_ref)
                                {
                                    Some(var.clone())
                                } else {
                                    None
                                },
                            );
                        }
                    }
                }
            }
            AttributeKind::RuntimeVisibleAnnotations => {
                let mut reader = RuntimeVisibleAnnotationsReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    self.const_pool.remap_annotation(index, &entry);
                }
            }
            AttributeKind::RuntimeInvisibleAnnotations => {
                let mut reader = RuntimeInvisibleAnnotationsReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    self.const_pool.remap_annotation(index, &entry);
                }
            }
            AttributeKind::RuntimeVisibleParameterAnnotations => {
                let mut reader = RuntimeVisibleParamAnnotationsReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    self.const_pool.remap_param_annotations(index, &entry);
                }
            }
            AttributeKind::RuntimeInvisibleParameterAnnotations => {
                let mut reader = RuntimeInvisibleParamAnnotationsReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    self.const_pool.remap_param_annotations(index, &entry);
                }
            }
            AttributeKind::RuntimeVisibleTypeAnnotations => {
                let mut reader = RuntimeVisibleTypeAnnotationsReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    self.const_pool.remap_typed_annotation(index, &entry);
                }
            }
            AttributeKind::RuntimeInvisibleTypeAnnotations => {
                let mut reader = RuntimeInvisibleTypeAnnotationsReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    self.const_pool.remap_typed_annotation(index, &entry);
                }
            }
            AttributeKind::Record => {
                let mut reader = RecordReader::new(attr.info)?;
                while let Some(entry) = reader.next().transpose()? {
                    if let AttrContext::Class(class) = cx {
                        self.const_pool
                            .remap_field(index, class, entry.name_idx, entry.desc_idx);
                    }
                    for attr in &*entry.attributes {
                        self.try_remap_attribute(attr, index, AttrContext::RecordComponent)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl ConstPoolBuffer<'_> {
    fn remap_class_info(&mut self, index: &Index, idx: NonZero<u16>) {
        if let Some(Some(ConstantPoolEntry::Class(idx))) = self.entries.get(idx.get() as usize) {
            self.remap_class_name(index, *idx);
        }
    }

    fn remap_class_name(&mut self, index: &Index, nid: NonZero<u16>) {
        let nid = nid.get() as usize;
        if let Some(state) = self.states.get_mut(nid)
            && state.remapped.is_none()
            && let Some(Some(ConstantPoolEntry::Utf8(src))) = self.entries.get(nid)
        {
            state.remapped = if let Ok(decoded) = mutf8::decode(src.0)
                && let Some(entry) = index.classes.get(&*decoded)
            {
                Some(entry.name.clone())
            } else {
                None
            }
        }
    }

    fn class<'a>(&self, index: &'a Index, idx: NonZero<u16>) -> Option<&'a Class> {
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
            .and_then(|name| index.classes.get(&*name))
    }

    fn remap_field_name_and_type(
        &mut self,
        index: &Index,
        class: NonZero<u16>,
        ntid: NonZero<u16>,
    ) {
        if let Some(Some(ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        })) = self.entries.get(ntid.get() as usize)
        {
            self.remap_field(
                index,
                self.class(index, class),
                *name_index,
                *descriptor_index,
            );
        }
    }

    fn remap_annotation(&mut self, index: &Index, annotation: &Annotation<'_>) {
        self.remap_field_type(index, annotation.type_idx);
        for (_, v) in &*annotation.pairs {
            self.remap_element_value(index, v);
        }
    }

    fn remap_param_annotations(&mut self, index: &Index, annotation: &ParamAnnotations<'_>) {
        for val in &*annotation.0 {
            self.remap_annotation(index, val);
        }
    }

    fn remap_typed_annotation(&mut self, index: &Index, annotation: &TypedAnnotation<'_>) {
        self.remap_field_type(index, annotation.type_idx);
        for (_, v) in &*annotation.pairs {
            self.remap_element_value(index, v);
        }
    }

    fn remap_element_value(&mut self, index: &Index, entry: &ElementValue<'_>) {
        match entry {
            ElementValue::Enum {
                type_name_idx,
                // TODO: is this truly useless here?
                const_name_idx: _,
            } => self.remap_field_type(index, *type_name_idx),
            ElementValue::Class(idx) => self.remap_class_info(index, *idx),
            ElementValue::Annotation(annotation) => self.remap_annotation(index, annotation),
            ElementValue::Array(many) => {
                for v in &**many {
                    self.remap_element_value(index, v);
                }
            }
            _ => (),
        }
    }

    fn remap_field_type(&mut self, index: &Index, di: NonZero<u16>) {
        if let Some(Some(ConstantPoolEntry::Utf8(desc))) = self.entries.get(di.get() as usize)
            && let Ok(desc) = mutf8::decode(desc.0)
            && let Some(desc_state) = self.states.get_mut(di.get() as usize)
            && desc_state.remapped.is_none()
        {
            desc_state.remapped = Some(remap_field_type(index, &desc).ok().flatten());
        }
    }

    fn remap_field(
        &mut self,
        index: &Index,
        class: Option<&Class>,
        ni: NonZero<u16>,
        di: NonZero<u16>,
    ) {
        if let Some(Some(ConstantPoolEntry::Utf8(name))) = self.entries.get(ni.get() as usize)
            && let Some(Some(ConstantPoolEntry::Utf8(desc))) = self.entries.get(di.get() as usize)
            && let Ok(name) = mutf8::decode(name.0)
            && let Ok(desc) = mutf8::decode(desc.0)
            && let Ok([name_state, desc_state]) = self
                .states
                .get_disjoint_mut([ni.get() as usize, di.get() as usize])
            && desc_state.remapped.is_none()
        {
            if let Some(class) = class
                && let Some(dst) = class.fields.get(&*name)
            {
                name_state.remapped = Some(Some(dst.clone()));
                desc_state.remapped = Some(remap_field_type(index, &desc).ok().flatten());
            } else {
                name_state.remapped = Some(None);
                desc_state.remapped = Some(None);
            }
        }
    }

    fn remap_method_name_and_type(
        &mut self,
        index: &Index,
        class: NonZero<u16>,
        ntid: NonZero<u16>,
    ) {
        if let Some(Some(ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        })) = self.entries.get(ntid.get() as usize)
        {
            self.remap_method(
                index,
                self.class(index, class),
                *name_index,
                *descriptor_index,
            );
        }
    }

    fn remap_method<'i>(
        &mut self,
        index: &Index,
        class: Option<&'i Class>,
        ni: NonZero<u16>,
        di: NonZero<u16>,
    ) -> Option<&'i Method> {
        if let Some(Some(ConstantPoolEntry::Utf8(name))) = self.entries.get(ni.get() as usize)
            && let Some(Some(ConstantPoolEntry::Utf8(desc))) = self.entries.get(di.get() as usize)
            && let Ok(name) = mutf8::decode(name.0)
            && let Ok(desc) = mutf8::decode(desc.0)
            && let Ok([name_state, desc_state]) = self
                .states
                .get_disjoint_mut([ni.get() as usize, di.get() as usize])
            && desc_state.remapped.is_none()
        {
            if let Some(class) = class
                && let Some(dst) = class.methods.get(&index::DescKey {
                    name: name.into(),
                    desc: (*desc).into(),
                })
            {
                name_state.remapped = Some(dst.name.clone());
                name_state.remapped = Some(remap_method_desc(index, &desc).ok().flatten());
                Some(dst)
            } else {
                name_state.remapped = Some(None);
                desc_state.remapped = Some(None);
                None
            }
        } else {
            None
        }
    }
}

fn remap_field_type_raw<'a>(
    index: &'a Index,
    src: FieldType<'a>,
    changed: &mut bool,
) -> FieldType<'a> {
    match src {
        FieldType::Primitive(val) => FieldType::Primitive(val),
        FieldType::Class(cl) => FieldType::Class(index.remap_class_name(cl, changed)),
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
                name: index.remap_class_name(sig.name, changed),
                args: sig.args,
            },
            suffix: suffix.map(|suffix| ReducedClassTypeSignature {
                name: index.remap_class_name(suffix.name, changed),
                args: suffix.args,
            }),
        },
        TypeSignature::Array(sig) => {
            TypeSignature::Array(Box::new(remap_type_sig(index, *sig, changed)))
        }
        nice => nice,
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
) -> Result<(), classfile::Error> {
    buf.clear();
    let reader = Reader::new(src);

    let (header, mut reader) = reader.header()?;

    while let Some((idx, entry)) = reader.next().transpose()? {
        match entry {
            ConstantPoolEntry::Class(nid) => buf.classes.push(nid),
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

        buf.const_pool.entries.resize(idx.get() as usize, None);
        buf.const_pool.entries.push(Some(entry));
    }
    let reader = reader.finish()?;

    for &nid in &buf.classes {
        buf.const_pool.remap_class_name(index, nid);
    }
    for &(ci, nti) in &buf.field_refs {
        buf.const_pool.remap_field_name_and_type(index, ci, nti);
    }
    for &(ci, nti) in &buf.method_refs {
        buf.const_pool.remap_method_name_and_type(index, ci, nti);
    }

    let (metadata, mut reader) = reader.metadata()?;
    let this_class = buf.const_pool.class(index, metadata.this_class);

    while let Some(idx) = reader.next().transpose()? {
        buf.interfaces.push(idx);
    }
    let mut reader = reader.finish()?;

    while let Some(mut fr) = reader.next().transpose()? {
        let header = *fr.header();
        buf.const_pool.remap_field(
            index,
            this_class,
            header.name_index,
            header.descriptor_index,
        );
        let mut attrs = Vec::with_capacity(fr.len());
        while let Some(attr) = fr.next().transpose()? {
            buf.remap_attribute(&attr, index, AttrContext::Field);
            attrs.push(attr);
        }
        buf.fields.push((header, attrs));
    }

    let mut reader = reader.finish()?;
    while let Some(mut mr) = reader.next().transpose()? {
        let header = *mr.header();
        let this_method = buf.const_pool.remap_method(
            index,
            this_class,
            header.name_index,
            header.descriptor_index,
        );
        let mut attrs = Vec::with_capacity(mr.len());
        while let Some(attr) = mr.next().transpose()? {
            buf.remap_attribute(&attr, index, AttrContext::Method(this_method));
            attrs.push(attr);
        }
        buf.methods.push((header, attrs));
    }

    let mut reader = reader.finish()?;
    while let Some(attr) = reader.next().transpose()? {
        buf.remap_attribute(&attr, index, AttrContext::Class(this_class));
        buf.attrs.push(attr);
    }
    drop(reader);

    let writer = Writer::new(dst);
    let mut writer = writer.set_header(&header)?;

    for (idx, entry) in buf.const_pool.entries.iter().enumerate() {
        if let Some(entry) = entry {
            match entry {
                s @ ConstantPoolEntry::Utf8(_) => {
                    if let Some(state) = buf.const_pool.states.get(idx)
                        && let Some(Some(remapped)) = &state.remapped
                    {
                        let encoded = mutf8::encode(remapped);
                        writer.push(&ConstantPoolEntry::Utf8(ModifiedUtf8(&encoded)))?
                    } else {
                        writer.push(s)?
                    }
                }
                nice => writer.push(nice)?,
            }
        }
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
            wi.push(attr)?;
        }
        writer = Some(wi.finish()?)
    }

    let mut writer = Some(writer.unwrap().finish()?);
    for (header, attrs) in &buf.methods {
        let mut wi = writer.take().unwrap().set_header(header)?;
        for attr in attrs {
            wi.push(attr)?;
        }
        writer = Some(wi.finish()?)
    }

    let mut writer = writer.unwrap().finish()?;
    for attr in &buf.attrs {
        writer.push(attr)?;
    }

    writer.finish()?;
    Ok(())
}
