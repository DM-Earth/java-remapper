use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use mapping_serde::{Deserialize, Deserializer, de::Visitor};
use smol_str::SmolStr;

/// Naming mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub(crate) classes: HashMap<SmolStr, Class>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Class {
    /// Mapped name.
    pub(crate) name: Option<SmolStr>,
    pub(crate) methods: HashMap<DescKey, Method>,
    /// Mapped field names.
    pub(crate) fields: HashMap<SmolStr, SmolStr>,
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
            classes: HashMap::new(),
        };
        while deserializer
            .deserialize_class(RootVisitor(&mut index))?
            .is_some()
        {}
        Ok(index)
    }

    pub(crate) fn remap_class_name<'a>(&'a self, src: &'a str, changed: &mut bool) -> &'a str {
        self.classes
            .get(src)
            .and_then(|c| c.name.as_deref())
            .inspect(|_| *changed = true)
            .unwrap_or(src)
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
                methods: HashMap::new(),
                fields: HashMap::new(),
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
