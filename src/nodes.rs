use crate::class_reader::{AttributeInfo, CodeAttribute, CpInfo};

/// Represents a parsed Java Class File.
///
/// This structure holds the complete object model of a `.class` file, including
/// its header information, constant pool, interfaces, fields, methods, and attributes.
///
/// # See Also
/// * [JVM Specification: ClassFile Structure](https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.1)
#[derive(Debug, Clone)]
pub struct ClassNode {
    /// The minor version of the class file format.
    pub minor_version: u16,

    /// The major version of the class file format (e.g., 52 for Java 8, 61 for Java 17).
    pub major_version: u16,

    /// A bitmask of access flags used to denote access permissions to and properties of this class
    /// (e.g., `ACC_PUBLIC`, `ACC_FINAL`, `ACC_INTERFACE`).
    pub access_flags: u16,

    /// The raw constant pool containing heterogeneous constants (strings, integers, method references, etc.).
    /// Index 0 is reserved/unused.
    pub constant_pool: Vec<CpInfo>,

    /// The index into the constant pool pointing to a `CONSTANT_Class_info` structure representing this class.
    pub this_class: u16,

    /// The index into the constant pool pointing to a `CONSTANT_Class_info` structure representing the direct superclass.
    /// This is 0 for `java.lang.Object`.
    pub super_class: u16,

    /// The internal name of the class (e.g., `java/lang/String`).
    pub name: String,

    /// The internal name of the superclass (e.g., `java/lang/String`).
    /// Returns `None` if this class is `java.lang.Object`.
    pub super_name: Option<String>,

    /// The name of the source file from which this class was compiled, if the `SourceFile` attribute was present.
    pub source_file: Option<String>,

    /// A list of internal names of the direct superinterfaces of this class or interface.
    pub interfaces: Vec<String>,

    /// A list of indices into the constant pool representing the direct superinterfaces.
    pub interface_indices: Vec<u16>,

    /// The fields declared by this class or interface.
    pub fields: Vec<FieldNode>,

    /// The methods declared by this class or interface.
    pub methods: Vec<MethodNode>,

    /// Global attributes associated with the class (e.g., `SourceFile`, `InnerClasses`, `EnclosingMethod`).
    pub attributes: Vec<AttributeInfo>,
}

impl ClassNode {
    /// Sets the superclass by internal name (e.g., `java/lang/String`, `a/b/c`).
    /// Use `None` for `java/lang/Object`.
    pub fn set_super_name(&mut self, super_name: Option<&str>) {
        match super_name {
            None => {
                self.super_name = None;
                self.super_class = 0;
            }
            Some(name) => {
                let index = ensure_class(&mut self.constant_pool, name);
                self.super_name = Some(name.to_string());
                self.super_class = index;
            }
        }
    }
}

fn ensure_utf8(cp: &mut Vec<CpInfo>, value: &str) -> u16 {
    for (index, entry) in cp.iter().enumerate() {
        if let CpInfo::Utf8(existing) = entry
            && existing == value
        {
            return index as u16;
        }
    }
    cp.push(CpInfo::Utf8(value.to_string()));
    (cp.len() - 1) as u16
}

fn ensure_class(cp: &mut Vec<CpInfo>, name: &str) -> u16 {
    for (index, entry) in cp.iter().enumerate() {
        if let CpInfo::Class { name_index } = entry
            && let Some(CpInfo::Utf8(value)) = cp.get(*name_index as usize)
            && value == name
        {
            return index as u16;
        }
    }
    let name_index = ensure_utf8(cp, name);
    cp.push(CpInfo::Class { name_index });
    (cp.len() - 1) as u16
}

/// Represents a field (member variable) within a class.
///
/// # See Also
/// * [JVM Specification: field_info](https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.5)
#[derive(Debug, Clone)]
pub struct FieldNode {
    /// A bitmask of access flags (e.g., `ACC_PUBLIC`, `ACC_STATIC`, `ACC_FINAL`).
    pub access_flags: u16,

    /// The constant pool index containing the name of the field.
    pub name_index: u16,

    /// The constant pool index containing the field descriptor.
    pub descriptor_index: u16,

    /// The name of the field.
    pub name: String,

    /// The field descriptor (e.g., `Ljava/lang/String;` or `I`).
    pub descriptor: String,

    /// Attributes associated with this field (e.g., `ConstantValue`, `Synthetic`, `Deprecated`, `Signature`).
    pub attributes: Vec<AttributeInfo>,
}

/// Represents a method within a class.
///
/// # See Also
/// * [JVM Specification: method_info](https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.6)
#[derive(Debug, Clone)]
pub struct MethodNode {
    /// A bitmask of access flags (e.g., `ACC_PUBLIC`, `ACC_STATIC`, `ACC_SYNCHRONIZED`).
    pub access_flags: u16,

    /// The constant pool index containing the name of the method (e.g., `<init>` or `main`).
    pub name_index: u16,

    /// The constant pool index containing the method descriptor (e.g., `([Ljava/lang/String;)V`).
    pub descriptor_index: u16,

    /// The name of the method.
    pub name: String,

    /// The method descriptor describing parameter types and return type.
    pub descriptor: String,

    /// The `Code` attribute containing the JVM bytecode instructions and exception handlers.
    /// This will be `None` for `native` or `abstract` methods.
    pub code: Option<CodeAttribute>,

    /// Other attributes associated with this method (e.g., `Exceptions`, `Synthetic`, `Deprecated`, `Signature`).
    /// Note that the `Code` attribute is stored separately in the `code` field for convenience.
    pub attributes: Vec<AttributeInfo>,
}
