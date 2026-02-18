use crate::class_reader::{AttributeInfo, CodeAttribute, CpInfo};

#[derive(Debug, Clone)]
pub struct ClassNode {
    pub minor_version: u16,
    pub major_version: u16,
    pub access_flags: u16,
    pub constant_pool: Vec<CpInfo>,
    pub this_class: u16,
    pub super_class: u16,
    pub name: String,
    pub super_name: Option<String>,
    pub source_file: Option<String>,
    pub interfaces: Vec<String>,
    pub interface_indices: Vec<u16>,
    pub fields: Vec<FieldNode>,
    pub methods: Vec<MethodNode>,
    pub attributes: Vec<AttributeInfo>,
}

#[derive(Debug, Clone)]
pub struct FieldNode {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub name: String,
    pub descriptor: String,
    pub attributes: Vec<AttributeInfo>,
}

#[derive(Debug, Clone)]
pub struct MethodNode {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub name: String,
    pub descriptor: String,
    pub code: Option<CodeAttribute>,
    pub attributes: Vec<AttributeInfo>,
}
