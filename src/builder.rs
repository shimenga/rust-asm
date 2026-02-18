use std::collections::HashMap;

use crate::class_reader::{AttributeInfo, CodeAttribute, CpInfo, ExceptionTableEntry};
use crate::insn::{
    FieldInsnNode, Insn, InsnList, InsnNode, LdcInsnNode, LdcValue, MemberRef, MethodInsnNode,
    VarInsnNode,
};
use crate::nodes::{ClassNode, FieldNode, MethodNode};
use crate::opcodes;

#[derive(Debug, Default)]
pub struct ConstantPoolBuilder {
    cp: Vec<CpInfo>,
    utf8: HashMap<String, u16>,
    class: HashMap<String, u16>,
    string: HashMap<String, u16>,
    name_and_type: HashMap<(String, String), u16>,
    field_ref: HashMap<(String, String, String), u16>,
    method_ref: HashMap<(String, String, String), u16>,
}

impl ConstantPoolBuilder {
    pub fn new() -> Self {
        Self {
            cp: vec![CpInfo::Unusable],
            ..Default::default()
        }
    }

    pub fn into_pool(self) -> Vec<CpInfo> {
        self.cp
    }

    pub fn utf8(&mut self, value: &str) -> u16 {
        if let Some(index) = self.utf8.get(value) {
            return *index;
        }
        let index = self.push(CpInfo::Utf8(value.to_string()));
        self.utf8.insert(value.to_string(), index);
        index
    }

    pub fn class(&mut self, name: &str) -> u16 {
        if let Some(index) = self.class.get(name) {
            return *index;
        }
        let name_index = self.utf8(name);
        let index = self.push(CpInfo::Class { name_index });
        self.class.insert(name.to_string(), index);
        index
    }

    pub fn string(&mut self, value: &str) -> u16 {
        if let Some(index) = self.string.get(value) {
            return *index;
        }
        let string_index = self.utf8(value);
        let index = self.push(CpInfo::String { string_index });
        self.string.insert(value.to_string(), index);
        index
    }

    pub fn name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
        let key = (name.to_string(), descriptor.to_string());
        if let Some(index) = self.name_and_type.get(&key) {
            return *index;
        }
        let name_index = self.utf8(name);
        let descriptor_index = self.utf8(descriptor);
        let index = self.push(CpInfo::NameAndType {
            name_index,
            descriptor_index,
        });
        self.name_and_type.insert(key, index);
        index
    }

    pub fn field_ref(&mut self, owner: &str, name: &str, descriptor: &str) -> u16 {
        let key = (owner.to_string(), name.to_string(), descriptor.to_string());
        if let Some(index) = self.field_ref.get(&key) {
            return *index;
        }
        let class_index = self.class(owner);
        let name_and_type_index = self.name_and_type(name, descriptor);
        let index = self.push(CpInfo::Fieldref {
            class_index,
            name_and_type_index,
        });
        self.field_ref.insert(key, index);
        index
    }

    pub fn method_ref(&mut self, owner: &str, name: &str, descriptor: &str) -> u16 {
        let key = (owner.to_string(), name.to_string(), descriptor.to_string());
        if let Some(index) = self.method_ref.get(&key) {
            return *index;
        }
        let class_index = self.class(owner);
        let name_and_type_index = self.name_and_type(name, descriptor);
        let index = self.push(CpInfo::Methodref {
            class_index,
            name_and_type_index,
        });
        self.method_ref.insert(key, index);
        index
    }

    fn push(&mut self, entry: CpInfo) -> u16 {
        self.cp.push(entry);
        (self.cp.len() - 1) as u16
    }
}

pub struct ClassBuilder {
    minor_version: u16,
    major_version: u16,
    access_flags: u16,
    name: String,
    super_name: Option<String>,
    interfaces: Vec<String>,
    fields: Vec<FieldBuilder>,
    methods: Vec<MethodBuilder>,
    attributes: Vec<AttributeInfo>,
    source_file: Option<String>,
    cp: ConstantPoolBuilder,
}

impl ClassBuilder {
    pub fn new(name: &str, super_name: &str) -> Self {
        Self {
            minor_version: 0,
            major_version: 52,
            access_flags: 0,
            name: name.to_string(),
            super_name: Some(super_name.to_string()),
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
            source_file: None,
            cp: ConstantPoolBuilder::new(),
        }
    }

    pub fn version(&mut self, major: u16, minor: u16) -> &mut Self {
        self.major_version = major;
        self.minor_version = minor;
        self
    }

    pub fn access_flags(&mut self, flags: u16) -> &mut Self {
        self.access_flags = flags;
        self
    }

    pub fn add_interface(&mut self, name: &str) -> &mut Self {
        self.interfaces.push(name.to_string());
        self
    }

    pub fn add_field(&mut self, field: FieldBuilder) -> &mut Self {
        self.fields.push(field);
        self
    }

    pub fn add_method(&mut self, method: MethodBuilder) -> &mut Self {
        self.methods.push(method);
        self
    }

    pub fn add_attribute(&mut self, attr: AttributeInfo) -> &mut Self {
        self.attributes.push(attr);
        self
    }

    pub fn source_file(&mut self, name: &str) -> &mut Self {
        self.source_file = Some(name.to_string());
        self
    }

    pub fn build(mut self) -> ClassNode {
        let this_class = self.cp.class(&self.name);
        let super_class = match self.super_name.as_deref() {
            Some(name) => self.cp.class(name),
            None => 0,
        };

        let mut interface_indices = Vec::with_capacity(self.interfaces.len());
        for name in &self.interfaces {
            interface_indices.push(self.cp.class(name));
        }

        let mut fields = Vec::with_capacity(self.fields.len());
        for field in self.fields {
            let name_index = self.cp.utf8(&field.name);
            let descriptor_index = self.cp.utf8(&field.descriptor);
            fields.push(FieldNode {
                access_flags: field.access_flags,
                name_index,
                descriptor_index,
                name: field.name,
                descriptor: field.descriptor,
                attributes: field.attributes,
            });
        }

        let mut methods = Vec::with_capacity(self.methods.len());
        for method in self.methods {
            let name_index = self.cp.utf8(&method.name);
            let descriptor_index = self.cp.utf8(&method.descriptor);
            let code = method.code.map(|code| code.build(&mut self.cp));
            methods.push(MethodNode {
                access_flags: method.access_flags,
                name_index,
                descriptor_index,
                name: method.name,
                descriptor: method.descriptor,
                code,
                attributes: method.attributes,
            });
        }

        if let Some(source_name) = self.source_file.as_ref() {
            let source_index = self.cp.utf8(source_name);
            self.attributes
                .push(AttributeInfo::SourceFile { sourcefile_index: source_index });
        }

        ClassNode {
            minor_version: self.minor_version,
            major_version: self.major_version,
            access_flags: self.access_flags,
            constant_pool: self.cp.into_pool(),
            this_class,
            super_class,
            name: self.name,
            super_name: self.super_name,
            source_file: self.source_file.clone(),
            interfaces: self.interfaces,
            interface_indices,
            fields,
            methods,
            attributes: self.attributes,
        }
    }
}

pub struct FieldBuilder {
    access_flags: u16,
    name: String,
    descriptor: String,
    attributes: Vec<AttributeInfo>,
}

impl FieldBuilder {
    pub fn new(access_flags: u16, name: &str, descriptor: &str) -> Self {
        Self {
            access_flags,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(&mut self, attr: AttributeInfo) -> &mut Self {
        self.attributes.push(attr);
        self
    }
}

pub struct MethodBuilder {
    access_flags: u16,
    name: String,
    descriptor: String,
    code: Option<CodeBody>,
    attributes: Vec<AttributeInfo>,
}

impl MethodBuilder {
    pub fn new(access_flags: u16, name: &str, descriptor: &str) -> Self {
        Self {
            access_flags,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            code: None,
            attributes: Vec::new(),
        }
    }

    pub fn code(&mut self, max_stack: u16, max_locals: u16) -> &mut InsnList {
        if self.code.is_none() {
            self.code = Some(CodeBody::new(max_stack, max_locals, InsnList::new()));
        }
        let code = self.code.as_mut().expect("code should be initialized");
        code.max_stack = max_stack;
        code.max_locals = max_locals;
        &mut code.insns
    }

    pub fn set_code(&mut self, max_stack: u16, max_locals: u16, insns: InsnList) -> &mut Self {
        self.code = Some(CodeBody::new(max_stack, max_locals, insns));
        self
    }

    pub fn add_attribute(&mut self, attr: AttributeInfo) -> &mut Self {
        self.attributes.push(attr);
        self
    }

    pub fn add_code_exception(&mut self, entry: ExceptionTableEntry) -> &mut Self {
        if let Some(code) = &mut self.code {
            code.exception_table.push(entry);
        }
        self
    }

    pub fn add_code_attribute(&mut self, attr: AttributeInfo) -> &mut Self {
        if let Some(code) = &mut self.code {
            code.attributes.push(attr);
        }
        self
    }
}

struct CodeBody {
    max_stack: u16,
    max_locals: u16,
    insns: InsnList,
    exception_table: Vec<ExceptionTableEntry>,
    attributes: Vec<AttributeInfo>,
}

impl CodeBody {
    fn new(max_stack: u16, max_locals: u16, insns: InsnList) -> Self {
        Self {
            max_stack,
            max_locals,
            insns,
            exception_table: Vec::new(),
            attributes: Vec::new(),
        }
    }

    fn build(self, cp: &mut ConstantPoolBuilder) -> CodeAttribute {
        let mut code = Vec::new();
        let mut instructions = Vec::new();
        for insn in self.insns.into_insns() {
            let resolved = emit_insn(&mut code, insn, cp);
            instructions.push(resolved);
        }
        CodeAttribute {
            max_stack: self.max_stack,
            max_locals: self.max_locals,
            code,
            instructions,
            insn_nodes: Vec::new(),
            exception_table: self.exception_table,
            try_catch_blocks: Vec::new(),
            attributes: self.attributes,
        }
    }
}

fn build_code_attribute(
    max_stack: u16,
    max_locals: u16,
    insns: InsnList,
    cp: &mut ConstantPoolBuilder,
    exception_table: Vec<ExceptionTableEntry>,
    attributes: Vec<AttributeInfo>,
) -> CodeAttribute {
    CodeBody {
        max_stack,
        max_locals,
        insns,
        exception_table,
        attributes,
    }
    .build(cp)
}

fn emit_insn(code: &mut Vec<u8>, insn: Insn, cp: &mut ConstantPoolBuilder) -> Insn {
    let offset = code.len();
    match insn {
        Insn::Simple(node) => {
            code.push(node.opcode);
            Insn::Simple(node)
        }
        Insn::Int(node) => {
            code.push(node.insn.opcode);
            match node.insn.opcode {
                opcodes::BIPUSH => write_i1(code, node.operand as i8),
                opcodes::SIPUSH => write_i2(code, node.operand as i16),
                opcodes::NEWARRAY => write_u1(code, node.operand as u8),
                _ => write_i1(code, node.operand as i8),
            }
            Insn::Int(node)
        }
        Insn::Var(node) => {
            code.push(node.insn.opcode);
            write_u1(code, node.var_index as u8);
            Insn::Var(node)
        }
        Insn::Type(node) => {
            code.push(node.insn.opcode);
            write_u2(code, node.type_index);
            Insn::Type(node)
        }
        Insn::Field(node) => {
            code.push(node.insn.opcode);
            let (index, resolved) = resolve_field_ref(node, cp);
            write_u2(code, index);
            Insn::Field(resolved)
        }
        Insn::Method(node) => {
            code.push(node.insn.opcode);
            let (index, resolved) = resolve_method_ref(node, cp);
            write_u2(code, index);
            Insn::Method(resolved)
        }
        Insn::InvokeInterface(node) => {
            code.push(node.insn.opcode);
            write_u2(code, node.method_index);
            write_u1(code, node.count);
            write_u1(code, 0);
            Insn::InvokeInterface(node)
        }
        Insn::InvokeDynamic(node) => {
            code.push(node.insn.opcode);
            write_u2(code, node.method_index);
            write_u2(code, 0);
            Insn::InvokeDynamic(node)
        }
        Insn::Jump(node) => {
            code.push(node.insn.opcode);
            match node.insn.opcode {
                opcodes::GOTO_W | opcodes::JSR_W => write_i4(code, node.offset),
                _ => write_i2(code, node.offset as i16),
            }
            Insn::Jump(node)
        }
        Insn::Ldc(node) => {
            let (opcode, index, resolved) = resolve_ldc(node, cp);
            code.push(opcode);
            if opcode == opcodes::LDC {
                write_u1(code, index as u8);
            } else {
                write_u2(code, index);
            }
            Insn::Ldc(resolved)
        }
        Insn::Iinc(node) => {
            code.push(node.insn.opcode);
            write_u1(code, node.var_index as u8);
            write_i1(code, node.increment as i8);
            Insn::Iinc(node)
        }
        Insn::TableSwitch(node) => {
            code.push(node.insn.opcode);
            write_switch_padding(code, offset);
            write_i4(code, node.default_offset);
            write_i4(code, node.low);
            write_i4(code, node.high);
            for value in &node.offsets {
                write_i4(code, *value);
            }
            Insn::TableSwitch(node)
        }
        Insn::LookupSwitch(node) => {
            code.push(node.insn.opcode);
            write_switch_padding(code, offset);
            write_i4(code, node.default_offset);
            write_i4(code, node.pairs.len() as i32);
            for (key, value) in &node.pairs {
                write_i4(code, *key);
                write_i4(code, *value);
            }
            Insn::LookupSwitch(node)
        }
        Insn::MultiANewArray(node) => {
            code.push(node.insn.opcode);
            write_u2(code, node.type_index);
            write_u1(code, node.dimensions);
            Insn::MultiANewArray(node)
        }
    }
}

fn write_u2(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u1(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn write_i1(out: &mut Vec<u8>, value: i8) {
    out.push(value as u8);
}

fn write_i2(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_i4(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_switch_padding(out: &mut Vec<u8>, opcode_offset: usize) {
    let mut padding = (4 - ((opcode_offset + 1) % 4)) % 4;
    while padding > 0 {
        out.push(0);
        padding -= 1;
    }
}

fn resolve_field_ref(node: FieldInsnNode, cp: &mut ConstantPoolBuilder) -> (u16, FieldInsnNode) {
    match node.field_ref {
        MemberRef::Index(index) => (index, node),
        MemberRef::Symbolic {
            owner,
            name,
            descriptor,
        } => {
            let index = cp.field_ref(&owner, &name, &descriptor);
            (
                index,
                FieldInsnNode {
                    insn: node.insn,
                    field_ref: MemberRef::Index(index),
                },
            )
        }
    }
}

fn resolve_method_ref(
    node: MethodInsnNode,
    cp: &mut ConstantPoolBuilder,
) -> (u16, MethodInsnNode) {
    match node.method_ref {
        MemberRef::Index(index) => (index, node),
        MemberRef::Symbolic {
            owner,
            name,
            descriptor,
        } => {
            let index = cp.method_ref(&owner, &name, &descriptor);
            (
                index,
                MethodInsnNode {
                    insn: node.insn,
                    method_ref: MemberRef::Index(index),
                },
            )
        }
    }
}

fn resolve_ldc(node: LdcInsnNode, cp: &mut ConstantPoolBuilder) -> (u8, u16, LdcInsnNode) {
    match node.value {
        LdcValue::Index(index) => {
            let opcode = if index <= 0xFF {
                opcodes::LDC
            } else {
                opcodes::LDC_W
            };
            (
                opcode,
                index,
                LdcInsnNode {
                    insn: InsnNode { opcode },
                    value: LdcValue::Index(index),
                },
            )
        }
        LdcValue::String(value) => {
            let index = cp.string(&value);
            let opcode = if index <= 0xFF {
                opcodes::LDC
            } else {
                opcodes::LDC_W
            };
            (
                opcode,
                index,
                LdcInsnNode {
                    insn: InsnNode { opcode },
                    value: LdcValue::Index(index),
                },
            )
        }
    }
}

struct FieldData {
    access_flags: u16,
    name: String,
    descriptor: String,
    attributes: Vec<AttributeInfo>,
}

struct MethodData {
    access_flags: u16,
    name: String,
    descriptor: String,
    code: Option<CodeAttribute>,
    attributes: Vec<AttributeInfo>,
}

pub struct ClassWriter {
    options: u32,
    minor_version: u16,
    major_version: u16,
    access_flags: u16,
    name: String,
    super_name: Option<String>,
    interfaces: Vec<String>,
    fields: Vec<FieldData>,
    methods: Vec<MethodData>,
    attributes: Vec<AttributeInfo>,
    source_file: Option<String>,
    cp: ConstantPoolBuilder,
}

impl ClassWriter {
    pub fn new(options: u32) -> Self {
        Self {
            options,
            minor_version: 0,
            major_version: 52,
            access_flags: 0,
            name: String::new(),
            super_name: None,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
            source_file: None,
            cp: ConstantPoolBuilder::new(),
        }
    }

    pub fn visit(
        &mut self,
        major: u16,
        minor: u16,
        access_flags: u16,
        name: &str,
        super_name: Option<&str>,
        interfaces: &[&str],
    ) -> &mut Self {
        self.major_version = major;
        self.minor_version = minor;
        self.access_flags = access_flags;
        self.name = name.to_string();
        self.super_name = super_name.map(|value| value.to_string());
        self.interfaces = interfaces.iter().map(|value| (*value).to_string()).collect();
        self
    }

    pub fn visit_source_file(&mut self, name: &str) -> &mut Self {
        self.source_file = Some(name.to_string());
        self
    }

    pub fn visit_method(
        &mut self,
        access_flags: u16,
        name: &str,
        descriptor: &str,
    ) -> MethodVisitor {
        MethodVisitor::new(access_flags, name, descriptor)
    }

    pub fn visit_field(
        &mut self,
        access_flags: u16,
        name: &str,
        descriptor: &str,
    ) -> FieldVisitor {
        FieldVisitor::new(access_flags, name, descriptor)
    }

    pub fn add_attribute(&mut self, attr: AttributeInfo) -> &mut Self {
        self.attributes.push(attr);
        self
    }

    pub fn visit_end(&mut self) {}

    pub fn to_class_node(mut self) -> Result<ClassNode, String> {
        if self.name.is_empty() {
            return Err("missing class name, call visit() first".to_string());
        }

        let this_class = self.cp.class(&self.name);
        let super_class = match self.super_name.as_deref() {
            Some(name) => self.cp.class(name),
            None => 0,
        };

        let mut interface_indices = Vec::with_capacity(self.interfaces.len());
        for name in &self.interfaces {
            interface_indices.push(self.cp.class(name));
        }

        let mut fields = Vec::with_capacity(self.fields.len());
        for field in self.fields {
            let name_index = self.cp.utf8(&field.name);
            let descriptor_index = self.cp.utf8(&field.descriptor);
            fields.push(FieldNode {
                access_flags: field.access_flags,
                name_index,
                descriptor_index,
                name: field.name,
                descriptor: field.descriptor,
                attributes: field.attributes,
            });
        }

        let mut methods = Vec::with_capacity(self.methods.len());
        for method in self.methods {
            let name_index = self.cp.utf8(&method.name);
            let descriptor_index = self.cp.utf8(&method.descriptor);
            methods.push(MethodNode {
                access_flags: method.access_flags,
                name_index,
                descriptor_index,
                name: method.name,
                descriptor: method.descriptor,
                code: method.code,
                attributes: method.attributes,
            });
        }

        if let Some(source_name) = self.source_file.as_ref() {
            let source_index = self.cp.utf8(source_name);
            self.attributes
                .push(AttributeInfo::SourceFile { sourcefile_index: source_index });
        }

        Ok(ClassNode {
            minor_version: self.minor_version,
            major_version: self.major_version,
            access_flags: self.access_flags,
            constant_pool: self.cp.into_pool(),
            this_class,
            super_class,
            name: self.name,
            super_name: self.super_name,
            source_file: self.source_file.clone(),
            interfaces: self.interfaces,
            interface_indices,
            fields,
            methods,
            attributes: self.attributes,
        })
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, crate::class_writer::ClassWriteError> {
        let options = self.options;
        let class_node = self
            .to_class_node()
            .map_err(crate::class_writer::ClassWriteError::FrameComputation)?;
        let writer = crate::class_writer::ClassWriter::new(options);
        writer.to_bytes(&class_node)
    }
}

pub struct MethodVisitor {
    access_flags: u16,
    name: String,
    descriptor: String,
    has_code: bool,
    max_stack: u16,
    max_locals: u16,
    insns: InsnList,
    exception_table: Vec<ExceptionTableEntry>,
    code_attributes: Vec<AttributeInfo>,
    attributes: Vec<AttributeInfo>,
}

impl MethodVisitor {
    fn new(access_flags: u16, name: &str, descriptor: &str) -> Self {
        Self {
            access_flags,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            has_code: false,
            max_stack: 0,
            max_locals: 0,
            insns: InsnList::new(),
            exception_table: Vec::new(),
            code_attributes: Vec::new(),
            attributes: Vec::new(),
        }
    }

    pub fn visit_code(&mut self) -> &mut Self {
        self.has_code = true;
        self
    }

    pub fn visit_insn(&mut self, opcode: u8) -> &mut Self {
        self.insns.add(InsnNode { opcode });
        self
    }

    pub fn visit_var_insn(&mut self, opcode: u8, var_index: u16) -> &mut Self {
        self.insns.add(VarInsnNode {
            insn: InsnNode { opcode },
            var_index,
        });
        self
    }

    pub fn visit_field_insn(
        &mut self,
        opcode: u8,
        owner: &str,
        name: &str,
        descriptor: &str,
    ) -> &mut Self {
        self.insns.add(FieldInsnNode::new(opcode, owner, name, descriptor));
        self
    }

    pub fn visit_method_insn(
        &mut self,
        opcode: u8,
        owner: &str,
        name: &str,
        descriptor: &str,
        _is_interface: bool,
    ) -> &mut Self {
        self.insns.add(MethodInsnNode::new(opcode, owner, name, descriptor));
        self
    }

    pub fn visit_ldc_insn(&mut self, value: &str) -> &mut Self {
        self.insns.add(LdcInsnNode::string(value));
        self
    }

    pub fn visit_maxs(&mut self, max_stack: u16, max_locals: u16) -> &mut Self {
        self.max_stack = max_stack;
        self.max_locals = max_locals;
        self
    }

    pub fn visit_end(mut self, class: &mut ClassWriter) {
        let code = if self.has_code || !self.insns.insns().is_empty() {
            Some(build_code_attribute(
                self.max_stack,
                self.max_locals,
                self.insns,
                &mut class.cp,
                std::mem::take(&mut self.exception_table),
                std::mem::take(&mut self.code_attributes),
            ))
        } else {
            None
        };
        class.methods.push(MethodData {
            access_flags: self.access_flags,
            name: self.name,
            descriptor: self.descriptor,
            code,
            attributes: std::mem::take(&mut self.attributes),
        });
    }
}

pub struct FieldVisitor {
    access_flags: u16,
    name: String,
    descriptor: String,
    attributes: Vec<AttributeInfo>,
}

impl FieldVisitor {
    fn new(access_flags: u16, name: &str, descriptor: &str) -> Self {
        Self {
            access_flags,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(&mut self, attr: AttributeInfo) -> &mut Self {
        self.attributes.push(attr);
        self
    }

    pub fn visit_end(self, class: &mut ClassWriter) {
        class.fields.push(FieldData {
            access_flags: self.access_flags,
            name: self.name,
            descriptor: self.descriptor,
            attributes: self.attributes,
        });
    }
}
