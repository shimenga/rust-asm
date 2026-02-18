use crate::class_reader::{
    AttributeInfo, BootstrapMethod, CodeAttribute, CpInfo, ExceptionTableEntry, InnerClass,
    LineNumber, LocalVariable, MethodParameter, StackMapFrame, VerificationTypeInfo,
};
use crate::nodes::{ClassNode, FieldNode, MethodNode};

#[derive(Debug)]
pub enum ClassWriteError {
    MissingConstantPool,
    InvalidConstantPool,
    InvalidOpcode { opcode: u8, offset: usize },
    FrameComputation(String),
}

impl std::fmt::Display for ClassWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassWriteError::MissingConstantPool => write!(f, "missing constant pool"),
            ClassWriteError::InvalidConstantPool => write!(f, "invalid constant pool"),
            ClassWriteError::InvalidOpcode { opcode, offset } => {
                write!(f, "invalid opcode 0x{opcode:02X} at offset {offset}")
            }
            ClassWriteError::FrameComputation(message) => {
                write!(f, "frame computation error: {message}")
            }
        }
    }
}

impl std::error::Error for ClassWriteError {}

pub const COMPUTE_FRAMES: u32 = 0x1;
pub const COMPUTE_MAXS: u32 = 0x2;

pub struct ClassWriter {
    options: u32,
}

impl ClassWriter {
    pub fn new(options: u32) -> Self {
        Self { options }
    }

    pub fn from_class_node(_class_node: &ClassNode) -> Self {
        Self::new(0)
    }

    pub fn to_bytes(&self, class_node: &ClassNode) -> Result<Vec<u8>, ClassWriteError> {
        if class_node.constant_pool.is_empty() {
            return Err(ClassWriteError::MissingConstantPool);
        }

        let mut cp = class_node.constant_pool.clone();
        let mut out = Vec::new();
        write_u4(&mut out, 0xCAFEBABE);
        write_u2(&mut out, class_node.minor_version);
        write_u2(&mut out, class_node.major_version);

        let mut class_attributes = class_node.attributes.clone();
        if let Some(source_file) = &class_node.source_file {
            class_attributes.retain(|attr| !matches!(attr, AttributeInfo::SourceFile { .. }));
            let source_index = ensure_utf8(&mut cp, source_file);
            class_attributes.push(AttributeInfo::SourceFile {
                sourcefile_index: source_index,
            });
        }

        let mut attribute_names = Vec::new();
        collect_attribute_names(&class_attributes, &mut attribute_names);
        for field in &class_node.fields {
            collect_attribute_names(&field.attributes, &mut attribute_names);
        }
        for method in &class_node.methods {
            collect_attribute_names(&method.attributes, &mut attribute_names);
            if let Some(code) = &method.code {
                attribute_names.push("Code".to_string());
                collect_attribute_names(&code.attributes, &mut attribute_names);
            }
        }
        for name in attribute_names {
            ensure_utf8(&mut cp, &name);
        }

        let mut precomputed_stack_maps: Vec<Option<Vec<StackMapFrame>>> =
            Vec::with_capacity(class_node.methods.len());
        let mut precomputed_maxs: Vec<Option<(u16, u16)>> =
            Vec::with_capacity(class_node.methods.len());
        let compute_frames = self.options & COMPUTE_FRAMES != 0;
        let compute_maxs_flag = self.options & COMPUTE_MAXS != 0;
        if compute_frames {
            ensure_utf8(&mut cp, "StackMapTable");
            for method in &class_node.methods {
                if let Some(code) = &method.code {
                    let maxs = if compute_maxs_flag {
                        Some(compute_maxs(method, class_node, code, &cp)?)
                    } else {
                        None
                    };
                    let max_locals = maxs.map(|item| item.1).unwrap_or(code.max_locals);
                    let stack_map =
                        compute_stack_map_table(method, class_node, code, &mut cp, max_locals)?;
                    precomputed_stack_maps.push(Some(stack_map));
                    precomputed_maxs.push(maxs);
                } else {
                    precomputed_stack_maps.push(None);
                    precomputed_maxs.push(None);
                }
            }
        } else if compute_maxs_flag {
            for method in &class_node.methods {
                if let Some(code) = &method.code {
                    precomputed_maxs.push(Some(compute_maxs(method, class_node, code, &cp)?));
                } else {
                    precomputed_maxs.push(None);
                }
            }
            precomputed_stack_maps.resize(class_node.methods.len(), None);
        } else {
            precomputed_stack_maps.resize(class_node.methods.len(), None);
            precomputed_maxs.resize(class_node.methods.len(), None);
        }

        write_constant_pool(&mut out, &cp)?;
        write_u2(&mut out, class_node.access_flags);
        write_u2(&mut out, class_node.this_class);
        write_u2(&mut out, class_node.super_class);
        write_u2(&mut out, class_node.interface_indices.len() as u16);
        for index in &class_node.interface_indices {
            write_u2(&mut out, *index);
        }

        write_u2(&mut out, class_node.fields.len() as u16);
        for field in &class_node.fields {
            write_field(&mut out, field, &mut cp)?;
        }

        write_u2(&mut out, class_node.methods.len() as u16);
        for (index, method) in class_node.methods.iter().enumerate() {
            let stack_map = precomputed_stack_maps
                .get(index)
                .and_then(|item| item.as_ref());
            let maxs = precomputed_maxs.get(index).and_then(|item| *item);
            write_method(
                &mut out,
                method,
                class_node,
                &mut cp,
                self.options,
                stack_map,
                maxs,
            )?;
        }

        write_u2(&mut out, class_attributes.len() as u16);
        for attr in &class_attributes {
            write_attribute(&mut out, attr, &mut cp, None, self.options, None, None)?;
        }

        Ok(out)
    }
}

fn write_field(
    out: &mut Vec<u8>,
    field: &FieldNode,
    cp: &mut Vec<CpInfo>,
) -> Result<(), ClassWriteError> {
    write_u2(out, field.access_flags);
    write_u2(out, field.name_index);
    write_u2(out, field.descriptor_index);
    write_u2(out, field.attributes.len() as u16);
    for attr in &field.attributes {
        write_attribute(out, attr, cp, None, 0, None, None)?;
    }
    Ok(())
}

fn write_method(
    out: &mut Vec<u8>,
    method: &MethodNode,
    class_node: &ClassNode,
    cp: &mut Vec<CpInfo>,
    options: u32,
    precomputed_stack_map: Option<&Vec<StackMapFrame>>,
    precomputed_maxs: Option<(u16, u16)>,
) -> Result<(), ClassWriteError> {
    write_u2(out, method.access_flags);
    write_u2(out, method.name_index);
    write_u2(out, method.descriptor_index);

    let mut attributes = method.attributes.clone();
    if let Some(code) = &method.code {
        attributes.retain(|attr| !matches!(attr, AttributeInfo::Code(_)));
        attributes.push(AttributeInfo::Code(code.clone()));
    }

    write_u2(out, attributes.len() as u16);
    for attr in &attributes {
        write_attribute(
            out,
            attr,
            cp,
            Some((method, class_node)),
            options,
            precomputed_stack_map,
            precomputed_maxs,
        )?;
    }
    Ok(())
}

fn write_attribute(
    out: &mut Vec<u8>,
    attr: &AttributeInfo,
    cp: &mut Vec<CpInfo>,
    method_ctx: Option<(&MethodNode, &ClassNode)>,
    options: u32,
    precomputed_stack_map: Option<&Vec<StackMapFrame>>,
    precomputed_maxs: Option<(u16, u16)>,
) -> Result<(), ClassWriteError> {
    match attr {
        AttributeInfo::Code(code) => {
            let name_index = ensure_utf8(cp, "Code");
            let mut info = Vec::new();
            let mut code_attributes = code.attributes.clone();
            let (max_stack, max_locals) =
                precomputed_maxs.unwrap_or((code.max_stack, code.max_locals));
            if options & COMPUTE_FRAMES != 0 {
                code_attributes.retain(|item| !matches!(item, AttributeInfo::StackMapTable { .. }));
                let stack_map = if let Some(precomputed) = precomputed_stack_map {
                    precomputed.clone()
                } else {
                    let (method, class_node) = method_ctx.ok_or_else(|| {
                        ClassWriteError::FrameComputation("missing method".to_string())
                    })?;
                    compute_stack_map_table(method, class_node, code, cp, max_locals)?
                };
                code_attributes.push(AttributeInfo::StackMapTable { entries: stack_map });
            }

            write_u2(&mut info, max_stack);
            write_u2(&mut info, max_locals);
            write_u4(&mut info, code.code.len() as u32);
            info.extend_from_slice(&code.code);
            write_u2(&mut info, code.exception_table.len() as u16);
            for entry in &code.exception_table {
                write_exception_table_entry(&mut info, entry);
            }
            write_u2(&mut info, code_attributes.len() as u16);
            for nested in &code_attributes {
                write_attribute(&mut info, nested, cp, method_ctx, options, None, None)?;
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::ConstantValue {
            constantvalue_index,
        } => {
            let name_index = ensure_utf8(cp, "ConstantValue");
            let mut info = Vec::new();
            write_u2(&mut info, *constantvalue_index);
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::Exceptions {
            exception_index_table,
        } => {
            let name_index = ensure_utf8(cp, "Exceptions");
            let mut info = Vec::new();
            write_u2(&mut info, exception_index_table.len() as u16);
            for index in exception_index_table {
                write_u2(&mut info, *index);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::SourceFile { sourcefile_index } => {
            let name_index = ensure_utf8(cp, "SourceFile");
            let mut info = Vec::new();
            write_u2(&mut info, *sourcefile_index);
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::LineNumberTable { entries } => {
            let name_index = ensure_utf8(cp, "LineNumberTable");
            let mut info = Vec::new();
            write_u2(&mut info, entries.len() as u16);
            for entry in entries {
                write_line_number(&mut info, entry);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::LocalVariableTable { entries } => {
            let name_index = ensure_utf8(cp, "LocalVariableTable");
            let mut info = Vec::new();
            write_u2(&mut info, entries.len() as u16);
            for entry in entries {
                write_local_variable(&mut info, entry);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::Signature { signature_index } => {
            let name_index = ensure_utf8(cp, "Signature");
            let mut info = Vec::new();
            write_u2(&mut info, *signature_index);
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::StackMapTable { entries } => {
            let name_index = ensure_utf8(cp, "StackMapTable");
            let mut info = Vec::new();
            write_u2(&mut info, entries.len() as u16);
            for entry in entries {
                write_stack_map_frame(&mut info, entry);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::Deprecated => {
            let name_index = ensure_utf8(cp, "Deprecated");
            write_attribute_with_info(out, name_index, &[]);
        }
        AttributeInfo::Synthetic => {
            let name_index = ensure_utf8(cp, "Synthetic");
            write_attribute_with_info(out, name_index, &[]);
        }
        AttributeInfo::InnerClasses { classes } => {
            let name_index = ensure_utf8(cp, "InnerClasses");
            let mut info = Vec::new();
            write_u2(&mut info, classes.len() as u16);
            for class in classes {
                write_inner_class(&mut info, class);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::EnclosingMethod {
            class_index,
            method_index,
        } => {
            let name_index = ensure_utf8(cp, "EnclosingMethod");
            let mut info = Vec::new();
            write_u2(&mut info, *class_index);
            write_u2(&mut info, *method_index);
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::BootstrapMethods { methods } => {
            let name_index = ensure_utf8(cp, "BootstrapMethods");
            let mut info = Vec::new();
            write_u2(&mut info, methods.len() as u16);
            for method in methods {
                write_bootstrap_method(&mut info, method);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::MethodParameters { parameters } => {
            let name_index = ensure_utf8(cp, "MethodParameters");
            let mut info = Vec::new();
            write_u1(&mut info, parameters.len() as u8);
            for parameter in parameters {
                write_method_parameter(&mut info, parameter);
            }
            write_attribute_with_info(out, name_index, &info);
        }
        AttributeInfo::Unknown { name, info } => {
            let name_index = ensure_utf8(cp, name);
            write_attribute_with_info(out, name_index, info);
        }
    }

    Ok(())
}

fn write_attribute_with_info(out: &mut Vec<u8>, name_index: u16, info: &[u8]) {
    write_u2(out, name_index);
    write_u4(out, info.len() as u32);
    out.extend_from_slice(info);
}

fn write_exception_table_entry(out: &mut Vec<u8>, entry: &ExceptionTableEntry) {
    write_u2(out, entry.start_pc);
    write_u2(out, entry.end_pc);
    write_u2(out, entry.handler_pc);
    write_u2(out, entry.catch_type);
}

fn write_line_number(out: &mut Vec<u8>, entry: &LineNumber) {
    write_u2(out, entry.start_pc);
    write_u2(out, entry.line_number);
}

fn write_local_variable(out: &mut Vec<u8>, entry: &LocalVariable) {
    write_u2(out, entry.start_pc);
    write_u2(out, entry.length);
    write_u2(out, entry.name_index);
    write_u2(out, entry.descriptor_index);
    write_u2(out, entry.index);
}

fn write_inner_class(out: &mut Vec<u8>, entry: &InnerClass) {
    write_u2(out, entry.inner_class_info_index);
    write_u2(out, entry.outer_class_info_index);
    write_u2(out, entry.inner_name_index);
    write_u2(out, entry.inner_class_access_flags);
}

fn write_bootstrap_method(out: &mut Vec<u8>, entry: &BootstrapMethod) {
    write_u2(out, entry.bootstrap_method_ref);
    write_u2(out, entry.bootstrap_arguments.len() as u16);
    for arg in &entry.bootstrap_arguments {
        write_u2(out, *arg);
    }
}

fn write_method_parameter(out: &mut Vec<u8>, entry: &MethodParameter) {
    write_u2(out, entry.name_index);
    write_u2(out, entry.access_flags);
}

fn write_stack_map_frame(out: &mut Vec<u8>, frame: &StackMapFrame) {
    match frame {
        StackMapFrame::SameFrame { offset_delta } => {
            write_u1(out, *offset_delta as u8);
        }
        StackMapFrame::SameLocals1StackItemFrame {
            offset_delta,
            stack,
        } => {
            write_u1(out, (*offset_delta as u8) + 64);
            write_verification_type(out, stack);
        }
        StackMapFrame::SameLocals1StackItemFrameExtended {
            offset_delta,
            stack,
        } => {
            write_u1(out, 247);
            write_u2(out, *offset_delta);
            write_verification_type(out, stack);
        }
        StackMapFrame::ChopFrame { offset_delta, k } => {
            write_u1(out, 251 - *k);
            write_u2(out, *offset_delta);
        }
        StackMapFrame::SameFrameExtended { offset_delta } => {
            write_u1(out, 251);
            write_u2(out, *offset_delta);
        }
        StackMapFrame::AppendFrame {
            offset_delta,
            locals,
        } => {
            write_u1(out, 251 + locals.len() as u8);
            write_u2(out, *offset_delta);
            for local in locals {
                write_verification_type(out, local);
            }
        }
        StackMapFrame::FullFrame {
            offset_delta,
            locals,
            stack,
        } => {
            write_u1(out, 255);
            write_u2(out, *offset_delta);
            write_u2(out, locals.len() as u16);
            for local in locals {
                write_verification_type(out, local);
            }
            write_u2(out, stack.len() as u16);
            for value in stack {
                write_verification_type(out, value);
            }
        }
    }
}

fn write_verification_type(out: &mut Vec<u8>, value: &VerificationTypeInfo) {
    match value {
        VerificationTypeInfo::Top => write_u1(out, 0),
        VerificationTypeInfo::Integer => write_u1(out, 1),
        VerificationTypeInfo::Float => write_u1(out, 2),
        VerificationTypeInfo::Double => write_u1(out, 3),
        VerificationTypeInfo::Long => write_u1(out, 4),
        VerificationTypeInfo::Null => write_u1(out, 5),
        VerificationTypeInfo::UninitializedThis => write_u1(out, 6),
        VerificationTypeInfo::Object { cpool_index } => {
            write_u1(out, 7);
            write_u2(out, *cpool_index);
        }
        VerificationTypeInfo::Uninitialized { offset } => {
            write_u1(out, 8);
            write_u2(out, *offset);
        }
    }
}

fn collect_attribute_names(attributes: &[AttributeInfo], names: &mut Vec<String>) {
    for attr in attributes {
        match attr {
            AttributeInfo::Code(_) => names.push("Code".to_string()),
            AttributeInfo::ConstantValue { .. } => names.push("ConstantValue".to_string()),
            AttributeInfo::Exceptions { .. } => names.push("Exceptions".to_string()),
            AttributeInfo::SourceFile { .. } => names.push("SourceFile".to_string()),
            AttributeInfo::LineNumberTable { .. } => names.push("LineNumberTable".to_string()),
            AttributeInfo::LocalVariableTable { .. } => {
                names.push("LocalVariableTable".to_string())
            }
            AttributeInfo::Signature { .. } => names.push("Signature".to_string()),
            AttributeInfo::StackMapTable { .. } => names.push("StackMapTable".to_string()),
            AttributeInfo::Deprecated => names.push("Deprecated".to_string()),
            AttributeInfo::Synthetic => names.push("Synthetic".to_string()),
            AttributeInfo::InnerClasses { .. } => names.push("InnerClasses".to_string()),
            AttributeInfo::EnclosingMethod { .. } => names.push("EnclosingMethod".to_string()),
            AttributeInfo::BootstrapMethods { .. } => names.push("BootstrapMethods".to_string()),
            AttributeInfo::MethodParameters { .. } => names.push("MethodParameters".to_string()),
            AttributeInfo::Unknown { name, .. } => names.push(name.clone()),
        }
    }
}

fn write_constant_pool(out: &mut Vec<u8>, cp: &[CpInfo]) -> Result<(), ClassWriteError> {
    write_u2(out, cp.len() as u16);
    for entry in cp.iter().skip(1) {
        match entry {
            CpInfo::Unusable => {}
            CpInfo::Utf8(value) => {
                write_u1(out, 1);
                write_u2(out, value.len() as u16);
                out.extend_from_slice(value.as_bytes());
            }
            CpInfo::Integer(value) => {
                write_u1(out, 3);
                write_u4(out, *value as u32);
            }
            CpInfo::Float(value) => {
                write_u1(out, 4);
                write_u4(out, value.to_bits());
            }
            CpInfo::Long(value) => {
                write_u1(out, 5);
                write_u8(out, *value as u64);
            }
            CpInfo::Double(value) => {
                write_u1(out, 6);
                write_u8(out, value.to_bits());
            }
            CpInfo::Class { name_index } => {
                write_u1(out, 7);
                write_u2(out, *name_index);
            }
            CpInfo::String { string_index } => {
                write_u1(out, 8);
                write_u2(out, *string_index);
            }
            CpInfo::Fieldref {
                class_index,
                name_and_type_index,
            } => {
                write_u1(out, 9);
                write_u2(out, *class_index);
                write_u2(out, *name_and_type_index);
            }
            CpInfo::Methodref {
                class_index,
                name_and_type_index,
            } => {
                write_u1(out, 10);
                write_u2(out, *class_index);
                write_u2(out, *name_and_type_index);
            }
            CpInfo::InterfaceMethodref {
                class_index,
                name_and_type_index,
            } => {
                write_u1(out, 11);
                write_u2(out, *class_index);
                write_u2(out, *name_and_type_index);
            }
            CpInfo::NameAndType {
                name_index,
                descriptor_index,
            } => {
                write_u1(out, 12);
                write_u2(out, *name_index);
                write_u2(out, *descriptor_index);
            }
            CpInfo::MethodHandle {
                reference_kind,
                reference_index,
            } => {
                write_u1(out, 15);
                write_u1(out, *reference_kind);
                write_u2(out, *reference_index);
            }
            CpInfo::MethodType { descriptor_index } => {
                write_u1(out, 16);
                write_u2(out, *descriptor_index);
            }
            CpInfo::Dynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            } => {
                write_u1(out, 17);
                write_u2(out, *bootstrap_method_attr_index);
                write_u2(out, *name_and_type_index);
            }
            CpInfo::InvokeDynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            } => {
                write_u1(out, 18);
                write_u2(out, *bootstrap_method_attr_index);
                write_u2(out, *name_and_type_index);
            }
            CpInfo::Module { name_index } => {
                write_u1(out, 19);
                write_u2(out, *name_index);
            }
            CpInfo::Package { name_index } => {
                write_u1(out, 20);
                write_u2(out, *name_index);
            }
        }
    }
    Ok(())
}

fn ensure_utf8(cp: &mut Vec<CpInfo>, value: &str) -> u16 {
    if let Some(index) = cp_find_utf8(cp, value) {
        return index;
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

fn cp_find_utf8(cp: &[CpInfo], value: &str) -> Option<u16> {
    for (index, entry) in cp.iter().enumerate() {
        if let CpInfo::Utf8(existing) = entry
            && existing == value
        {
            return Some(index as u16);
        }
    }
    None
}

fn write_u1(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn write_u2(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u4(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u8(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FrameType {
    Top,
    Integer,
    Float,
    Long,
    Double,
    Null,
    UninitializedThis,
    Object(String),
    Uninitialized(u16),
}

fn compute_stack_map_table(
    method: &MethodNode,
    class_node: &ClassNode,
    code: &CodeAttribute,
    cp: &mut Vec<CpInfo>,
    max_locals: u16,
) -> Result<Vec<StackMapFrame>, ClassWriteError> {
    let insns = parse_instructions(&code.code)?;
    if insns.is_empty() {
        return Ok(Vec::new());
    }

    let mut insn_index = std::collections::HashMap::new();
    for (index, insn) in insns.iter().enumerate() {
        insn_index.insert(insn.offset, index);
    }

    let handlers = build_exception_handlers(code, cp)?;
    let handler_common = handler_common_types(&handlers);
    let mut frames: std::collections::HashMap<u16, FrameState> = std::collections::HashMap::new();
    let mut worklist = std::collections::VecDeque::new();
    let mut in_worklist = std::collections::HashSet::new();

    let mut initial = initial_frame(method, class_node)?;
    pad_locals(&mut initial.locals, max_locals);
    frames.insert(0, initial.clone());
    worklist.push_back(0u16);
    in_worklist.insert(0u16);

    let mut max_iterations = 0usize;
    while let Some(offset) = worklist.pop_front() {
        in_worklist.remove(&offset);
        max_iterations += 1;
        if max_iterations > 100000 {
            return Err(ClassWriteError::FrameComputation(
                "frame analysis exceeded iteration limit".to_string(),
            ));
        }
        let index = *insn_index.get(&offset).ok_or_else(|| {
            ClassWriteError::FrameComputation(format!("missing instruction at {offset}"))
        })?;
        let insn = &insns[index];
        let frame = frames
            .get(&offset)
            .ok_or_else(|| ClassWriteError::FrameComputation(format!("missing frame at {offset}")))?
            .clone();
        let insn1 = &insn;
        let out_frame = execute_instruction(insn1, &frame, class_node, cp)?;

        for succ in instruction_successors(insn) {
            if let Some(next_frame) = merge_frame(&out_frame, frames.get(&succ)) {
                let changed = match frames.get(&succ) {
                    Some(existing) => existing != &next_frame,
                    None => true,
                };
                if changed {
                    frames.insert(succ, next_frame);
                    if in_worklist.insert(succ) {
                        worklist.push_back(succ);
                    }
                }
            }
        }

        for handler in handlers.iter().filter(|item| item.covers(offset)) {
            let mut handler_frame = FrameState {
                locals: frame.locals.clone(),
                stack: Vec::new(),
            };
            let exception_type = handler_common
                .get(&handler.handler_pc)
                .cloned()
                .unwrap_or_else(|| handler.exception_type.clone());
            handler_frame.stack.push(exception_type);
            if let Some(next_frame) = merge_frame(&handler_frame, frames.get(&handler.handler_pc)) {
                let changed = match frames.get(&handler.handler_pc) {
                    Some(existing) => existing != &next_frame,
                    None => true,
                };
                if changed {
                    frames.insert(handler.handler_pc, next_frame);
                    if in_worklist.insert(handler.handler_pc) {
                        worklist.push_back(handler.handler_pc);
                    }
                }
            }
        }
    }

    let mut frame_offsets: Vec<u16> = frames.keys().copied().collect();
    frame_offsets.sort_unstable();
    let mut result = Vec::new();
    let mut previous_offset: i32 = -1;
    for offset in frame_offsets {
        if offset == 0 {
            continue;
        }
        let frame = frames
            .get(&offset)
            .ok_or_else(|| ClassWriteError::FrameComputation(format!("missing frame at {offset}")))?
            .clone();
        let locals = compact_locals(&frame.locals);
        let stack = frame.stack;
        let offset_delta = (offset as i32 - previous_offset - 1) as u16;
        previous_offset = offset as i32;
        let locals_info = locals
            .iter()
            .map(|value| to_verification_type(value, cp))
            .collect();
        let stack_info = stack
            .iter()
            .map(|value| to_verification_type(value, cp))
            .collect();
        result.push(StackMapFrame::FullFrame {
            offset_delta,
            locals: locals_info,
            stack: stack_info,
        });
    }

    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameState {
    locals: Vec<FrameType>,
    stack: Vec<FrameType>,
}

fn merge_frame(frame: &FrameState, existing: Option<&FrameState>) -> Option<FrameState> {
    match existing {
        None => Some(frame.clone()),
        Some(other) => {
            let merged = FrameState {
                locals: merge_vec(&frame.locals, &other.locals),
                stack: merge_vec(&frame.stack, &other.stack),
            };
            if merged == *other { None } else { Some(merged) }
        }
    }
}

fn merge_vec(a: &[FrameType], b: &[FrameType]) -> Vec<FrameType> {
    let len = a.len().max(b.len());
    let mut merged = Vec::with_capacity(len);
    for i in 0..len {
        let left = a.get(i).cloned().unwrap_or(FrameType::Top);
        let right = b.get(i).cloned().unwrap_or(FrameType::Top);
        merged.push(merge_type(&left, &right));
    }
    merged
}

fn merge_type(a: &FrameType, b: &FrameType) -> FrameType {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (FrameType::Top, _) => FrameType::Top,
        (_, FrameType::Top) => FrameType::Top,
        (FrameType::Null, FrameType::Object(name)) | (FrameType::Object(name), FrameType::Null) => {
            FrameType::Object(name.clone())
        }
        (FrameType::Object(left), FrameType::Object(right)) => {
            FrameType::Object(common_superclass(left, right))
        }
        (FrameType::Object(_), FrameType::Uninitialized(_))
        | (FrameType::Uninitialized(_), FrameType::Object(_))
        | (FrameType::UninitializedThis, FrameType::Object(_))
        | (FrameType::Object(_), FrameType::UninitializedThis) => {
            FrameType::Object("java/lang/Object".to_string())
        }
        _ => FrameType::Top,
    }
}

fn common_superclass(left: &str, right: &str) -> String {
    if left == right {
        return left.to_string();
    }
    if left.starts_with('[') || right.starts_with('[') {
        return "java/lang/Object".to_string();
    }

    let mut ancestors = std::collections::HashSet::new();
    let mut current = left;
    ancestors.insert(current.to_string());
    while let Some(parent) = known_superclass(current) {
        if ancestors.insert(parent.to_string()) {
            current = parent;
        } else {
            break;
        }
    }
    ancestors.insert("java/lang/Object".to_string());

    current = right;
    if ancestors.contains(current) {
        return current.to_string();
    }
    while let Some(parent) = known_superclass(current) {
        if ancestors.contains(parent) {
            return parent.to_string();
        }
        current = parent;
    }
    "java/lang/Object".to_string()
}

fn known_superclass(name: &str) -> Option<&'static str> {
    match name {
        "java/lang/Throwable" => Some("java/lang/Object"),
        "java/lang/Exception" => Some("java/lang/Throwable"),
        "java/lang/RuntimeException" => Some("java/lang/Exception"),
        "java/lang/IllegalArgumentException" => Some("java/lang/RuntimeException"),
        "java/lang/IllegalStateException" => Some("java/lang/RuntimeException"),
        "java/security/GeneralSecurityException" => Some("java/lang/Exception"),
        "java/security/NoSuchAlgorithmException" => Some("java/security/GeneralSecurityException"),
        "java/security/InvalidKeyException" => Some("java/security/GeneralSecurityException"),
        "javax/crypto/NoSuchPaddingException" => Some("java/security/GeneralSecurityException"),
        "javax/crypto/IllegalBlockSizeException" => Some("java/security/GeneralSecurityException"),
        "javax/crypto/BadPaddingException" => Some("java/security/GeneralSecurityException"),
        _ => None,
    }
}

fn pad_locals(locals: &mut Vec<FrameType>, max_locals: u16) {
    while locals.len() < max_locals as usize {
        locals.push(FrameType::Top);
    }
}

fn compute_maxs(
    method: &MethodNode,
    class_node: &ClassNode,
    code: &CodeAttribute,
    cp: &[CpInfo],
) -> Result<(u16, u16), ClassWriteError> {
    let insns = parse_instructions(&code.code)?;
    if insns.is_empty() {
        let initial = initial_frame(method, class_node)?;
        return Ok((0, initial.locals.len() as u16));
    }

    let mut insn_index = std::collections::HashMap::new();
    for (index, insn) in insns.iter().enumerate() {
        insn_index.insert(insn.offset, index);
    }

    let handlers = build_exception_handlers(code, cp)?;
    let mut frames: std::collections::HashMap<u16, FrameState> = std::collections::HashMap::new();
    let mut worklist = std::collections::VecDeque::new();
    let mut in_worklist = std::collections::HashSet::new();

    let initial = initial_frame(method, class_node)?;
    frames.insert(0, initial.clone());
    worklist.push_back(0u16);
    in_worklist.insert(0u16);

    let mut max_stack = initial.stack.len();
    let mut max_locals = initial.locals.len();
    let mut max_iterations = 0usize;
    let mut offset_hits: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();
    while let Some(offset) = worklist.pop_front() {
        in_worklist.remove(&offset);
        max_iterations += 1;
        *offset_hits.entry(offset).or_insert(0) += 1;
        if max_iterations > 100000 {
            return Err(ClassWriteError::FrameComputation(
                "frame analysis exceeded iteration limit".to_string(),
            ));
        }
        let index = *insn_index.get(&offset).ok_or_else(|| {
            ClassWriteError::FrameComputation(format!("missing instruction at {offset}"))
        })?;
        let insn = &insns[index];
        let frame = frames.get(&offset).cloned().ok_or_else(|| {
            ClassWriteError::FrameComputation(format!("missing frame at {offset}"))
        })?;
        max_stack = max_stack.max(stack_slots(&frame.stack));
        max_locals = max_locals.max(frame.locals.len());

        let out_frame = execute_instruction(insn, &frame, class_node, cp)?;
        max_stack = max_stack.max(stack_slots(&out_frame.stack));
        max_locals = max_locals.max(out_frame.locals.len());

        for succ in instruction_successors(insn) {
            if let Some(next_frame) = merge_frame(&out_frame, frames.get(&succ)) {
                let changed = match frames.get(&succ) {
                    Some(existing) => existing != &next_frame,
                    None => true,
                };
                if changed {
                    frames.insert(succ, next_frame);
                    if in_worklist.insert(succ) {
                        worklist.push_back(succ);
                    }
                }
            }
        }

        for handler in handlers.iter().filter(|item| item.covers(offset)) {
            let mut handler_frame = FrameState {
                locals: frame.locals.clone(),
                stack: Vec::new(),
            };
            handler_frame.stack.push(handler.exception_type.clone());
            max_stack = max_stack.max(stack_slots(&handler_frame.stack));
            max_locals = max_locals.max(handler_frame.locals.len());
            if let Some(next_frame) = merge_frame(&handler_frame, frames.get(&handler.handler_pc)) {
                let changed = match frames.get(&handler.handler_pc) {
                    Some(existing) => existing != &next_frame,
                    None => true,
                };
                if changed {
                    frames.insert(handler.handler_pc, next_frame);
                    if in_worklist.insert(handler.handler_pc) {
                        worklist.push_back(handler.handler_pc);
                    }
                }
            }
        }
    }

    Ok((max_stack as u16, max_locals as u16))
}

fn stack_slots(stack: &[FrameType]) -> usize {
    let mut slots = 0usize;
    for value in stack {
        slots += if is_category2(value) { 2 } else { 1 };
    }
    slots
}

fn compact_locals(locals: &[FrameType]) -> Vec<FrameType> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < locals.len() {
        match locals[i] {
            FrameType::Top => {
                if i > 0 && matches!(locals[i - 1], FrameType::Long | FrameType::Double) {
                    i += 1;
                    continue;
                }
                out.push(FrameType::Top);
            }
            FrameType::Long | FrameType::Double => {
                out.push(locals[i].clone());
                if i + 1 < locals.len() && matches!(locals[i + 1], FrameType::Top) {
                    i += 1;
                }
            }
            _ => out.push(locals[i].clone()),
        }
        i += 1;
    }

    while matches!(out.last(), Some(FrameType::Top)) {
        out.pop();
    }
    out
}

fn to_verification_type(value: &FrameType, cp: &mut Vec<CpInfo>) -> VerificationTypeInfo {
    match value {
        FrameType::Top => VerificationTypeInfo::Top,
        FrameType::Integer => VerificationTypeInfo::Integer,
        FrameType::Float => VerificationTypeInfo::Float,
        FrameType::Long => VerificationTypeInfo::Long,
        FrameType::Double => VerificationTypeInfo::Double,
        FrameType::Null => VerificationTypeInfo::Null,
        FrameType::UninitializedThis => VerificationTypeInfo::UninitializedThis,
        FrameType::Uninitialized(offset) => VerificationTypeInfo::Uninitialized { offset: *offset },
        FrameType::Object(name) => {
            let index = ensure_class(cp, name);
            VerificationTypeInfo::Object { cpool_index: index }
        }
    }
}

fn initial_frame(
    method: &MethodNode,
    class_node: &ClassNode,
) -> Result<FrameState, ClassWriteError> {
    let mut locals = Vec::new();
    let is_static = method.access_flags & 0x0008 != 0;
    if !is_static {
        if method.name == "<init>" {
            locals.push(FrameType::UninitializedThis);
        } else {
            locals.push(FrameType::Object(class_node.name.clone()));
        }
    }
    let (params, _) = parse_method_descriptor(&method.descriptor)?;
    for param in params {
        push_local_type(&mut locals, param);
    }
    Ok(FrameState {
        locals,
        stack: Vec::new(),
    })
}

fn push_local_type(locals: &mut Vec<FrameType>, ty: FieldType) {
    match ty {
        FieldType::Long => {
            locals.push(FrameType::Long);
            locals.push(FrameType::Top);
        }
        FieldType::Double => {
            locals.push(FrameType::Double);
            locals.push(FrameType::Top);
        }
        FieldType::Float => locals.push(FrameType::Float),
        FieldType::Boolean
        | FieldType::Byte
        | FieldType::Char
        | FieldType::Short
        | FieldType::Int => locals.push(FrameType::Integer),
        FieldType::Object(name) => locals.push(FrameType::Object(name)),
        FieldType::Array(desc) => locals.push(FrameType::Object(desc)),
        FieldType::Void => {}
    }
}

#[derive(Debug, Clone)]
struct ExceptionHandlerInfo {
    start_pc: u16,
    end_pc: u16,
    handler_pc: u16,
    exception_type: FrameType,
}

impl ExceptionHandlerInfo {
    fn covers(&self, offset: u16) -> bool {
        offset >= self.start_pc && offset < self.end_pc
    }
}

fn build_exception_handlers(
    code: &CodeAttribute,
    cp: &[CpInfo],
) -> Result<Vec<ExceptionHandlerInfo>, ClassWriteError> {
    let mut handlers = Vec::new();
    for entry in &code.exception_table {
        let exception_type = if entry.catch_type == 0 {
            FrameType::Object("java/lang/Throwable".to_string())
        } else {
            let class_name = cp_class_name(cp, entry.catch_type)?;
            FrameType::Object(class_name.to_string())
        };
        handlers.push(ExceptionHandlerInfo {
            start_pc: entry.start_pc,
            end_pc: entry.end_pc,
            handler_pc: entry.handler_pc,
            exception_type,
        });
    }
    Ok(handlers)
}

fn handler_common_types(
    handlers: &[ExceptionHandlerInfo],
) -> std::collections::HashMap<u16, FrameType> {
    let mut map: std::collections::HashMap<u16, FrameType> = std::collections::HashMap::new();
    for handler in handlers {
        map.entry(handler.handler_pc)
            .and_modify(|existing| {
                *existing = merge_exception_type(existing, &handler.exception_type);
            })
            .or_insert_with(|| handler.exception_type.clone());
    }
    map
}

fn merge_exception_type(left: &FrameType, right: &FrameType) -> FrameType {
    match (left, right) {
        (FrameType::Object(l), FrameType::Object(r)) => FrameType::Object(common_superclass(l, r)),
        _ if left == right => left.clone(),
        _ => FrameType::Object("java/lang/Object".to_string()),
    }
}

fn dump_frame_debug(
    method: &MethodNode,
    label: &str,
    iterations: usize,
    hits: &std::collections::HashMap<u16, u32>,
) {
    let mut entries: Vec<(u16, u32)> = hits.iter().map(|(k, v)| (*k, *v)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let top = entries.into_iter().take(10).collect::<Vec<_>>();
    eprintln!(
        "[frame-debug] method={}{} label={} iterations={} top_offsets={:?}",
        method.name, method.descriptor, label, iterations, top
    );
}

#[derive(Debug, Clone)]
struct ParsedInstruction {
    offset: u16,
    opcode: u8,
    operand: Operand,
}

#[derive(Debug, Clone)]
enum Operand {
    None,
    I1(i8),
    I2(i16),
    I4(i32),
    U1(u8),
    U2(u16),
    U4(u32),
    Jump(i16),
    JumpWide(i32),
    TableSwitch {
        default_offset: i32,
        low: i32,
        high: i32,
        offsets: Vec<i32>,
    },
    LookupSwitch {
        default_offset: i32,
        pairs: Vec<(i32, i32)>,
    },
    Iinc {
        index: u16,
        increment: i16,
    },
    InvokeInterface {
        index: u16,
        count: u8,
    },
    InvokeDynamic {
        index: u16,
    },
    MultiANewArray {
        index: u16,
        dims: u8,
    },
    Wide {
        opcode: u8,
        index: u16,
        increment: Option<i16>,
    },
}

fn parse_instructions(code: &[u8]) -> Result<Vec<ParsedInstruction>, ClassWriteError> {
    let mut insns = Vec::new();
    let mut pos = 0usize;
    while pos < code.len() {
        let offset = pos as u16;
        let opcode = code[pos];
        pos += 1;
        let operand = match opcode {
            0x10 => {
                let value = read_i1(code, &mut pos)?;
                Operand::I1(value)
            }
            0x11 => Operand::I2(read_i2(code, &mut pos)?),
            0x12 => Operand::U1(read_u1(code, &mut pos)?),
            0x13 | 0x14 => Operand::U2(read_u2(code, &mut pos)?),
            0x15..=0x19 | 0x36..=0x3A | 0xA9 => Operand::U1(read_u1(code, &mut pos)?),
            0x84 => {
                let index = read_u1(code, &mut pos)? as u16;
                let inc = read_i1(code, &mut pos)? as i16;
                Operand::Iinc {
                    index,
                    increment: inc,
                }
            }
            0x99..=0xA8 | 0xC6 | 0xC7 => Operand::Jump(read_i2(code, &mut pos)?),
            0xC8 | 0xC9 => Operand::JumpWide(read_i4(code, &mut pos)?),
            0xAA => {
                let padding = (4 - (pos % 4)) % 4;
                pos += padding;
                let default_offset = read_i4(code, &mut pos)?;
                let low = read_i4(code, &mut pos)?;
                let high = read_i4(code, &mut pos)?;
                let count = if high < low {
                    0
                } else {
                    (high - low + 1) as usize
                };
                let mut offsets = Vec::with_capacity(count);
                for _ in 0..count {
                    offsets.push(read_i4(code, &mut pos)?);
                }
                Operand::TableSwitch {
                    default_offset,
                    low,
                    high,
                    offsets,
                }
            }
            0xAB => {
                let padding = (4 - (pos % 4)) % 4;
                pos += padding;
                let default_offset = read_i4(code, &mut pos)?;
                let npairs = read_i4(code, &mut pos)? as usize;
                let mut pairs = Vec::with_capacity(npairs);
                for _ in 0..npairs {
                    let key = read_i4(code, &mut pos)?;
                    let value = read_i4(code, &mut pos)?;
                    pairs.push((key, value));
                }
                Operand::LookupSwitch {
                    default_offset,
                    pairs,
                }
            }
            0xB2..=0xB8 | 0xBB | 0xBD | 0xC0 | 0xC1 => Operand::U2(read_u2(code, &mut pos)?),
            0xB9 => {
                let index = read_u2(code, &mut pos)?;
                let count = read_u1(code, &mut pos)?;
                let _ = read_u1(code, &mut pos)?;
                Operand::InvokeInterface { index, count }
            }
            0xBA => {
                let index = read_u2(code, &mut pos)?;
                let _ = read_u2(code, &mut pos)?;
                Operand::InvokeDynamic { index }
            }
            0xBC => Operand::U1(read_u1(code, &mut pos)?),
            0xC4 => {
                let wide_opcode = read_u1(code, &mut pos)?;
                match wide_opcode {
                    0x15..=0x19 | 0x36..=0x3A | 0xA9 => {
                        let index = read_u2(code, &mut pos)?;
                        Operand::Wide {
                            opcode: wide_opcode,
                            index,
                            increment: None,
                        }
                    }
                    0x84 => {
                        let index = read_u2(code, &mut pos)?;
                        let increment = read_i2(code, &mut pos)?;
                        Operand::Wide {
                            opcode: wide_opcode,
                            index,
                            increment: Some(increment),
                        }
                    }
                    _ => {
                        return Err(ClassWriteError::InvalidOpcode {
                            opcode: wide_opcode,
                            offset: pos - 1,
                        });
                    }
                }
            }
            0xC5 => {
                let index = read_u2(code, &mut pos)?;
                let dims = read_u1(code, &mut pos)?;
                Operand::MultiANewArray { index, dims }
            }
            _ => Operand::None,
        };
        insns.push(ParsedInstruction {
            offset,
            opcode,
            operand,
        });
    }
    Ok(insns)
}

fn instruction_successors(insn: &ParsedInstruction) -> Vec<u16> {
    let mut successors = Vec::new();
    let next_offset = insn.offset.saturating_add(instruction_length(insn) as u16);
    match insn.opcode {
        0xA7 | 0xC8 => {
            if let Some(target) = jump_target(insn) {
                successors.push(target);
            }
        }
        0xA8 | 0xC9 => {
            if let Some(target) = jump_target(insn) {
                successors.push(target);
            }
            successors.push(next_offset);
        }
        0x99..=0xA6 | 0xC6 | 0xC7 => {
            if let Some(target) = jump_target(insn) {
                successors.push(target);
            }
            successors.push(next_offset);
        }
        0xAA => {
            if let Operand::TableSwitch {
                default_offset,
                offsets,
                ..
            } = &insn.operand
            {
                successors.push((insn.offset as i32 + default_offset) as u16);
                for offset in offsets {
                    successors.push((insn.offset as i32 + *offset) as u16);
                }
            }
        }
        0xAB => {
            if let Operand::LookupSwitch {
                default_offset,
                pairs,
            } = &insn.operand
            {
                successors.push((insn.offset as i32 + default_offset) as u16);
                for (_, offset) in pairs {
                    successors.push((insn.offset as i32 + *offset) as u16);
                }
            }
        }
        0xAC..=0xB1 | 0xBF => {}
        0xC2 | 0xC3 => {
            successors.push(next_offset);
        }
        _ => {
            if next_offset != insn.offset {
                successors.push(next_offset);
            }
        }
    }
    successors
}

fn jump_target(insn: &ParsedInstruction) -> Option<u16> {
    match insn.operand {
        Operand::Jump(offset) => Some((insn.offset as i32 + offset as i32) as u16),
        Operand::JumpWide(offset) => Some((insn.offset as i32 + offset) as u16),
        _ => None,
    }
}

fn instruction_length(insn: &ParsedInstruction) -> usize {
    match &insn.operand {
        Operand::None => 1,
        Operand::I1(_) | Operand::U1(_) => 2,
        Operand::I2(_) | Operand::U2(_) | Operand::Jump(_) => 3,
        Operand::I4(_) | Operand::U4(_) | Operand::JumpWide(_) => 5,
        Operand::Iinc { .. } => 3,
        Operand::InvokeInterface { .. } => 5,
        Operand::InvokeDynamic { .. } => 5,
        Operand::MultiANewArray { .. } => 4,
        Operand::Wide {
            opcode, increment, ..
        } => {
            if *opcode == 0x84 && increment.is_some() {
                6
            } else {
                4
            }
        }
        Operand::TableSwitch { offsets, .. } => {
            1 + switch_padding(insn.offset) + 12 + offsets.len() * 4
        }
        Operand::LookupSwitch { pairs, .. } => {
            1 + switch_padding(insn.offset) + 8 + pairs.len() * 8
        }
    }
}

fn switch_padding(offset: u16) -> usize {
    let pos = (offset as usize + 1) % 4;
    (4 - pos) % 4
}

fn execute_instruction(
    insn: &ParsedInstruction,
    frame: &FrameState,
    class_node: &ClassNode,
    cp: &[CpInfo],
) -> Result<FrameState, ClassWriteError> {
    let mut locals = frame.locals.clone();
    let mut stack = frame.stack.clone();

    let pop = |stack: &mut Vec<FrameType>| {
        stack.pop().ok_or_else(|| {
            ClassWriteError::FrameComputation(format!("stack underflow at {}", insn.offset))
        })
    };

    match insn.opcode {
        0x00 => {}
        0x01 => stack.push(FrameType::Null),
        0x02..=0x08 => stack.push(FrameType::Integer),
        0x09 | 0x0A => stack.push(FrameType::Long),
        0x0B..=0x0D => stack.push(FrameType::Float),
        0x0E | 0x0F => stack.push(FrameType::Double),
        0x10 => stack.push(FrameType::Integer),
        0x11 => stack.push(FrameType::Integer),
        0x12..=0x14 => {
            let ty = ldc_type(insn, cp)?;
            stack.push(ty);
        }
        0x15..=0x19 => {
            let index = var_index(insn)?;
            if let Some(value) = locals.get(index as usize) {
                stack.push(value.clone());
            } else {
                stack.push(FrameType::Top);
            }
        }
        0x1A..=0x1D => stack.push(load_local(
            &locals,
            (insn.opcode - 0x1A) as u16,
            FrameType::Integer,
        )),
        0x1E..=0x21 => stack.push(load_local(
            &locals,
            (insn.opcode - 0x1E) as u16,
            FrameType::Long,
        )),
        0x22..=0x25 => stack.push(load_local(
            &locals,
            (insn.opcode - 0x22) as u16,
            FrameType::Float,
        )),
        0x26..=0x29 => stack.push(load_local(
            &locals,
            (insn.opcode - 0x26) as u16,
            FrameType::Double,
        )),
        0x2A..=0x2D => stack.push(load_local(
            &locals,
            (insn.opcode - 0x2A) as u16,
            FrameType::Object(class_node.name.clone()),
        )),
        0x2E..=0x35 => {
            pop(&mut stack)?;
            let array_ref = pop(&mut stack)?; //fixed: array -> java/lang/Object.
            let ty = match insn.opcode {
                0x2E => FrameType::Integer,
                0x2F => FrameType::Long,
                0x30 => FrameType::Float,
                0x31 => FrameType::Double,
                0x32 => array_element_type(&array_ref)
                    .unwrap_or_else(|| FrameType::Object("java/lang/Object".to_string())),
                0x33..=0x35 => FrameType::Integer,
                _ => FrameType::Top,
            };
            stack.push(ty);
        }
        0x36..=0x3A => {
            let index = var_index(insn)?;
            let value = pop(&mut stack)?;
            store_local(&mut locals, index, value);
        }
        0x3B..=0x3E => {
            let value = pop(&mut stack)?;
            store_local(&mut locals, (insn.opcode - 0x3B) as u16, value);
        }
        0x3F..=0x42 => {
            let value = pop(&mut stack)?;
            store_local(&mut locals, (insn.opcode - 0x3F) as u16, value);
        }
        0x43..=0x46 => {
            let value = pop(&mut stack)?;
            store_local(&mut locals, (insn.opcode - 0x43) as u16, value);
        }
        0x47..=0x4A => {
            let value = pop(&mut stack)?;
            store_local(&mut locals, (insn.opcode - 0x47) as u16, value);
        }
        0x4B..=0x4E => {
            let value = pop(&mut stack)?;
            store_local(&mut locals, (insn.opcode - 0x4B) as u16, value);
        }
        0x4F..=0x56 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
            pop(&mut stack)?;
        }
        0x57 => {
            pop(&mut stack)?;
        }
        0x58 => {
            let v1 = pop(&mut stack)?;
            if is_category2(&v1) {
                return Err(ClassWriteError::FrameComputation(
                    "pop2 category2".to_string(),
                ));
            }
            let v2 = pop(&mut stack)?;
            if is_category2(&v2) {
                return Err(ClassWriteError::FrameComputation(
                    "pop2 invalid".to_string(),
                ));
            }
        }
        0x59 => {
            let v1 = pop(&mut stack)?;
            if is_category2(&v1) {
                return Err(ClassWriteError::FrameComputation(
                    "dup category2".to_string(),
                ));
            }
            stack.push(v1.clone());
            stack.push(v1);
        }
        0x5A => {
            let v1 = pop(&mut stack)?;
            let v2 = pop(&mut stack)?;
            if is_category2(&v1) || is_category2(&v2) {
                return Err(ClassWriteError::FrameComputation("dup_x1".to_string()));
            }
            stack.push(v1.clone());
            stack.push(v2);
            stack.push(v1);
        }
        0x5B => {
            let v1 = pop(&mut stack)?;
            let v2 = pop(&mut stack)?;
            let v3 = pop(&mut stack)?;
            if is_category2(&v1) || is_category2(&v2) {
                return Err(ClassWriteError::FrameComputation("dup_x2".to_string()));
            }
            stack.push(v1.clone());
            stack.push(v3);
            stack.push(v2);
            stack.push(v1);
        }
        0x5C => {
            let v1 = pop(&mut stack)?;
            if is_category2(&v1) {
                stack.push(v1.clone());
                stack.push(v1);
            } else {
                let v2 = pop(&mut stack)?;
                if is_category2(&v2) {
                    return Err(ClassWriteError::FrameComputation("dup2".to_string()));
                }
                stack.push(v2.clone());
                stack.push(v1.clone());
                stack.push(v2);
                stack.push(v1);
            }
        }
        0x5D => {
            let v1 = pop(&mut stack)?;
            if is_category2(&v1) {
                let v2 = pop(&mut stack)?;
                stack.push(v1.clone());
                stack.push(v2);
                stack.push(v1);
            } else {
                let v2 = pop(&mut stack)?;
                let v3 = pop(&mut stack)?;
                stack.push(v2.clone());
                stack.push(v1.clone());
                stack.push(v3);
                stack.push(v2);
                stack.push(v1);
            }
        }
        0x5E => {
            let v1 = pop(&mut stack)?;
            if is_category2(&v1) {
                let v2 = pop(&mut stack)?;
                let v3 = pop(&mut stack)?;
                stack.push(v1.clone());
                stack.push(v3);
                stack.push(v2);
                stack.push(v1);
            } else {
                let v2 = pop(&mut stack)?;
                let v3 = pop(&mut stack)?;
                let v4 = pop(&mut stack)?;
                stack.push(v2.clone());
                stack.push(v1.clone());
                stack.push(v4);
                stack.push(v3);
                stack.push(v2);
                stack.push(v1);
            }
        }
        0x5F => {
            let v1 = pop(&mut stack)?;
            let v2 = pop(&mut stack)?;
            if is_category2(&v1) || is_category2(&v2) {
                return Err(ClassWriteError::FrameComputation("swap".to_string()));
            }
            stack.push(v1);
            stack.push(v2);
        }
        0x60 | 0x64 | 0x68 | 0x6C | 0x70 | 0x78 | 0x7A | 0x7C | 0x7E | 0x80 | 0x82 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x61 | 0x65 | 0x69 | 0x6D | 0x71 | 0x79 | 0x7B | 0x7D | 0x7F | 0x81 | 0x83 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
            stack.push(FrameType::Long);
        }
        0x62 | 0x66 | 0x6A | 0x6E | 0x72 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
            stack.push(FrameType::Float);
        }
        0x63 | 0x67 | 0x6B | 0x6F | 0x73 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
            stack.push(FrameType::Double);
        }
        0x74 => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x75 => {
            pop(&mut stack)?;
            stack.push(FrameType::Long);
        }
        0x76 => {
            pop(&mut stack)?;
            stack.push(FrameType::Float);
        }
        0x77 => {
            pop(&mut stack)?;
            stack.push(FrameType::Double);
        }
        0x84 => {}
        0x85 => {
            pop(&mut stack)?;
            stack.push(FrameType::Long);
        }
        0x86 => {
            pop(&mut stack)?;
            stack.push(FrameType::Float);
        }
        0x87 => {
            pop(&mut stack)?;
            stack.push(FrameType::Double);
        }
        0x88 => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x89 => {
            pop(&mut stack)?;
            stack.push(FrameType::Float);
        }
        0x8A => {
            pop(&mut stack)?;
            stack.push(FrameType::Double);
        }
        0x8B => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x8C => {
            pop(&mut stack)?;
            stack.push(FrameType::Long);
        }
        0x8D => {
            pop(&mut stack)?;
            stack.push(FrameType::Double);
        }
        0x8E => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x8F => {
            pop(&mut stack)?;
            stack.push(FrameType::Long);
        }
        0x90 => {
            pop(&mut stack)?;
            stack.push(FrameType::Float);
        }
        0x91..=0x93 => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x94..=0x98 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0x99..=0x9E | 0xC6 | 0xC7 => {
            pop(&mut stack)?;
        }
        0x9F..=0xA6 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
        }
        0xA7 | 0xC8 => {}
        0xA8 | 0xA9 | 0xC9 => {
            return Err(ClassWriteError::FrameComputation(format!(
                "jsr/ret not supported at {}",
                insn.offset
            )));
        }
        0xAA | 0xAB => {
            pop(&mut stack)?;
        }
        0xAC => {
            pop(&mut stack)?;
        }
        0xAD => {
            pop(&mut stack)?;
        }
        0xAE => {
            pop(&mut stack)?;
        }
        0xAF => {
            pop(&mut stack)?;
        }
        0xB0 => {
            pop(&mut stack)?;
        }
        0xB1 => {}
        0xB2 => {
            let ty = field_type(insn, cp)?;
            stack.push(ty);
        }
        0xB3 => {
            pop(&mut stack)?;
        }
        0xB4 => {
            pop(&mut stack)?;
            let ty = field_type(insn, cp)?;
            stack.push(ty);
        }
        0xB5 => {
            pop(&mut stack)?;
            pop(&mut stack)?;
        }
        0xB6..=0xBA => {
            let (args, ret, owner, is_init) = method_type(insn, cp)?;
            for _ in 0..args.len() {
                pop(&mut stack)?;
            }
            if insn.opcode != 0xB8 && insn.opcode != 0xBA {
                let receiver = pop(&mut stack)?;
                if is_init {
                    let init_owner = if receiver == FrameType::UninitializedThis {
                        class_node.name.clone()
                    } else {
                        owner
                    };
                    initialize_uninitialized(&mut locals, &mut stack, receiver, init_owner);
                }
            }
            if let Some(ret) = ret {
                stack.push(ret);
            }
        }
        0xBB => {
            if let Operand::U2(_index) = insn.operand {
                stack.push(FrameType::Uninitialized(insn.offset));
            }
        }
        0xBC => {
            pop(&mut stack)?;
            if let Operand::U1(atype) = insn.operand {
                let desc = newarray_descriptor(atype)?;
                stack.push(FrameType::Object(desc));
            } else {
                stack.push(FrameType::Object("[I".to_string()));
            }
        }
        0xBD => {
            pop(&mut stack)?;
            if let Operand::U2(index) = insn.operand {
                let class_name = cp_class_name(cp, index)?;
                stack.push(FrameType::Object(format!("[L{class_name};")));
            }
        }
        0xBE => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0xBF => {
            pop(&mut stack)?;
        }
        0xC0 => {
            pop(&mut stack)?;
            if let Operand::U2(index) = insn.operand {
                let class_name = cp_class_name(cp, index)?;
                stack.push(FrameType::Object(class_name.to_string()));
            }
        }
        0xC1 => {
            pop(&mut stack)?;
            stack.push(FrameType::Integer);
        }
        0xC2 | 0xC3 => {
            pop(&mut stack)?;
        }
        0xC4 => {
            if let Operand::Wide {
                opcode,
                index,
                increment,
            } = insn.operand
            {
                match opcode {
                    0x15..=0x19 => {
                        if let Some(value) = locals.get(index as usize) {
                            stack.push(value.clone());
                        }
                    }
                    0x36..=0x3A => {
                        let value = pop(&mut stack)?;
                        store_local(&mut locals, index, value);
                    }
                    0x84 => {
                        let _ = increment;
                    }
                    0xA9 => {}
                    _ => {}
                }
            }
        }
        0xC5 => {
            if let Operand::MultiANewArray { dims, .. } = insn.operand {
                for _ in 0..dims {
                    pop(&mut stack)?;
                }
                if let Operand::MultiANewArray { index, .. } = insn.operand {
                    let desc = cp_class_name(cp, index)?;
                    stack.push(FrameType::Object(desc.to_string()));
                } else {
                    stack.push(FrameType::Object("[Ljava/lang/Object;".to_string()));
                }
            }
        }
        0xCA | 0xFE | 0xFF => {}
        _ => {}
    }

    Ok(FrameState { locals, stack })
}

fn initialize_uninitialized(
    locals: &mut [FrameType],
    stack: &mut [FrameType],
    receiver: FrameType,
    owner: String,
) {
    let init = FrameType::Object(owner);
    for value in locals.iter_mut().chain(stack.iter_mut()) {
        if *value == receiver {
            *value = init.clone();
        }
    }
}

fn is_category2(value: &FrameType) -> bool {
    matches!(value, FrameType::Long | FrameType::Double)
}

fn load_local(locals: &[FrameType], index: u16, fallback: FrameType) -> FrameType {
    locals.get(index as usize).cloned().unwrap_or(fallback)
}

fn store_local(locals: &mut Vec<FrameType>, index: u16, value: FrameType) {
    let idx = index as usize;
    if locals.len() <= idx {
        locals.resize(idx + 1, FrameType::Top);
    }
    locals[idx] = value.clone();
    if is_category2(&value) {
        if locals.len() <= idx + 1 {
            locals.resize(idx + 2, FrameType::Top);
        }
        locals[idx + 1] = FrameType::Top;
    }
}

fn array_element_type(value: &FrameType) -> Option<FrameType> {
    let FrameType::Object(desc) = value else {
        return None;
    };
    if !desc.starts_with('[') {
        return None;
    }
    let element = &desc[1..];
    if element.starts_with('[') {
        return Some(FrameType::Object(element.to_string()));
    }
    let mut chars = element.chars();
    match chars.next() {
        Some('L') => {
            let name = element
                .trim_start_matches('L')
                .trim_end_matches(';')
                .to_string();
            Some(FrameType::Object(name))
        }
        Some('Z') | Some('B') | Some('C') | Some('S') | Some('I') => Some(FrameType::Integer),
        Some('F') => Some(FrameType::Float),
        Some('J') => Some(FrameType::Long),
        Some('D') => Some(FrameType::Double),
        _ => None,
    }
}

fn var_index(insn: &ParsedInstruction) -> Result<u16, ClassWriteError> {
    match insn.operand {
        Operand::U1(value) => Ok(value as u16),
        Operand::Wide { index, .. } => Ok(index),
        _ => Err(ClassWriteError::FrameComputation(format!(
            "missing var index at {}",
            insn.offset
        ))),
    }
}

fn ldc_type(insn: &ParsedInstruction, cp: &[CpInfo]) -> Result<FrameType, ClassWriteError> {
    let index = match insn.operand {
        Operand::U1(value) => value as u16,
        Operand::U2(value) => value,
        _ => {
            return Err(ClassWriteError::FrameComputation(format!(
                "invalid ldc at {}",
                insn.offset
            )));
        }
    };
    match cp.get(index as usize) {
        Some(CpInfo::Integer(_)) => Ok(FrameType::Integer),
        Some(CpInfo::Float(_)) => Ok(FrameType::Float),
        Some(CpInfo::Long(_)) => Ok(FrameType::Long),
        Some(CpInfo::Double(_)) => Ok(FrameType::Double),
        Some(CpInfo::String { .. }) => Ok(FrameType::Object("java/lang/String".to_string())),
        Some(CpInfo::Class { .. }) => Ok(FrameType::Object("java/lang/Class".to_string())),
        Some(CpInfo::MethodType { .. }) => {
            Ok(FrameType::Object("java/lang/invoke/MethodType".to_string()))
        }
        Some(CpInfo::MethodHandle { .. }) => Ok(FrameType::Object(
            "java/lang/invoke/MethodHandle".to_string(),
        )),
        _ => Ok(FrameType::Top),
    }
}

fn field_type(insn: &ParsedInstruction, cp: &[CpInfo]) -> Result<FrameType, ClassWriteError> {
    let index = match insn.operand {
        Operand::U2(value) => value,
        _ => {
            return Err(ClassWriteError::FrameComputation(format!(
                "invalid field operand at {}",
                insn.offset
            )));
        }
    };
    let descriptor = cp_field_descriptor(cp, index)?;
    let field_type = parse_field_descriptor(descriptor)?;
    Ok(field_type_to_frame(field_type))
}

fn method_type(
    insn: &ParsedInstruction,
    cp: &[CpInfo],
) -> Result<(Vec<FieldType>, Option<FrameType>, String, bool), ClassWriteError> {
    let index = match insn.operand {
        Operand::U2(value) => value,
        Operand::InvokeInterface { index, .. } => index,
        Operand::InvokeDynamic { index } => index,
        _ => {
            return Err(ClassWriteError::FrameComputation(format!(
                "invalid method operand at {}",
                insn.offset
            )));
        }
    };
    let (owner, descriptor, name) = cp_method_descriptor(cp, index, insn.opcode)?;
    let (args, ret) = parse_method_descriptor(descriptor)?;
    let ret_frame = match ret {
        FieldType::Void => None,
        other => Some(field_type_to_frame(other)),
    };
    Ok((args, ret_frame, owner.to_string(), name == "<init>"))
}

fn field_type_to_frame(field_type: FieldType) -> FrameType {
    match field_type {
        FieldType::Boolean
        | FieldType::Byte
        | FieldType::Char
        | FieldType::Short
        | FieldType::Int => FrameType::Integer,
        FieldType::Float => FrameType::Float,
        FieldType::Long => FrameType::Long,
        FieldType::Double => FrameType::Double,
        FieldType::Object(name) => FrameType::Object(name),
        FieldType::Array(desc) => FrameType::Object(desc),
        FieldType::Void => FrameType::Top,
    }
}

fn cp_class_name(cp: &[CpInfo], index: u16) -> Result<&str, ClassWriteError> {
    match cp.get(index as usize) {
        Some(CpInfo::Class { name_index }) => match cp.get(*name_index as usize) {
            Some(CpInfo::Utf8(name)) => Ok(name),
            _ => Err(ClassWriteError::InvalidConstantPool),
        },
        _ => Err(ClassWriteError::InvalidConstantPool),
    }
}

fn newarray_descriptor(atype: u8) -> Result<String, ClassWriteError> {
    let desc = match atype {
        4 => "[Z",
        5 => "[C",
        6 => "[F",
        7 => "[D",
        8 => "[B",
        9 => "[S",
        10 => "[I",
        11 => "[J",
        _ => {
            return Err(ClassWriteError::FrameComputation(
                "invalid newarray type".to_string(),
            ));
        }
    };
    Ok(desc.to_string())
}

fn cp_field_descriptor(cp: &[CpInfo], index: u16) -> Result<&str, ClassWriteError> {
    match cp.get(index as usize) {
        Some(CpInfo::Fieldref {
            name_and_type_index,
            ..
        }) => match cp.get(*name_and_type_index as usize) {
            Some(CpInfo::NameAndType {
                descriptor_index, ..
            }) => match cp.get(*descriptor_index as usize) {
                Some(CpInfo::Utf8(desc)) => Ok(desc),
                _ => Err(ClassWriteError::InvalidConstantPool),
            },
            _ => Err(ClassWriteError::InvalidConstantPool),
        },
        _ => Err(ClassWriteError::InvalidConstantPool),
    }
}

fn cp_method_descriptor(
    cp: &[CpInfo],
    index: u16,
    opcode: u8,
) -> Result<(&str, &str, &str), ClassWriteError> {
    match cp.get(index as usize) {
        Some(CpInfo::Methodref {
            class_index,
            name_and_type_index,
        })
        | Some(CpInfo::InterfaceMethodref {
            class_index,
            name_and_type_index,
        }) => {
            let owner = cp_class_name(cp, *class_index)?;
            match cp.get(*name_and_type_index as usize) {
                Some(CpInfo::NameAndType {
                    name_index,
                    descriptor_index,
                }) => {
                    let name = cp_utf8(cp, *name_index)?;
                    let desc = cp_utf8(cp, *descriptor_index)?;
                    Ok((owner, desc, name))
                }
                _ => Err(ClassWriteError::InvalidConstantPool),
            }
        }
        Some(CpInfo::InvokeDynamic {
            name_and_type_index,
            ..
        }) if opcode == 0xBA => match cp.get(*name_and_type_index as usize) {
            Some(CpInfo::NameAndType {
                name_index,
                descriptor_index,
            }) => {
                let name = cp_utf8(cp, *name_index)?;
                let desc = cp_utf8(cp, *descriptor_index)?;
                Ok(("java/lang/Object", desc, name))
            }
            _ => Err(ClassWriteError::InvalidConstantPool),
        },
        _ => Err(ClassWriteError::InvalidConstantPool),
    }
}

fn cp_utf8(cp: &[CpInfo], index: u16) -> Result<&str, ClassWriteError> {
    match cp.get(index as usize) {
        Some(CpInfo::Utf8(value)) => Ok(value.as_str()),
        _ => Err(ClassWriteError::InvalidConstantPool),
    }
}

#[derive(Debug, Clone)]
enum FieldType {
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Float,
    Long,
    Double,
    Object(String),
    Array(String),
    Void,
}

fn parse_field_descriptor(desc: &str) -> Result<FieldType, ClassWriteError> {
    let mut chars = desc.chars().peekable();
    parse_field_type(&mut chars)
}

fn parse_method_descriptor(desc: &str) -> Result<(Vec<FieldType>, FieldType), ClassWriteError> {
    let mut chars = desc.chars().peekable();
    if chars.next() != Some('(') {
        return Err(ClassWriteError::FrameComputation(
            "bad method descriptor".to_string(),
        ));
    }
    let mut params = Vec::new();
    while let Some(&ch) = chars.peek() {
        if ch == ')' {
            chars.next();
            break;
        }
        params.push(parse_field_type(&mut chars)?);
    }
    let ret = parse_return_type(&mut chars)?;
    Ok((params, ret))
}

fn parse_field_type<I>(chars: &mut std::iter::Peekable<I>) -> Result<FieldType, ClassWriteError>
where
    I: Iterator<Item = char>,
{
    match chars.next() {
        Some('Z') => Ok(FieldType::Boolean),
        Some('B') => Ok(FieldType::Byte),
        Some('C') => Ok(FieldType::Char),
        Some('S') => Ok(FieldType::Short),
        Some('I') => Ok(FieldType::Int),
        Some('F') => Ok(FieldType::Float),
        Some('J') => Ok(FieldType::Long),
        Some('D') => Ok(FieldType::Double),
        Some('L') => {
            let mut name = String::new();
            for ch in chars.by_ref() {
                if ch == ';' {
                    break;
                }
                name.push(ch);
            }
            Ok(FieldType::Object(name))
        }
        Some('[') => {
            let mut desc = String::from("[");
            let inner = parse_field_type(chars)?;
            match inner {
                FieldType::Object(name) => {
                    desc.push('L');
                    desc.push_str(&name);
                    desc.push(';');
                }
                FieldType::Boolean => desc.push('Z'),
                FieldType::Byte => desc.push('B'),
                FieldType::Char => desc.push('C'),
                FieldType::Short => desc.push('S'),
                FieldType::Int => desc.push('I'),
                FieldType::Float => desc.push('F'),
                FieldType::Long => desc.push('J'),
                FieldType::Double => desc.push('D'),
                FieldType::Void => {}
                FieldType::Array(inner_desc) => desc.push_str(&inner_desc),
            }
            Ok(FieldType::Array(desc))
        }
        _ => Err(ClassWriteError::FrameComputation(
            "bad field descriptor".to_string(),
        )),
    }
}

fn parse_return_type<I>(chars: &mut std::iter::Peekable<I>) -> Result<FieldType, ClassWriteError>
where
    I: Iterator<Item = char>,
{
    match chars.peek() {
        Some('V') => {
            chars.next();
            Ok(FieldType::Void)
        }
        _ => parse_field_type(chars),
    }
}

fn read_u1(code: &[u8], pos: &mut usize) -> Result<u8, ClassWriteError> {
    if *pos >= code.len() {
        return Err(ClassWriteError::FrameComputation(
            "unexpected eof".to_string(),
        ));
    }
    let value = code[*pos];
    *pos += 1;
    Ok(value)
}

fn read_i1(code: &[u8], pos: &mut usize) -> Result<i8, ClassWriteError> {
    Ok(read_u1(code, pos)? as i8)
}

fn read_u2(code: &[u8], pos: &mut usize) -> Result<u16, ClassWriteError> {
    if *pos + 2 > code.len() {
        return Err(ClassWriteError::FrameComputation(
            "unexpected eof".to_string(),
        ));
    }
    let value = u16::from_be_bytes([code[*pos], code[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

fn read_i2(code: &[u8], pos: &mut usize) -> Result<i16, ClassWriteError> {
    Ok(read_u2(code, pos)? as i16)
}

fn read_i4(code: &[u8], pos: &mut usize) -> Result<i32, ClassWriteError> {
    if *pos + 4 > code.len() {
        return Err(ClassWriteError::FrameComputation(
            "unexpected eof".to_string(),
        ));
    }
    let value = i32::from_be_bytes([code[*pos], code[*pos + 1], code[*pos + 2], code[*pos + 3]]);
    *pos += 4;
    Ok(value)
}
