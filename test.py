from dataclasses import dataclass
import clang.cindex
from clang.cindex import Config, CursorKind, StorageClass, conf, TypeKind, LinkageKind
from configparser import ConfigParser
import re
from pathlib import Path
from string import Template

config = ConfigParser()
config.read("config.ini")

class MyTemplate(Template):
    braceidpattern = r'(?a:[_a-z][_a-z0-9:]*)'

@dataclass
class ConfigRuleKind:
    kind: str
    qualifier: str | None

@dataclass
class ConfigRule:
    name: str
    # Name of kind (e.g. variable) -> set of qualifiers (e.g. [static])
    kinds: dict[str, set[str] | None]
    is_pointer: bool | None
    rule: str
    
class NameConfig:
    # _TYPE_LOOKUP = {
    #     CursorKind.VAR_DECL: "variable",
    #     CursorKind.PARM_DECL: "parameter",
    #     CursorKind.FUNCTION_DECL: "function",
    # }
    # _STORAGE_LOOKUP = {
    #     StorageClass.STATIC: "static"
    # }

    def __init__(self, config: ConfigParser):
        self._rules = []
        self._exclude_pointer_types = []

        for section_name in config.sections():
            section = config[section_name]

            if section_name == "options":
                self._exclude_pointer_types.extend(x.strip() for x in section.get("exclude_pointer_types", "").split(', '))
                continue

            section_kinds = section.get("kind")
            if section_kinds is None:
                raise Exception(f"Section '{section_name}' does not have a 'kind' member")
            
            kinds = {}
            for section_kind in section_kinds.split(', '):
                section_kind = section_kind.strip()
                parts = section_kind.split(':', maxsplit=1)
                kind = parts[0]
                qualifier = parts[1] if len(parts) > 1 else None
                if kind in kinds:
                    if (qualifier is None) != (kinds[kind] is not None):
                        extra_qualifier = qualifier if qualifier is not None else kinds[kind]
                        raise Exception(f"Section '{section_name}': kind '{kind}:{extra_qualifier}' is redundant")
                    if kinds[kind] is not None:
                        kinds[kind].add(qualifier)
                else:
                    kinds[kind] = (None if qualifier is None else {qualifier})

            rule = section.get("rule")
            if rule is None:
                raise Exception(f"Section {section_name} does not have a 'rule' member")
            is_pointer = section.getboolean("pointer", None)

            self._rules.append(ConfigRule(name=section_name, kinds=kinds, is_pointer=is_pointer, rule=rule))

    # def _get_name(self, cursor):
    #     if cursor.kind == CursorKind.FUNCTION_DECL:
    #         return cursor.spelling
    #     return cursor.displayname

    def _get_config_kind(self, cursor, file_path):
        is_header = file_path.suffix in ['.h', '.hpp']
        if cursor.kind == CursorKind.PARM_DECL:
            return "parameter"
        if cursor.kind == CursorKind.VAR_DECL:
            if cursor.linkage == LinkageKind.EXTERNAL:
                return "global_variable"
            if cursor.linkage == LinkageKind.INTERNAL:
                return "static_variable"
            if cursor.linkage == LinkageKind.NO_LINKAGE:
                return "local_variable"
            print(f"WARNING: Unexpected linkage {cursor.linkage} for {cursor.spelling}")
            return None
        if cursor.kind == CursorKind.FUNCTION_DECL:
            # Inline functions in headers are counted as globals
            if cursor.linkage == LinkageKind.EXTERNAL or (conf.lib.clang_Cursor_isFunctionInlined(cursor) and is_header):
                return "global_function"
            if cursor.linkage == LinkageKind.INTERNAL:
                return "static_function"
            print(f"WARNING: Unexpected linkage {cursor.linkage} for {cursor.spelling}")
            return None
        if cursor.kind == CursorKind.STRUCT_DECL:
            return "struct_tag"
        if cursor.kind == CursorKind.ENUM_DECL:
            return "enum_tag"
        if cursor.kind == CursorKind.TYPEDEF_DECL:
            underlying_type = cursor.underlying_typedef_type.get_canonical()
            if underlying_type.kind == TypeKind.RECORD:
                return "struct_typedef"
            if underlying_type.kind == TypeKind.ENUM:
                return "enum_typedef"
            if underlying_type.kind == TypeKind.POINTER:
                if underlying_type.get_pointee().kind == TypeKind.FUNCTIONPROTO:
                    return "function_pointer_typedef"
            return None
        if cursor.kind == CursorKind.FIELD_DECL:
            return "struct_member"
        # if cursor.kind == CursorKind.TYPEDEF_DECL:
        #     print(f"{cursor.spelling} {cursor.underlying_typedef_type.get_canonical().kind}")
        return None

    def find_rule(self, cursor):
        if not conf.lib.clang_Location_isFromMainFile(cursor.location):
            return None
        
        file_path = Path(cursor.location.file.name)

        config_kind = self._get_config_kind(cursor, file_path)
        if config_kind is None:
            return None
        
        substitute_vars = {
            'filename:stem': file_path.stem,
            'case:camel': '[a-z][a-zA-Z0-9]*',
            'case:pascal': '[A-Z][a-zA-Z0-9]*',
        }
        
        for rule in self._rules:
            if config_kind not in rule.kinds:
                continue

            rule_qualifiers = rule.kinds[config_kind]
            if rule_qualifiers is not None:
                qualifiers = []
                if cursor.kind in [CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL] and cursor.type.kind == TypeKind.POINTER:
                    if cursor.type.get_pointee().spelling not in self._exclude_pointer_types:
                        qualifiers.append("pointer")
                
                if not any(x in rule_qualifiers for x in qualifiers):
                    continue

            # print(cursor.__dir__())
            name = cursor.spelling
            # print(f"Matching rule: {cursor}, {repr(rule)} {cursor.displayname}")
            rule_regex = MyTemplate(rule.rule).substitute(substitute_vars)
            if re.fullmatch(rule_regex, name) is None:
                print(f"{cursor.location.file}:{cursor.location.line}:{cursor.location.column} - Name '{name}' fails rule '{rule.name}' ({rule.rule})")
            break

            


c = NameConfig(config)

Config.set_library_file(r"C:\Program Files\LLVM\bin\libclang.dll")

def traverse(node):
    c.find_rule(node)

    # Don't recurse into typedefs for enums and structs, as that's a duplicate of recursing into the typedef'd type
    # (which means we'll visit all struct/enum members twice)
    if node.kind != CursorKind.TYPEDEF_DECL or node.underlying_typedef_type.get_canonical() not in [TypeKind.RECORD, TypeKind.ENUM]:
        for child in node.get_children():
            traverse(child)

    # if node.kind == CursorKind.PARM_DECL:
    #     print(f"{node.spelling} {node.type.kind}")

    # print('Found %s %s [file=%s, line=%s, col=%s]' % (node.kind, node.displayname, node.location.file, node.location.line, node.location.column))


idx = clang.cindex.Index.create()
tu = idx.parse("StepperMotor/StepperMotorDriver.h")
root = tu.cursor
traverse(root)


# for x in tu.cursor.get_tokens():
#     print(x.kind)
#     print("  '" + str(x.spelling) + "'")
    