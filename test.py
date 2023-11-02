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
    visibility: list[str] | None
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
            
            visibility = section.get("visibility")
            if visibility is not None:
                visibility = [x.strip() for x in visibility.split(',')]

            self._rules.append(ConfigRule(name=section_name, kinds=kinds, visibility=visibility, rule=rule))

    # def _get_name(self, cursor):
    #     if cursor.kind == CursorKind.FUNCTION_DECL:
    #         return cursor.spelling
    #     return cursor.displayname

    def _is_struct_or_enum_unnamed(self, struct_or_enum, cursor) -> bool:
        # If a struct/enum is unnamed, clang takes the typedef name as the name.
        # (The C API has methods to query this, but they're not exposed to Python)
        # Therefore we need to look at the tokens to figure out.
        # Look for the 'struct', then the following '{', and see if the typedef name appears in between.
        # (People can do things like 'typedef struct /* foo */ {')
        # We might also see e.g. 'typedef struct T_tag T_t', so there might not be a '{'
        # Look for 'struct/enum' and '{', with the thing that might be the tag name or might be the
        # typedef name in the middle. If we find the 'struct/enum' and '{' but not the name, it's
        # unnamed.
        struct_or_enum = 'struct' if cursor.kind == CursorKind.STRUCT_DECL else 'enum'
        tokens = [x.spelling for x in cursor.get_tokens()]
        try:
            struct_or_enum_pos = tokens.index(struct_or_enum)
            open_brace_pos = tokens.index('{', struct_or_enum_pos)
        except ValueError:
            return False
        try:
            _dummy = tokens.index(cursor.spelling, struct_or_enum_pos, open_brace_pos)
            return False
        except ValueError:
            return True

    # (type, visibility)
    def _get_config_kind(self, cursor, file_path) -> tuple[str | None, str | None]:
        is_header = file_path.suffix in ['.h', '.hpp']
        if cursor.kind == CursorKind.PARM_DECL:
            return ("parameter", None)
        if cursor.kind == CursorKind.VAR_DECL:
            if cursor.linkage == LinkageKind.EXTERNAL:
                return ("variable", "global")
            if cursor.linkage == LinkageKind.INTERNAL:
                return ("variable", "global" if is_header else "file")
            if cursor.linkage == LinkageKind.NO_LINKAGE:
                return ("variable", "local")
            print(f"WARNING: Unexpected linkage {cursor.linkage} for {cursor.spelling}")
            return (None, None)
        if cursor.kind == CursorKind.FUNCTION_DECL:
            # Inline functions in headers are counted as globals
            if cursor.linkage == LinkageKind.EXTERNAL or (conf.lib.clang_Cursor_isFunctionInlined(cursor) and is_header):
                return ("function", "global")
            if cursor.linkage == LinkageKind.INTERNAL:
                return ("function", "file")
            print(f"WARNING: Unexpected linkage {cursor.linkage} for {cursor.spelling}")
            return (None, None)
        # When unions/structs are behind typedefs we can't distinguish them anyway
        if cursor.kind in (CursorKind.STRUCT_DECL, CursorKind.UNION_DECL):
            if self._is_struct_or_enum_unnamed('struct', cursor):
                return (None, None)
            return ("struct_tag", "global" if is_header else "file")
        if cursor.kind == CursorKind.ENUM_DECL:
            if self._is_struct_or_enum_unnamed('enum', cursor):
                return (None, None)
            return ("enum_tag", "global" if is_header else "file")
        if cursor.kind == CursorKind.TYPEDEF_DECL:
            underlying_type = cursor.underlying_typedef_type.get_canonical()
            if underlying_type.kind == TypeKind.RECORD:
                return ("struct_typedef", "global" if is_header else "file")
            if underlying_type.kind == TypeKind.ENUM:
                return ("enum_typedef", "global" if is_header else "file")
            if underlying_type.kind == TypeKind.POINTER:
                if underlying_type.get_pointee().kind == TypeKind.FUNCTIONPROTO:
                    return ("function_pointer_typedef", "global" if is_header else "file")
            return (None, None)
        if cursor.kind == CursorKind.FIELD_DECL:
            return ("struct_member", None)
        if cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
            return ("enum_member", "global" if is_header else "file")
        # if cursor.kind == CursorKind.TYPEDEF_DECL:
        #     print(f"{cursor.spelling} {cursor.underlying_typedef_type.get_canonical().kind}")
        return (None, None)

    def process(self, cursor, containing_type):
        if not conf.lib.clang_Location_isFromMainFile(cursor.location):
            return None
        
        file_path = Path(cursor.location.file.name)

        config_kind, visibility = self._get_config_kind(cursor, file_path)
        # print(f"{cursor.spelling} {config_kind} {visibility}")
        if config_kind is None:
            return None
        
        substitute_vars = {
            'filename:stem': file_path.stem,
            'case:camel': '[a-z][a-zA-Z0-9]*',
            'case:pascal': '[A-Z][a-zA-Z0-9]*',
        }

        # if cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
        #     print(cursor.semantic_parent.spelling)
        
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

            if visibility is not None and rule.visibility is not None and visibility not in rule.visibility:
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

def traverse(cursor, containing_type = None):
    c.process(cursor, containing_type)

    # Enums and structs can be typedef'd. If they are, we visit the decl first, and then the typedef.
    # If an enum/struct is anonymous, we wait until we visit the typedef. Otherwise we visit it now, then don't recurse into the typedef.
    # if cursor.kind in [CursorKind.ENUM_DECL, CursorKind.STRUCT_DECL]:
    #     print(cursor.spelling)

    # When we visit an enum/struct member, we want to remember the name of the containing typedef if any.
    # Annoyingly we visit the enum decl before we visit its typedef, so we don't know ahead of time whether an enum is going to be
    # typedef'd or not.

    # Set containing_typedef when we enter a typedef. If we reach an enum decl and containing_typedef 
    # if cursor.kind == CursorKind.TYPEDEF_DECL and cursor.underlying_typedef_type.get_canonical().kind == TypeKind.ENUM:
    #     containing_type = cursor

    # # If we visit a typedef for an enum, we want to remember the name of the containing type. 

    # # Don't recurse into typedefs for enums and structs, as that's a duplicate of recursing into the typedef'd type
    # # (which means we'll visit all struct/enum members twice)
    if cursor.kind != CursorKind.TYPEDEF_DECL or cursor.underlying_typedef_type.get_canonical().kind not in [TypeKind.RECORD, TypeKind.ENUM]:
        for child in cursor.get_children():
            traverse(child)
    # print('Found %s %s [file=%s, line=%s, col=%s]' % (cursor.kind, cursor.displayname, cursor.location.file, cursor.location.line, cursor.location.column))

    # for child in cursor.get_children():
    #     traverse(child)

    # if node.kind == CursorKind.PARM_DECL:
    #     print(f"{node.spelling} {node.type.kind}")



idx = clang.cindex.Index.create()
tu = idx.parse("Test.h")
root = tu.cursor
traverse(root)


# for x in tu.cursor.get_tokens():
#     print(x.kind)
#     print("  '" + str(x.spelling) + "'")
    