from dataclasses import dataclass
import clang.cindex
from clang.cindex import Config, CursorKind, conf, TypeKind, LinkageKind
from configparser import ConfigParser
import re
from pathlib import Path
from string import Template
from argparse import ArgumentParser
import sys

class MyTemplate(Template):
    braceidpattern = r'(?a:[_a-z][_a-z0-9\-:]*)'

@dataclass
class ConfigRule:
    name: str
    # Name of kind (e.g. variable) -> set of qualifiers (e.g. [static])
    kinds: dict[str, set[str] | None]
    visibility: list[str] | None
    types: list[str] | None
    parent_match: str | None
    prefix: str | None
    suffix: str | None
    rule: str
    
class RuleSet:
    def __init__(self, config: ConfigParser):
        self.rules = []

        for section_name in config.sections():
            section = config[section_name]

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
                    kinds[kind] = (None if qualifier is None else {qualifier})#

            variable_types = section.get("type")
            if variable_types is not None:
                variable_types = [x.strip() for x in variable_types.split(',')]

            parent_match = section.get("parent_match")
            prefix = section.get("prefix")
            suffix = section.get("suffix")

            rule = section.get("rule")
            # It's OK for there to be no rule if there's a prefix or suffix
            if rule is None and prefix is None and suffix is None:
                raise Exception(f"Section {section_name} does not have a 'rule' member")
            
            visibility = section.get("visibility")
            if visibility is not None:
                visibility = [x.strip() for x in visibility.split(',')]

            self.rules.append(ConfigRule(
                name=section_name,
                kinds=kinds,
                visibility=visibility,
                types=variable_types,
                parent_match=parent_match,
                prefix=prefix,
                suffix=suffix,
                rule=rule))

class Processor:
    def __init__(self, rule_set: RuleSet, verbosity: int) -> None:
        self._rule_set = rule_set
        self._verbosity = verbosity
        self._has_failures = False

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
        global_or_file = "global" if is_header else "file"
        if cursor.kind == CursorKind.PARM_DECL:
            return ("parameter", None)
        if cursor.kind == CursorKind.VAR_DECL:
            # In header files, all variables are global
            if is_header:
                return ("variable", "global")
            if cursor.linkage == LinkageKind.INTERNAL:
                return ("variable", "file")
            if cursor.linkage == LinkageKind.NO_LINKAGE:
                return ("variable", "local")
            if cursor.linkage == LinkageKind.EXTERNAL:
                # Both 'int Foo' and 'extern int foo' come up here. We want to exclude 'extern' as people don't have control
                # over those names. People can't control the names of symbols defined elsewhere
                if (conf.lib.clang_Cursor_hasVarDeclExternalStorage(cursor)):
                    return (None, None)
                return ("variable", "global")
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
        if cursor.kind == CursorKind.STRUCT_DECL:
            if self._is_struct_or_enum_unnamed('struct', cursor):
                return (None, None)
            return ("struct_tag", global_or_file)
        if cursor.kind == CursorKind.UNION_DECL:
            if self._is_struct_or_enum_unnamed('union', cursor):
                return (None, None)
            return ("union_tag", global_or_file)
        if cursor.kind == CursorKind.ENUM_DECL:
            if self._is_struct_or_enum_unnamed('enum', cursor):
                return (None, None)
            return ("enum_tag", global_or_file)
        if cursor.kind == CursorKind.TYPEDEF_DECL:
            underlying_type = cursor.underlying_typedef_type.get_canonical()
            # Unwrap any pointers
            while underlying_type.kind == TypeKind.POINTER:
                underlying_type = underlying_type.get_pointee()
            if underlying_type.kind == TypeKind.RECORD:
                # I don't think cindex exposes a way to tell the difference...
                if underlying_type.spelling.startswith("union "):
                    return ("union_typedef", global_or_file)
                return ("struct_typedef", global_or_file)
            if underlying_type.kind == TypeKind.ENUM:
                return ("enum_typedef", global_or_file)
            if underlying_type.kind == TypeKind.FUNCTIONPROTO:
                return ("function_typedef", global_or_file)
            return ("scalar_typedef", global_or_file)
        if cursor.kind == CursorKind.FIELD_DECL:
            # I don't think cindex exposes a way to tell the difference...
            if cursor.semantic_parent.type.spelling.startswith("union "):
                return ("union_member", global_or_file)
            return ("struct_member", None)
        if cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
            return ("enum_member", global_or_file)
        return (None, None)
    

    def _process_node(self, cursor):
        if not conf.lib.clang_Location_isFromMainFile(cursor.location):
            return True
        
        file_path = Path(cursor.location.file.name)
        location = f"{cursor.location.file}:{cursor.location.line}:{cursor.location.column}"
        name = cursor.spelling

        config_kind, visibility = self._get_config_kind(cursor, file_path)

        if config_kind is None:
            return True
        
        substitute_vars = {
            'filename:stem': re.escape(file_path.stem),
            'case:camel': '[a-z][a-zA-Z0-9]*',
            'case:pascal': '[A-Z][a-zA-Z0-9]*',
            'case:snake': '[a-z]([a-z0-9_]*[a-z0-9])?',
            'case:upper-snake': '[A-Z]([A-Z0-9_]*[A-Z0-9])?',
        }

        qualifiers = []
        # If it's a typedef, qualify it as 'pointer' if it typedef's a pointer
        pointer_type = cursor.underlying_typedef_type.get_canonical() if cursor.kind == CursorKind.TYPEDEF_DECL else cursor.type
        if pointer_type.kind == TypeKind.POINTER:
            qualifiers.append("pointer")
            pointer_level = 1
            t = pointer_type.get_pointee()
            while t.kind == TypeKind.POINTER:
                pointer_level += 1
                t = t.get_pointee()
            substitute_vars['pointer-level'] = str(pointer_level)

        if self._verbosity > 0:
            print(f"{location} - Name: '{name}'; kind: {config_kind}; visibility: {visibility}; " +
                  f"qualifiers: '{', '.join(qualifiers)}'; type: '{cursor.type.spelling}'")

        prefix_rules: list[ConfigRule] = []
        suffix_rules: list[ConfigRule] = []
        rule_to_apply = None
        for rule in self._rule_set.rules:
            if config_kind not in rule.kinds:
                if self._verbosity > 2:
                    print(f"  Skip rule '{rule.name}': kind '{config_kind}' not in '{', '.join(rule.kinds.keys())}'")
                continue

            if rule.types is not None and not any(re.fullmatch(x, cursor.type.spelling) for x in rule.types):
                if self._verbosity > 2:
                    print(f"  Skip rule '{rule.name}': type '{cursor.type.spelling}' not in '{', '.join(rule.types)}'")
                continue

            rule_qualifiers = rule.kinds[config_kind]
            if rule_qualifiers is not None and not any(x in rule_qualifiers for x in qualifiers):
                if self._verbosity > 2:
                    print(f"  Skip rule '{rule.name}': qualifiers '{', '.join(qualifiers)}' does not intersect '{', '.join(rule_qualifiers)}'")
                continue

            if visibility is not None and rule.visibility is not None and visibility not in rule.visibility:
                if self._verbosity > 2:
                    print(f"  Skip rule '{rule.name}': visibility '{visibility}' not in '{', '.join(rule.visibility)}'")
                continue

            if rule.prefix is not None:
                prefix_rules.append(rule)
            if rule.suffix is not None:
                suffix_rules.append(rule)

            if rule.rule is not None:
                rule_to_apply = rule
                break

        expanded_prefix = None
        expanded_suffix = None
        name_without_prefix_suffix = name

        if len(prefix_rules) > 0:
            expanded_prefix = MyTemplate("".join(x.prefix for x in prefix_rules)).substitute(substitute_vars)
            if not name.startswith(expanded_prefix):
                print(f"{location} - Name '{name}' is missing required prefix '{expanded_prefix}' from [{', '.join(x.name for x in prefix_rules)}]")
                return False
            name_without_prefix_suffix = name_without_prefix_suffix[len(expanded_prefix):]

        if len(suffix_rules) > 0:
            expanded_suffix = MyTemplate("".join(x.suffix for x in suffix_rules)).substitute(substitute_vars)
            if not name.startswith(expanded_suffix):
                print(f"{location} - Name '{name}' is missing required suffix '{expanded_suffix}' from [{', '.join(x.name for x in suffix_rules)}]")
                return False
            name_without_prefix_suffix = name_without_prefix_suffix[:-len(expanded_suffix)]

        if rule_to_apply is not None:
            if cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
                parent_name = cursor.semantic_parent.spelling
                if rule_to_apply.parent_match is not None:
                    match = re.fullmatch(rule.parent_match, parent_name)
                    if match is None:
                        print(f"WARNING: Rule '{rule_to_apply.name}' parent_match '{rule_to_apply.parent_match}' does not match parent '{parent_name}'")
                    else:
                        try:
                            parent_name = match.group('name')
                        except IndexError:
                            print(f"WARNING: Rule '{rule_to_apply.name}' parent_match '{rule_to_apply.parent_match}' does not have a capture group called 'name'")
                substitute_vars["parent"] = re.escape(parent_name)
                substitute_vars["parent:upper"] = re.escape(re.sub(r'(?<!^)(?=[A-Z])', '_', parent_name).upper())
                
            rule_regex = MyTemplate(rule_to_apply.rule).substitute(substitute_vars)
            if self._verbosity > 1:
                print(f"  Testing rule '{rule_to_apply.name}. Rule: '{rule_to_apply.rule}'; expanded: '{rule_regex}'; stripped name: '{name_without_prefix_suffix}'; vars:")
                for k, v in substitute_vars.items():
                    print(f"   - {k}: {v}")
            if re.fullmatch(rule_regex, name_without_prefix_suffix) is None:
                rule_name = f"'{rule_to_apply.name} ({rule_regex}"
                parts = []
                if expanded_prefix is not None:
                    parts.append(f"prefix '{expanded_prefix}'")
                if expanded_suffix is not None:
                    parts.append(f"suffix '{expanded_suffix}'")
                if len(parts) > 0:
                    rule_name += " with " + ", ".join(parts)
                rule_name += ")"
                print(f"{location} - Name '{name}' fails rule {rule_name}")
                return False
            
        return True
    
    def process(self, cursor) -> bool:
        self._process(cursor)
        return not self._has_failures

    def _process(self, cursor) -> None:
        passed = self._process_node(cursor)
        if not passed:
            self._has_failures = True

        # Don't recurse into typedefs for enums and structs, as that's a duplicate of recursing into the typedef'd type
        # (which means we'll visit all struct/enum members twice)
        if cursor.kind != CursorKind.TYPEDEF_DECL or cursor.underlying_typedef_type.get_canonical().kind not in [TypeKind.RECORD, TypeKind.ENUM]:
            for child in cursor.get_children():
                self._process(child)

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("filename", help="Path to the file to process")
    parser.add_argument("-c", "--config", required=True, help="Path to the configuration file")
    parser.add_argument("--libclang", help="Path to libclang.dll, if it isn't in your PATH")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Print debug messages (specify multiple times for more verbosity)")
    args = parser.parse_args()

    if args.libclang:
        Config.set_library_file(args.libclang)

    config = ConfigParser()
    if len(config.read(args.config)) != 1:
        raise Exception(f"Unable to open config file '{args.config}'")
    
    processor = Processor(RuleSet(config), args.verbose)
    idx = clang.cindex.Index.create()
    tu = idx.parse(args.filename)
    root = tu.cursor
    passed = processor.process(tu.cursor)
    if not passed:
        sys.exit(1)
    