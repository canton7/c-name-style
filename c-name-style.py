#!/usr/bin/env python

import re
import sys
from argparse import ArgumentParser
from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path
from string import Template

from clang.cindex import Index  # type: ignore
from clang.cindex import Config, Cursor, CursorKind, LinkageKind, Token, TokenKind, TranslationUnit, TypeKind, conf


class SubstTemplate(Template):
    braceidpattern = r"(?a:[_a-z][_a-z0-9\-:]*)"


@dataclass
class Rule:
    name: str
    kinds: list[str] | None
    visibility: list[str] | None
    types: list[str] | None
    file: str | None
    not_file: str | None
    pointer: int | bool | None
    parent_match: str | None
    prefix: str | None
    suffix: str | None
    rule: str | None
    allow_rule: str | None


class RuleSet:
    def __init__(self, config: ConfigParser) -> None:
        self.rules: list[Rule] = []
        self.placeholders: dict[str, str] = {}

        for section_name in config.sections():
            section = config[section_name]

            if section_name == "placeholders":
                self.placeholders = {f"p:{k}": v for k, v in config.items(section_name)}
                continue

            kinds = section.get("kind")
            if kinds is not None:
                kinds = [x.strip() for x in kinds.split(",")]

            variable_types = section.get("type")
            if variable_types is not None:
                variable_types = [x.strip() for x in variable_types.split(",")]

            visibility = section.get("visibility")
            if visibility is not None:
                visibility = [x.strip() for x in visibility.split(",")]

            file = section.get("file")
            not_file = section.get("not-file")

            # getboolean parses '1' as true
            try:
                pointer = section.getint("pointer")
            except ValueError:
                pointer = section.getboolean("pointer")

            parent_match = section.get("parent-match")
            prefix = section.get("prefix")
            suffix = section.get("suffix")

            rule = section.get("rule")
            allow_rule = section.get("allow-rule")
            # It's OK for there to be no rule/allow-rule if there's a prefix or suffix
            if rule is None and allow_rule is None and prefix is None and suffix is None:
                raise Exception(f"Section '{section_name}' does not have a 'rule' or 'allow-rule' member")
            if rule is not None and allow_rule is not None:
                raise Exception(f"Section '{section_name}' may not have both a 'rule' and an 'allow-rule")

            self.rules.append(
                Rule(
                    name=section_name,
                    kinds=kinds,
                    visibility=visibility,
                    types=variable_types,
                    file=file,
                    not_file=not_file,
                    pointer=pointer,
                    parent_match=parent_match,
                    prefix=prefix,
                    suffix=suffix,
                    rule=rule,
                    allow_rule=allow_rule,
                )
            )


@dataclass
class IgnoreComment:
    start_line: int
    end_line: int | None
    token: Token
    used: bool = False


class Processor:
    _KIND_EXPANSION = {
        "tag": ["struct-tag", "enum-tag", "union-tag"],
        "typedef": ["struct-typedef", "enum-typedef", "union-typedef", "function-typedef", "scalar-typedef"],
        "member": ["struct-member", "union-member"],
    }

    _COMMENT_REGEX = r"(?://\s*c-name-style\s+(.*))|(?:/\*\s*c-name-style\s+(.*)\*/)"

    def __init__(self, rule_set: RuleSet, verbosity: int) -> None:
        self._rule_set = rule_set
        self._verbosity = verbosity

        self._ignore_comments: dict[str, list[IgnoreComment]] = {}  # filename -> [IgnoreComment]
        self._declarations: dict[str, Cursor] = {}  # {prototype USR: prototype cursor}
        self._has_failures = False

    def _sub_placeholders(self, template: str, placeholders: dict[str, str]) -> str:
        # Do the placeholders section first
        result = template
        if len(self._rule_set.placeholders) > 0:
            result = SubstTemplate(result).safe_substitute(self._rule_set.placeholders)
        result = SubstTemplate(result).safe_substitute(placeholders)
        return result

    def _is_struct_enum_union_unnamed(self, cursor: Cursor) -> bool:
        # If a struct/enum is unnamed, clang takes the typedef name as the name.
        # (The C API has methods to query this, but they're not exposed to Python)
        # Therefore we need to look at the tokens to figure out.
        # Look for the 'struct', then the following '{', and see if the typedef name appears in between.
        # (People can do things like 'typedef struct /* foo */ {')
        # We might also see e.g. 'typedef struct T_tag T_t', so there might not be a '{'
        # Look for 'struct/enum' and '{', with the thing that might be the tag name or might be the
        # typedef name in the middle. If we find the 'struct/enum' and '{' but not the name, it's
        # unnamed.
        if cursor.kind == CursorKind.ENUM_DECL:
            t = "enum"
        elif cursor.kind == CursorKind.STRUCT_DECL:
            t = "struct"
        elif cursor.kind == CursorKind.UNION_DECL:
            t = "union"
        else:
            raise AssertionError()
        tokens = [x.spelling for x in cursor.get_tokens()]
        try:
            type_pos = tokens.index(t)
            open_brace_pos = tokens.index("{", type_pos)
        except ValueError:
            return False
        try:
            _dummy = tokens.index(cursor.spelling, type_pos, open_brace_pos)
            return False
        except ValueError:
            return True

    def _get_cursor_type(self, cursor: Cursor) -> str:
        # If llvm can't resolve a type, it replaces it with 'int'. That's unhelpful when we're just trying to match on its name!
        # We'll take what it gives us, and replace 'int' with the actual name.
        identifier: str | None = None
        for token in cursor.get_tokens():
            if token.kind == TokenKind.IDENTIFIER:
                identifier = token.spelling
                break

        type_name = cursor.type.spelling
        if identifier is not None:
            type_name = type_name.replace("int", identifier)
        return type_name

    def _process_included_node(self, cursor: Cursor) -> None:
        if (
            cursor.kind in (CursorKind.FUNCTION_DECL, CursorKind.STRUCT_DECL, CursorKind.UNION_DECL)
            and not cursor.is_definition()
        ):
            self._declarations[cursor.get_usr()] = cursor

    # (type, visibility)
    def _get_config_kind(self, cursor: Cursor, file_path: Path) -> tuple[str | None, str | None]:
        is_header = file_path.suffix in [".h", ".hpp"]
        global_or_file = "global" if is_header else "file"
        if cursor.kind == CursorKind.PARM_DECL:
            return ("parameter", None)
        if cursor.kind == CursorKind.VAR_DECL:
            if cursor.linkage == LinkageKind.EXTERNAL and conf.lib.clang_Cursor_hasVarDeclExternalStorage(cursor):
                # Both 'int Foo' and 'extern int foo' come up here. We want to exclude 'extern' as people don't have control
                # over those names. People can't control the names of symbols defined elsewhere
                return (None, None)
            if cursor.linkage == LinkageKind.NO_LINKAGE:
                return ("variable", "local")
            # In header files, all variables are global (except those in static inline functions, which have no linkage)
            if is_header:
                return ("variable", "global")
            if cursor.linkage == LinkageKind.INTERNAL:
                return ("variable", "file")
            if cursor.linkage == LinkageKind.EXTERNAL:
                return ("variable", "global")
            print(f"WARNING: Unexpected linkage {cursor.linkage} for {cursor.spelling}")
            return (None, None)
        if cursor.kind == CursorKind.FUNCTION_DECL:
            # Inline functions in headers are counted as globals
            if cursor.linkage == LinkageKind.EXTERNAL or (
                conf.lib.clang_Cursor_isFunctionInlined(cursor) and is_header
            ):
                return ("function", "global")
            if cursor.linkage == LinkageKind.INTERNAL:
                return ("function", "file")
            print(f"WARNING: Unexpected linkage {cursor.linkage} for {cursor.spelling}")
            return (None, None)
        if cursor.kind == CursorKind.STRUCT_DECL:
            if self._is_struct_enum_union_unnamed(cursor):
                return (None, None)
            # Don't want if we see 'struct/union Foo field' inside a struct/union declaration
            if cursor.lexical_parent.type.kind == TypeKind.RECORD:
                return (None, None)
            return ("struct-tag", global_or_file)
        if cursor.kind == CursorKind.UNION_DECL:
            if self._is_struct_enum_union_unnamed(cursor):
                return (None, None)
            # Don't want if we see 'struct/union Foo field' inside a struct/union declaration
            if cursor.lexical_parent.type.kind == TypeKind.RECORD:
                return (None, None)
            return ("union-tag", global_or_file)
        if cursor.kind == CursorKind.ENUM_DECL:
            if self._is_struct_enum_union_unnamed(cursor):
                return (None, None)
            return ("enum-tag", global_or_file)
        if cursor.kind == CursorKind.TYPEDEF_DECL:
            underlying_type = cursor.underlying_typedef_type.get_canonical()
            # Unwrap any pointers
            while underlying_type.kind == TypeKind.POINTER:
                underlying_type = underlying_type.get_pointee()
            if underlying_type.kind == TypeKind.RECORD:
                # I don't think cindex exposes a way to tell the difference...
                if underlying_type.spelling.startswith("union "):
                    return ("union-typedef", global_or_file)
                return ("struct-typedef", global_or_file)
            if underlying_type.kind == TypeKind.ENUM:
                return ("enum-typedef", global_or_file)
            if underlying_type.kind == TypeKind.FUNCTIONPROTO:
                return ("function-typedef", global_or_file)
            return ("scalar-typedef", global_or_file)
        if cursor.kind == CursorKind.FIELD_DECL:
            # I don't think cindex exposes a way to tell the difference...
            if cursor.semantic_parent.type.spelling.startswith("union "):
                return ("union-member", global_or_file)
            return ("struct-member", None)
        if cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
            return ("enum-constant", global_or_file)
        return (None, None)

    def _rule_applies(
        self, cursor: Cursor, rule: Rule, config_kind: str, visibility: str | None, pointer_level: int | None
    ) -> bool:
        rule_kinds = rule.kinds
        if rule_kinds is not None:
            for rule_kind in rule_kinds:
                if rule_kind in Processor._KIND_EXPANSION:
                    rule_kinds.extend(Processor._KIND_EXPANSION[rule_kind])
                    rule_kinds.remove(rule_kind)
            if config_kind not in rule_kinds:
                if self._verbosity > 2:
                    assert rule.kinds is not None
                    print(f"  Skip rule '{rule.name}': kind '{config_kind}' not in '{', '.join(rule.kinds)}'")
                return False

        if (
            pointer_level is not None
            and rule.pointer is not None
            and not (
                (isinstance(rule.pointer, bool) and rule.pointer == (pointer_level > 0))
                or (rule.pointer == pointer_level)
            )
        ):
            if self._verbosity > 2:
                print(f"  Skip rule '{rule.name}': pointer level '{pointer_level}' does not match '{rule.pointer}'")
            return False

        cursor_type = self._get_cursor_type(cursor)
        if rule.types is not None and not any(re.fullmatch(x, cursor_type) for x in rule.types):
            if self._verbosity > 2:
                print(f"  Skip rule '{rule.name}': type '{cursor_type}' not in '{', '.join(rule.types)}'")
            return False

        if rule.file is not None and not re.fullmatch(rule.file, cursor.location.file.name):
            if self._verbosity > 2:
                print(f"  Skip rule '{rule.name}': file '{cursor.location.file.name}' not matched by '{rule.file}'")
            return False

        if rule.not_file is not None and re.fullmatch(rule.not_file, cursor.location.file.name):
            if self._verbosity > 2:
                print(f"  Skip rule '{rule.name}': not-file '{cursor.location.file.name}' matched by '{rule.file}'")
            return False

        if visibility is not None and rule.visibility is not None and visibility not in rule.visibility:
            if self._verbosity > 2:
                print(f"  Skip rule '{rule.name}': visibility '{visibility}' not in '{', '.join(rule.visibility)}'")
            return False

        if (
            rule.parent_match is not None
            and cursor.kind == CursorKind.ENUM_CONSTANT_DECL
            and cursor.semantic_parent.is_anonymous()
        ):
            if self._verbosity > 2:
                print(f"  Skip rule '{rule.name}: parent-match specified but enum is anonymous")
            return False

        return True

    # return: true -> everything is OK, false -> rule failed, None -> continue processing
    def _test_rule(
        self,
        cursor: Cursor,
        rule: Rule,
        prefix_rules: list[Rule],
        suffix_rules: list[Rule],
        location: str,
        substitute_vars: dict[str, str],
    ) -> bool | None:
        ignore_comment = next(
            (
                x
                for x in self._ignore_comments.get(cursor.location.file.name, [])
                if x.start_line <= cursor.location.line and (x.end_line is None or x.end_line >= cursor.location.line)
            ),
            None,
        )
        name = cursor.spelling
        name_without_prefix_suffix = name
        success: bool | None = True

        def test_affix_rules(affix_rules: list[Rule], is_prefix: bool) -> str | None:
            nonlocal name_without_prefix_suffix
            nonlocal success
            expanded_affix = None

            if len(affix_rules) > 0:
                accessor = (lambda x: x.prefix) if is_prefix else (lambda x: x.suffix)
                term = "prefix" if is_prefix else "suffix"
                expanded_affix = "".join(self._sub_placeholders(accessor(x), substitute_vars) for x in affix_rules)  # type: ignore
                regex = "^" + expanded_affix if is_prefix else expanded_affix + "$"
                match = re.search(regex, name_without_prefix_suffix)
                if match is None:
                    if ignore_comment is not None:
                        ignore_comment.used = True
                        if self._verbosity > 1:
                            print(
                                f"    Ignored by comment: Name '{name}' is missing {term} '{expanded_affix}' from [{', '.join(x.name for x in affix_rules)}]"
                            )
                    else:
                        print(
                            f"{location} - Name '{name}' is missing {term} '{expanded_affix}' from [{', '.join(x.name for x in affix_rules)}]"
                        )
                        success = False
                else:
                    name_without_prefix_suffix = (
                        name_without_prefix_suffix[match.end() :]
                        if is_prefix
                        else name_without_prefix_suffix[: match.start()]
                    )

            return expanded_affix

        # If the affix is an empty string, then the accumulated affix doesn't apply to this rule
        expanded_prefix = test_affix_rules(prefix_rules, is_prefix=True) if rule.prefix != "" else None
        expanded_suffix = test_affix_rules(suffix_rules, is_prefix=False) if rule.suffix != "" else None

        if cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
            parent_name = cursor.semantic_parent.spelling
            if rule.parent_match is not None:
                # We checked earlier that the enum isn't anonymous if the rule has parent_match
                assert not cursor.semantic_parent.is_anonymous()
                match = re.fullmatch(rule.parent_match, parent_name)
                if match is None:
                    print(
                        f"{location} - WARNING: Rule '{rule.name}' parent-match '{rule.parent_match}' does not match parent '{parent_name}'"
                    )
                else:
                    try:
                        parent_name = match.group("name")
                    except IndexError:
                        print(
                            f"WARNING: Rule '{rule.name}' parent-match '{rule.rule}' does not have a capture group called 'name'"
                        )
            substitute_vars["parent"] = re.escape(parent_name)
            substitute_vars["parent:upper-snake"] = re.escape(re.sub(r"(?<!^)(?=[A-Z])", "_", parent_name).upper())

        rule_text = rule.rule or rule.allow_rule
        assert rule_text is not None
        rule_regex = self._sub_placeholders(rule_text, substitute_vars)
        rule_name = f"'{rule.name}' ('{rule_regex}'"
        parts = []
        if expanded_prefix is not None:
            parts.append(f"prefix '{expanded_prefix}'")
        if expanded_suffix is not None:
            parts.append(f"suffix '{expanded_suffix}'")
        if len(parts) > 0:
            rule_name += " with " + ", ".join(parts)
        rule_name += ")"

        if self._verbosity > 1:
            print(
                f"  Testing rule {rule_name}. Rule: '{rule_text}' (expanded: '{rule_regex}'); without prefix/suffixes: '{name_without_prefix_suffix}'; placeholders:"
            )
            for k, v in substitute_vars.items():
                print(f"    - {k}: {v}")
        if re.fullmatch(rule_regex, name_without_prefix_suffix) is None:
            if ignore_comment is not None:
                ignore_comment.used = True
                if self._verbosity > 1:
                    print(f"    Ignored by comment: '{name}' fails rule {rule_name} but was ignored by a comment")
            # rule: return true or false. allow_rule: return true or None
            elif rule.rule is not None:
                print(f"{location} - Name '{name}' fails rule {rule_name}")
                success = False
            else:
                assert rule.allow_rule is not None
                if self._verbosity > 1:
                    print(f"{location} - Name '{name}' fails allow-rule {rule_name}. Continuing...")
                success = None
        elif self._verbosity > 1:
            print(f"    Name '{name}' allowed by rule '{rule.name}'")

        return success

    def _process_node(self, cursor: Cursor) -> bool:
        if cursor.kind == CursorKind.TRANSLATION_UNIT:
            return True

        # There might be prototypes earlier in the file. We only want to warn once
        self._process_included_node(cursor)
        if not conf.lib.clang_Location_isFromMainFile(cursor.location):
            return True

        file_path = Path(cursor.location.file.name)

        location = f"{cursor.location.file}:{cursor.location.line}:{cursor.location.column}"

        # Ignore function/struct/union definitions that we've found the prototype / previous declaration for
        # (If someone types 'struct Name_Foo_tag' in a header, then 'struct Name_Foo_tag { .. }' in the source file, we don't want to warn for the source file)
        if (
            cursor.kind in (CursorKind.FUNCTION_DECL, CursorKind.STRUCT_DECL, CursorKind.UNION_DECL)
            and cursor.is_definition()
            and cursor.get_usr() in self._declarations
        ):
            if self._verbosity > 1:
                declaration = self._declarations[cursor.get_usr()].location
                print(
                    f"{location} - Skip '{cursor.spelling}' as a declaration found at {declaration.file.name}:{declaration.line}:{declaration.column}"
                )
            return True

        config_kind, visibility = self._get_config_kind(cursor, file_path)

        if config_kind is None:
            return True

        name = cursor.spelling

        pointer_level = None
        if cursor.kind in [CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.TYPEDEF_DECL, CursorKind.FIELD_DECL]:
            pointer_level = 0
            # If it's a typedef, qualify it as 'pointer' if it typedef's a pointer
            pointer_type = (
                cursor.underlying_typedef_type.get_canonical()
                if cursor.kind == CursorKind.TYPEDEF_DECL
                else cursor.type
            )
            while pointer_type.kind == TypeKind.POINTER:
                pointer_level += 1
                pointer_type = pointer_type.get_pointee()

        substitute_vars = {
            "filename": re.escape(file_path.stem),
            "case:camel": "[a-z][a-zA-Z0-9]*",
            "case:pascal": "[A-Z][a-zA-Z0-9]*",
            "case:snake": "[a-z]([a-z0-9_]*[a-z0-9])?",
            "case:upper-snake": "[A-Z]([A-Z0-9_]*[A-Z0-9])?",
            "pointer-level": str(pointer_level),
        }

        if self._verbosity > 0:
            cursor_type = self._get_cursor_type(cursor)
            print(
                f"{location} - Name: '{name}'; kind: {config_kind}; visibility: {visibility}; "
                + f"pointer: {pointer_level}; type: '{cursor_type}'"
            )

        prefix_rules: list[Rule] = []
        suffix_rules: list[Rule] = []
        for rule in self._rule_set.rules:
            if not self._rule_applies(cursor, rule, config_kind, visibility, pointer_level):
                continue

            # Don't process if empty string
            if rule.prefix:
                if self._verbosity > 1:
                    print(f"  Prefix rule '{rule.name}'; prefix: '{rule.prefix}'")
                prefix_rules.append(rule)
            if rule.suffix:
                if self._verbosity > 1:
                    print(f"  Suffix rule '{rule.name}; suffix: '{rule.suffix}'")
                suffix_rules.append(rule)

            if rule.rule is not None or rule.allow_rule is not None:
                result = self._test_rule(cursor, rule, prefix_rules, suffix_rules, location, substitute_vars)
                if result is not None:
                    return result

        return True

    def process(self, translation_unit: TranslationUnit) -> bool:
        self._process_tokens(translation_unit)
        self._process(translation_unit.cursor)

        for ignore_comments in self._ignore_comments.values():
            for ignore_comment in ignore_comments:
                if not ignore_comment.used:
                    location = ignore_comment.token.location
                    print(f"WARNING: {location.file.name}:{location.line}:{location.column} - ignore comment not used")

        return not self._has_failures

    def _process_tokens(self, translation_unit: TranslationUnit) -> None:
        current_off_comment: IgnoreComment | None = None
        for token in translation_unit.cursor.get_tokens():
            if token.kind == TokenKind.COMMENT:
                match = re.fullmatch(Processor._COMMENT_REGEX, token.spelling)
                if match is not None:
                    value = (match.group(1) or match.group(2)).strip()
                    location = f"{token.location.file}:{token.location.line}:{token.location.column}"
                    if value == "ignore":
                        line = token.location.line
                        span_before = translation_unit.get_extent(token.location.file.name, ((line, 1), (line, 1)))
                        tokens_before = list(translation_unit.get_tokens(extent=span_before))
                        if len(tokens_before) == 0 or (
                            len(tokens_before) == 1 and tokens_before[0].extent == token.extent
                        ):
                            line += 1  # Nothing before it
                        self._ignore_comments.setdefault(token.location.file.name, []).append(
                            IgnoreComment(start_line=line, end_line=line, token=token)
                        )
                    elif value == "off":
                        current_off_comment = IgnoreComment(start_line=token.location.line, end_line=None, token=token)
                        self._ignore_comments.setdefault(token.location.file.name, []).append(current_off_comment)
                    elif value == "on":
                        matching_off = current_off_comment
                        current_off_comment = None  # Either we've closed it, or we've moved onto another file
                        if (
                            matching_off is not None
                            and matching_off.token.location.file.name != token.location.file.name
                        ):
                            matching_off = None
                        if matching_off is None:
                            print(
                                f"WARNING: {location} - '{token.spelling}' without a corresponding 'c-name-style off'"
                            )
                        else:
                            matching_off.end_line = token.location.line
                    else:
                        print(f"WARNING: {location} - Unrecognised comment '{token.spelling}'")

    def _process(self, cursor: Cursor) -> None:
        passed = self._process_node(cursor)
        if not passed:
            self._has_failures = True

        # Don't recurse into typedefs for enums and structs, as that's a duplicate of recursing into the typedef'd type
        # (which means we'll visit all struct/enum members twice).
        # Also don't recurse into struct/union members, otherwise we'll complain if we find a member which is a type we don't like
        is_enum_record_typedef = (
            cursor.kind == CursorKind.TYPEDEF_DECL
            and cursor.underlying_typedef_type.get_canonical().kind in (TypeKind.RECORD, TypeKind.ENUM)
        )
        if not is_enum_record_typedef:
            for child in cursor.get_children():
                self._process(child)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("filename", help="Path to the file to process")
    parser.add_argument("-c", "--config", required=True, help="Path to the configuration file")
    parser.add_argument("--libclang", help="Path to libclang.dll, if it isn't in your PATH")
    parser.add_argument("-I", help="Include path (specify multiple times)", dest="include", action="append", default=[])
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Print debug messages (specify multiple times for more verbosity)",
    )
    args = parser.parse_args()

    if args.libclang:
        Config.set_library_file(args.libclang)

    config = ConfigParser()
    if len(config.read(args.config)) != 1:
        raise Exception(f"Unable to open config file '{args.config}'")

    processor = Processor(RuleSet(config), args.verbose)
    index = Index.create()
    translation_unit = index.parse(args.filename, args=[f"-I{x}" for x in args.include])
    passed = processor.process(translation_unit)
    if not passed:
        sys.exit(1)
