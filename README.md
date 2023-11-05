CNameStyle
==========

Introduction
------------

CNameStyle is a tool for defining and enforcing naming styles in C code.

It only deals with naming symbols, and not with things like spacing/brace/indentation styles (use clang-format or similar).


Setup
-----

This tool is built on libclang, so you'll need LLVM 17.0.4+ installed and libclang.dll available.

You'll also need the Python bindings: these might be installed with llvm in which case you can set your `PYTHONPATH` to include [this folder](https://github.com/llvm/llvm-project/tree/main/clang/bindings/python/clang), otherwise you can install a Python package such as [libclang](https://pypi.org/project/libclang/).


Configuration
-------------

You configure CNameStyle using an ini file, which contains a set of rules.
Each rule looks something like this:

```ini
[Static functions must be PascalCase]
kind = function
visibility = file
rule = ${case:pascal}
```

Each rule has a name (between the `[` and `]`), one or more filters (described later), and a `rule`.

When CNameStyle encounters a name (variable, function, etc) in the file being processed, it searches through the set of rules from top to bottom, looking for one which matches.
A rule matches if all of the filters match.
Once it finds a rule which matches, it tests the `rule` regex to see whether it matches the name, and prints a message if not.

Once it finds a rule which matches it stops, so the order of rules matters!


### `rule`

The `rule` option specifies a regex which must match the name of a symbol which has been matched by the filters in that rule (see below).
The regex is anchored to the start and end of the name, so no need to specify `$` or `^`.

Within the `rule`, various placeholders are available:
 - `${filename}`: The name of the file being processed, without any directory names or file extension
 - `${case:camel}`: A regex which matches `camel_case` variable names
 - `${case:pascal}`: A regex which matches `PascalCase` variable names
 - `${case:snake}`: A regex which matches `snake_case` variable names
 - `${case:upper-snake}`: A regex which matches `UPPER_SNAKE` variable names
 - `${pointer-level}`: See [Pointers](#pointers)
 - `${parent}`, `${parent:upper-snake}`: See [Enums](#enums)


### `kind` filter

The `kind` filter matches on the type of symbol being inspected.
It is a comma-separated list, with the following possible values.
If more than one value is given, only one value has to match for the filter to match.

| Value | Description |
|---    |---          |
| `parameter` | A function parameter |
| `variable` | A local variable (inside a function), or a variable defined at file level (i.e. static/global variables) |
| `function` | A function or function prototype |
| `struct_tag`, `enum_tag`, `union_tag` | The tag given to a struct, enum or union |
| `struct_typedef`, `enum_typedef`, `union_typedef`, `function_typedef`, `scalar_typedef` | The name given to a typedef of a struct, enum, union, function, or scalar |
| `struct_member`, `enum_constant`, `union_member` | The name given to a member of a struct, enum or union |


### `visibility` filter

The `visibility` filter is a comma-separated list of filters on the visibility of the symbol.
If more than one value is given, only one value has to match for the filter to match.

The possibile visibilities are `local`, `file` and `global`.
In C files, things at file scope with static linkage have `file` visibility, while things with external linkage are `global`.
In header files, everything at file scope has `global` visibility.

The sorts of visibility applicable to different `kinds` are given [below](#compatibility).


### Pointers

By default, the `kind` values which support pointers (see [Compatibility](#compatibility)) will match pointer and non-pointer types, e.g. `kind = variable` will match both `int foo` and `int* foo`.

You can specify a `pointer` filter make a rule only match symbols which are/aren't pointers:
  - `pointer = true`: Rule only matches pointers
  - `pointer = false`: Rule only matches non-pointers
  - `pointer = <n>` where `<n>` is an integer: Rule only matches pointers with a number of `*`'s equal to `<n>`

Within a `rule`, the placeholder `${pointer-level}` will contain an integer specifying the pointer level, i.e. the number of `*`'s on the pointer.
This lets you write rules such as:

```ini
[Local variable pointers must start with p]
kind = variable
visibility = local
pointer = true
rule = p{${pointer-level}}_${case:snake}
```

For e.g. a double pointer `int**`, this `rule` will expand to `p{2}_[a-z]([a-z0-9_]*[a-z0-9])?`, enforcing that the variable starts with the letter `p` repeated once per pointer level.


### Prefixes and suffixes

Rules can specify a `prefix` and/or `suffix`, which specifies a regex which must be present at the start/end of any symbols which match the rule.

Rules which do this do not need to specify a `rule`.
If they don't, when rules are processed in top-to-bottom order, processing will not stop at that rule but will continue.
The prefixes/suffixes from all matching rules are concatenated in order.

For example:

```ini
[Global variables start with the file name]
kind = variable
visibility = global
prefix = ${filename}_

[Pointers must begin with p]
kind = variable
pointer = true
prefix = p{${pointer-level}}

[Global variables must be PascalCase]
kind = variable
visibility = global
rule = ${case:pascal}
```

Taken in order, this means that:
 - Non-pointer global variables must have the form `FileName_VariableName`
 - Pointer global variables must have the form `FileName_pVariableName`


## Enums

Enum constants often need to start with the name of the enum, as a form of namespacing.
This can be achieved with the `parent_match` option.

`parent_match` must contain a regex which is matched against the enum name (the tag name if the enum has a tag, or else the typedef name if the enum is anonymous and is typedef'd).
It must contain a capture group called `name`.

If the enum is anonymous, rules which specify `parent_match` will not match.

The value of the `name` capture group is then made available as a placeholder in the `rule`, as:
  - `${parent}`: The actual value matched by the `parent_match` regex capture group
  - `${parent:upper-snake}`: The same value converted to `UPPER_SNAKE_CASE`

For example:

```ini
[Enum members must start with the enum name]
kind = enum_constant
parent_match = (?P<name>.*)_t
rule = ${parent:upper-snake}_${case:upper-snake}
```

Given:

```c
typedef enum
{
    FOO_ONE,
    FOO_TWO
} Foo_t;
```

This will match on the parent name `Foo_t` and extract the `Foo` as a capture group named `name`.
It then applies a rule that all enum constants must be of the form `FOO_${case:upper-snake}`, or `FOO_[A-Z]([A-Z0-9_]*[A-Z0-9])?`.


### `type` filter

The `type` filter is a command-separated list of regexes which are matched on the type of the symbol.
This can be useful if you need to apply different naming schemes to different types of variables.

Note that the type name which the `type` filter is matched against is generated by LLVM, contains things like `*` and `const`, and follows LLVM's conventions for the placement of `*` and `const`.
The easiest thing to do is to run the script with `-v`, which will print the types of symbols found.


### Compatibility

The relationship between `kind`, `visibility`, and pointers is given below.

| `kind` | `visibility` | Supports `pointer` |
|---     |---           | ---                 |
| `parameter` | None | Yes |
| `variable` | `global`, `file`, `local` | Yes |
| `function` | `global`, `file` | No |
| `struct_tag`, `enum_tag`, `union_tag` | `global`, `file` | No |
| `struct_typedef`, `enum_typedef`, `union_typedef`, `function_typedef`, `scalar_typedef` | `global`, `file` | Yes |
| `struct_member`, `union_member` | None | Yes |
| `enum_constant` | `global`, `file` | No |
