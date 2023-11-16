c-name-style 
============

Introduction
------------

c-name-style is a tool for defining and enforcing naming styles in C code.

It only deals with naming symbols, and not with things like spacing/brace/indentation styles (use clang-format or similar).


Setup
-----

This tool is built on libclang, so you'll need LLVM 17.0.4+ installed and libclang.dll available.
You will either need the folder containing libclang.dll (i.g. `llvm/bin`) on your `PATH`, or you can pass the `--libclang` parameter.

You'll also need the Python bindings: these might be installed with LLVM in which case you can set your `PYTHONPATH` to include [this folder](https://github.com/llvm/llvm-project/tree/main/clang/bindings/python/clang), otherwise you can install a Python package such as [libclang](https://pypi.org/project/libclang/).


Configuration
-------------

You configure c-name-style using an ini file, which contains a set of rules.
Each rule looks something like this:

```ini
[Static functions must be PascalCase]
kind = function
visibility = file
rule = ${case:pascal}
```

Each rule has a name (between the `[` and `]`), one or more filters (described later), and a `rule`.

When c-name-style encounters a symbol (variable, function, etc) in the file being processed, it searches through the set of rules from top to bottom, looking for one which matches.
A rule matches if all of the filters match.
Once it finds a rule which matches, it tests the `rule` regex to see whether it matches the symbol's name, and prints a message if not.

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

You can also define your own placeholders, see [Custom Placeholders](#custom-placeholders).


### `allow-rule`

The `allow-rule` option is similar to `rule`, but the behaviour is slightly different.

With `rule`, if the rule matches then the symbol being tested is deemed to be acceptable, and if the rule does not match then an error is printed.
Either way, processing stops.

With `allow-rule`, if the rule matches then the symbol being tested is deemed to be acceptable and processing stops, however if the rule does not match then no error is printed and processing continues to the next rule.

This provides a means of specifying exceptions to rules.


### `kind` filter

The `kind` filter matches on the type of symbol being inspected.
It is a comma-separated list, with the following possible values.
If more than one value is given, only one value has to match for the filter to match.

| Value | Description |
|---    |---          |
| `parameter` | A function parameter |
| `variable` | A local variable (inside a function), or a variable defined at file level (i.e. static/global variables) |
| `function` | A function or function prototype |
| `struct-tag`, `enum-tag`, `union-tag` | The tag given to a struct, enum or union |
| `struct-typedef`, `enum-typedef`, `union-typedef`, `function-typedef`, `scalar-typedef` | The name given to a typedef of a struct, enum, union, function, or scalar |
| `struct-member`, `union-member` | A member of a struct, enum or union |
| `enum-constant` | An enum constant |

You can also use the following shorthands:
 - `tag`: `struct-tag`, `enum-tag` and `union-tag`
 - `typedef`: `struct-typedef`, `enum-typedef`, `union-typedef`, `function-typedef` and `scalar-typedef`
 - `member`: `struct-member` and `union-member`


### `visibility` filter

The `visibility` filter is a comma-separated list of filters on the visibility of the symbol.
If more than one value is given, only one value has to match for the filter to match.

The possibile visibilities are `local`, `file` and `global`.
In C files, symbols at file scope with static linkage have `file` visibility, while symbols with external linkage are `global`.
In header files, everything at file scope has `global` visibility.

The sorts of visibility applicable to different `kinds` are given [below](#compatibility).


### `file` and `not-file` filters

The `file` and `not-files` contain a single regex which is matched against the file path (as passed to c-name-style).
If `file` is specified, then only files whose pathm match this regex will match the rule.
If `not-file` is specified, then only files whose path do not match this regex will match the rule.


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

Rules which do this do not need to specify a `rule` / `allow-rule`.
If they don't, when rules are processed in top-to-bottom order, processing will not stop at that rule but will continue.
The prefixes/suffixes from all matching rules are concatenated in order.

If a rule specifies an empty `prefix` / `suffix`, (i.e. `prefix =` or `suffix =`), then no prefix/suffix rules inherited by previous rules will be applied to that rule, however the will still be applied to the next and subsequent rules.

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

You can also use `suffix` to say that any local, parameter or member can have a "unit suffix", e.g. "_mv", regardless of the other naming rules:

```ini
[Variables may have a unit suffix]
kind = variable, parameter, struct-member, union-member
suffix = (_[a-zA-Z][a-zA-Z0-9]*)?
```


### Enums

Enum constants often need to start with the name of the enum, as a form of namespacing.
This can be achieved with the `parent-match` option.

`parent-match` must contain a regex which is matched against the enum name (the tag name if the enum has a tag, or else the typedef name if the enum is anonymous and is typedef'd).
It must contain a capture group called `name`.

If the enum is anonymous and isn't typedef'd, rules which specify `parent-match` will not match.

The value of the `name` capture group is then made available as a placeholder in the `rule`, as:
  - `${parent}`: The actual value matched by the `parent-match` regex capture group
  - `${parent:upper-snake}`: The same value converted to `UPPER_SNAKE_CASE`

For example:

```ini
[Enum members must start with the enum name]
kind = enum-constant
parent-match = (?P<name>.*)_t
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

The `type` filter is a comma-separated list of regexes which are matched on the type of the symbol.
This can be useful if you need to apply different naming schemes to different types of variables.

Note that the type name which the `type` filter is matched against is generated by LLVM, contains things like `*` and `const`, and follows LLVM's conventions for the placement of `*` and `const`.
The easiest thing to do is to run the script with `-v`, which will print the types of symbols found.


### Custom Placeholders

You can define your own placeholders for use in filters and `rule`s.
Define a `[placeholders]` section in your config file, and all items will be available as `${p:...}`.
For example:

```ini
[placeholders]
my-style = [a-z]*

[Some Rule]
kind = variable
rule = ${p:my-style}
```


### Compatibility

The relationship between `kind`, `visibility`, and pointers is given below.

| `kind` | `visibility` | `pointer` |
|---     |---           | ---       |
| `parameter` | None | Yes |
| `variable` | `global`, `file`, `local` | Yes |
| `function` | `global`, `file` | No |
| `struct-tag`, `enum-tag`, `union-tag` | `global`, `file` | No |
| `struct-typedef`, `enum-typedef`, `union-typedef`, `function-typedef`, `scalar-typedef` | `global`, `file` | Yes |
| `struct-member`, `union-member` | None | Yes |
| `enum-constant` | `global`, `file` | No |

If a filter type is not supported for a particular symbol kind, then the filter is ignored.
For example:

```ini
[Test rule]
kind = parameter, variable
visibility = local
```

This rule will match local variables and all parameters.


Ignoring Violations
-------------------

### Ignore Comments

You can ignore all violations on a line by placing the comment `// c-name-style ignore` (or `/* c-name-style ignore */`) either on the same line or on the line above.

You can also disable c-name-style for a region of code by using `// c-name-style off`, and re-enable later with `// c-name-style on`.


Function prototypes and include paths
-------------------------------------

When c-name-style finds a function definition, it looks in all of the header files in the translation unit to try and find a prototype.
If it finds one, it doesn't analyse the function name.
This means that you won't get violations if you provide the implementation for a function which is defined in another header.

The implication is that you need to analyse source files and header files separately.
If `Foo.c` includes `Foo.h`, you should pass both `Foo.c` and `Foo.h` to c-name-style.

You also need to set up your include paths for this mechanism to work: c-name-style needs to be able to find your headers.
Pass the `-I` flag to add paths to the include path.
