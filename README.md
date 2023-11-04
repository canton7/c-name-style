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

### `kind` filter

The `kind` filter is a comma-separated list, with the following possible values.
If more than one value is given, only one value has to match for the filter to match.

| Value | Description |
|---    |---          |
| `parameter` | A function parameter |
| `variable` | A local variable (inside a function), or a variable defined at file level (i.e. static/global variables) |
| `function` | A function or function prototype, either static, or global |
| `struct_tag`, `enum_tag`, `union_tag` | The tag given to a struct, enum or union |
| `struct_typedef`, `enum_typedef`, `union_typedef` | The name given to a typedef of a struct, enum or union |
| `function_pointer_typedef` | The name given to a typedef to a function pointer |
| `struct_member`, `enum_member`, `union_member` | The name given to a member of a struct, enum or union |

