#!/usr/bin/env python3

"""Opens every generated model enum into a class that holds any value the API serves.

A Java enum cannot hold a value it was not built with, so a value the API added to a tier, a
standing, a license type, a format or an outcome failed the whole call in every installed release
(6.13.0, measured 2026-11-17). Each becomes a final class with a constant per value the spec lists,
compared by value, which fromValue hands back for a known value, so == against a constant still
holds for one. Every enum the generator emits into the model package is an answer's: a request's
closed set is the hand-written io.vpndetection.DatabaseFormat. Run from scripts/generate.sh, and
it prints each class it opens.
"""

import pathlib
import re
import sys

ENUM = re.compile(
    r"^(?P<indent>[ ]*)public enum (?P<name>[A-Za-z_][A-Za-z0-9_]*) \{\n(?P<body>.*?)\n(?P=indent)\}\n",
    re.M | re.S,
)

CONSTANT = re.compile(r'^[ ]*(?P<constant>[A-Z][A-Z0-9_]*)\((?:String\.valueOf\()?"(?P<wire>[^"]*)"\)?\)[,;]', re.M)

OPEN_CLASS = """{i}public {static}final class {name} {{
{constants}
{i}  private static final java.util.List<{name}> KNOWN = java.util.List.of({known});

{i}  private final String value;

{i}  private {name}(String value) {{
{i}    this.value = java.util.Objects.requireNonNull(value, "value");
{i}  }}

{i}  /**
{i}   * The value as the API spells it, a constant's when this release was built with it, and
{i}   * otherwise a new value that equals any other holding the same string.
{i}   */
{i}  @JsonCreator
{i}  public static {name} fromValue(String value) {{
{i}    for ({name} known : KNOWN) {{
{i}      if (known.value.equals(value)) {{
{i}        return known;
{i}      }}
{i}    }}
{i}    return new {name}(value);
{i}  }}

{i}  /** Every value this release was built with, in the spec's order. */
{i}  public static java.util.List<{name}> known() {{
{i}    return KNOWN;
{i}  }}

{i}  /** The value as the API spells it. */
{i}  @JsonValue
{i}  public String getValue() {{
{i}    return value;
{i}  }}

{i}  /**
{i}   * Whether this release was built with the value, one of {{@link #known()}}. A value the API
{i}   * added since reads as itself with this false, rather than failing the call.
{i}   */
{i}  public boolean isKnown() {{
{i}    return KNOWN.contains(this);
{i}  }}

{i}  @Override
{i}  public boolean equals(Object o) {{
{i}    return this == o || (o instanceof {name} && value.equals((({name}) o).value));
{i}  }}

{i}  @Override
{i}  public int hashCode() {{
{i}    return value.hashCode();
{i}  }}

{i}  /** The value as the API spells it. */
{i}  @Override
{i}  public String toString() {{
{i}    return value;
{i}  }}
{extra}{i}}}
"""

# A top-level enum's own query-string form, which the generator gives it and nothing in the client
# calls; kept so the class answers what the enum did.
URL_QUERY = """
{i}  /**
{i}   * Convert the instance into URL query string.
{i}   *
{i}   * @param prefix prefix of the query string
{i}   * @return URL query string
{i}   */
{i}  public String toUrlQueryString(String prefix) {{
{i}    if (prefix == null) {{
{i}      prefix = "";
{i}    }}

{i}    return String.format(java.util.Locale.ROOT, "%s=%s", prefix, this.toString());
{i}  }}
"""


def open_enums(src):
    opened = []

    def open_one(m):
        name, indent = m.group("name"), m.group("indent")
        values = CONSTANT.findall(m.group("body"))
        if not values:
            raise SystemExit(f"enum {name} has no constants to open")
        opened.append(name)
        constants = "".join(
            f'{indent}  /** {{@code {wire}}} */\n'
            f'{indent}  public static final {name} {constant} = new {name}("{wire}");\n\n'
            for constant, wire in values)
        return OPEN_CLASS.format(
            i=indent,
            static="static " if indent else "",
            name=name,
            constants=constants[:-1],
            known=", ".join(constant for constant, _ in values),
            extra=URL_QUERY.format(i=indent) if "toUrlQueryString" in m.group("body") else "",
        )

    return ENUM.sub(open_one, src), opened


def main() -> int:
    total = 0
    for path in sorted(pathlib.Path(sys.argv[1]).glob("*.java")):
        src = path.read_text(encoding="utf-8")
        out, opened = open_enums(src)
        if opened:
            path.write_text(out, encoding="utf-8")
            for name in opened:
                print(f"  open {path.stem}.{name}" if name != path.stem else f"  open {name}")
            total += len(opened)
        if re.search(r"^\s*public enum ", out, re.M):
            raise SystemExit(f"{path.name} still declares an enum this pass could not open")
    print(f"  {total} model enums opened")
    return 0


if __name__ == "__main__":
    sys.exit(main())
