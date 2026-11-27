"""Writes the copy of the pinned spec the generator reads, with the edits that keep a public type.

A re-pin that would move a member's requirement (a member the models have always marked required,
which the spec lets a plan leave out) is generated from this copy, so it moves only at a major due
for another reason. The pin itself stays byte-equal to the published spec. Each edit targets one
member of one schema and fails when it matches nothing, so a spec that drops or moves the member
stops the generation rather than leaving a dead edit behind.

Usage: keep_types.py <pinned spec> <edited copy>
"""

import re
import sys

# Members the spec listed as required through 2026.11.25 and no longer lists from 2026.11.26, since
# a plan without them leaves them out. The model keeps each required, so RequiredMembers.PLAN_MEMBERS
# lists them: the decoder accepts an answer without one, and a test holds the two tables together.
PLAN_MEMBERS = [
    ("Asn", "type"),
]


def block(lines, start, indent):
    """The index past the last line of the block opened at `start`, whose children sit deeper than `indent`."""
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.strip() and len(line) - len(line.lstrip(" ")) <= indent:
            break
        end += 1
    return end


def find(lines, lo, hi, pattern):
    for i in range(lo, hi):
        if re.fullmatch(pattern, lines[i]):
            return i
    return None


def member_at(lines, schema, member):
    """The schema's start and the index of the line opening its property `member`."""
    schemas = find(lines, 0, len(lines), r"  schemas:")
    if schemas is None:
        sys.exit("keep_types: the spec has no components.schemas")
    at = find(lines, schemas + 1, block(lines, schemas, 2), r"    " + re.escape(schema) + r":")
    if at is None:
        sys.exit(f"keep_types: no schema {schema}")
    props = find(lines, at + 1, block(lines, at, 4), r"      properties:")
    if props is None:
        sys.exit(f"keep_types: {schema} has no properties")
    prop = find(lines, props + 1, block(lines, props, 6), r"        " + re.escape(member) + r":")
    if prop is None:
        sys.exit(f"keep_types: {schema} has no {member}")
    return at, prop


def restore_required(lines, schema, member):
    at, _ = member_at(lines, schema, member)
    end = block(lines, at, 4)
    required = find(lines, at + 1, end, r"      required:")
    if required is None:
        sys.exit(f"keep_types: {schema} has no required list")
    last = required
    while last + 1 < end and re.fullmatch(r"        - .*", lines[last + 1]):
        last += 1
        if lines[last] == f"        - {member}":
            sys.exit(f"keep_types: {schema}.{member} is required again; drop its edit")
    lines.insert(last + 1, f"        - {member}")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as f:
        lines = f.read().split("\n")
    for schema, member in PLAN_MEMBERS:
        restore_required(lines, schema, member)
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
