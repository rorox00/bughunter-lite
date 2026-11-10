#!/usr/bin/env python3
# scripts/lint_skills.py
"""Portability linter for bughunter-lite skills.

For each skills/<dir> (or the directories given as arguments), parse the
SKILL.md YAML frontmatter and enforce the rules that keep a skill portable and
auto-installable: a valid name that equals its directory, a present and bounded
description, and a body that is not absurdly long. Stdlib only.
"""

import os
import re
import sys

NAME_RE = re.compile(r"^[a-z0-9-]+$")
MAX_NAME = 64
MAX_DESC = 1024
MAX_BODY = 500

_BLOCK_INDICATORS = {">", "|", ">-", "|-", ">+", "|+"}


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def parse_frontmatter(text):
    """Return (dict, body_start_line) or (None, 0) if there is no frontmatter."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, 0
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return None, 0

    fm = lines[1:end]
    data = {}
    i = 0
    while i < len(fm):
        m = re.match(r"^([A-Za-z0-9_-]+):(.*)$", fm[i])
        if not m:
            i += 1
            continue
        key, rest = m.group(1), m.group(2).strip()

        if rest in _BLOCK_INDICATORS:
            # Folded (>) or literal (|) block scalar: gather indented lines.
            i += 1
            block = []
            while i < len(fm) and (fm[i].strip() == "" or fm[i][:1] in (" ", "\t")):
                block.append(fm[i].strip())
                i += 1
            sep = "\n" if rest[0] == "|" else " "
            data[key] = sep.join(block).strip()
            continue

        # Inline scalar, possibly continued on more-indented plain lines.
        val = _unquote(rest)
        i += 1
        cont = []
        while i < len(fm) and fm[i][:1] in (" ", "\t") and fm[i].strip():
            cont.append(fm[i].strip())
            i += 1
        if cont:
            val = (val + " " + " ".join(cont)).strip()
        data[key] = val

    return data, end + 1


def lint_dir(d):
    """Return a list of error strings for one skill directory (empty if clean)."""
    name_dir = os.path.basename(os.path.normpath(d))
    errors = []

    skill_md = os.path.join(d, "SKILL.md")
    if not os.path.isfile(skill_md):
        return ["%s: SKILL.md missing" % name_dir]

    with open(skill_md, encoding="utf-8") as f:
        text = f.read()

    data, body_start = parse_frontmatter(text)
    if data is None:
        return ["%s: no YAML frontmatter (--- ... ---)" % name_dir]

    name = data.get("name")
    desc = data.get("description")
    body_lines = len(text.splitlines()[body_start:])

    if not name:
        errors.append("%s: missing 'name'" % name_dir)
    else:
        if not NAME_RE.match(name):
            errors.append("%s: name '%s' must match ^[a-z0-9-]+$" % (name_dir, name))
        if len(name) > MAX_NAME:
            errors.append("%s: name is %d chars (>%d)" % (name_dir, len(name), MAX_NAME))
        if name != name_dir:
            errors.append("%s: name '%s' must equal directory name '%s'" % (name_dir, name, name_dir))

    if not desc:
        errors.append("%s: missing 'description'" % name_dir)
    elif len(desc) > MAX_DESC:
        errors.append("%s: description is %d chars (>%d)" % (name_dir, len(desc), MAX_DESC))

    if body_lines > MAX_BODY:
        errors.append("%s: body is %d lines (>%d)" % (name_dir, body_lines, MAX_BODY))

    return errors


def main(argv):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if argv:
        targets = argv
    else:
        skills_dir = os.path.join(repo, "skills")
        if os.path.isdir(skills_dir):
            targets = sorted(
                os.path.join(skills_dir, n) for n in os.listdir(skills_dir)
                if os.path.isdir(os.path.join(skills_dir, n)))
        else:
            targets = []

    all_errors = []
    count = 0
    for d in targets:
        if not os.path.isdir(d):
            all_errors.append("%s: not a directory" % d)
            continue
        count += 1
        all_errors.extend(lint_dir(d))

    for e in all_errors:
        print("ERROR:", e)
    if all_errors:
        print("lint: FAILED (%d error(s))" % len(all_errors))
        return 1
    print("lint: %d skill(s) OK" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
