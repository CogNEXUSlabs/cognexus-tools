"""Unpaired surrogates: the one kind of Python ``str`` that is not valid text.

A code point in U+D800-U+DFFF is half of a UTF-16 surrogate pair, never a
character on its own. ``json.loads`` makes one from a lone escape (what
serializing a JavaScript string cut in the middle of an emoji leaves) and
Python keeps it in a ``str``. No UTF-8 encoder accepts it, so a string holding
one cannot be hashed, written as UTF-8 JSON, signed or stored until something
decides what becomes of it.

The engine (``security/_surrogates.py``) and the SDK (``artzain/_surrogates.py``)
carry byte-identical copies of this module, pinned by a test. The guard modules
shared with the SDK keep their own copy of the pattern.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator, Optional

UNPAIRED_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")

#: A location shows keys cut to this many characters, and a path longer than
#: this many subscripts as its first three and last four, so none is long.
_KEY_SHOWN = 40
_PARTS_SHOWN = 8


def replace_unpaired_surrogates(text: str) -> str:
    """*text* with every unpaired surrogate replaced by U+FFFD."""
    return UNPAIRED_SURROGATE_RE.sub("\ufffd", text)


def find_unpaired_surrogate(value: Any) -> Optional[str]:
    """Where an unpaired surrogate sits in JSON-shaped *value*, or ``None``.

    Strings, dict keys and values, lists and tuples are searched without
    recursion. The walk runs on a request body before authentication, so it
    keeps one frame per level of nesting and builds a location only for the
    string it finds: a subscript path such as ``['notes'][0]``, or ``''`` when
    *value* is the string itself. Keys are written with ``repr``, which escapes
    a surrogate, and cut short, and the middle of a deep path is elided.
    """
    search = UNPAIRED_SURROGATE_RE.search
    if isinstance(value, str):
        return "" if search(value) else None
    if not isinstance(value, (dict, list, tuple)):
        return None
    # One frame per open container: its members, and its key in the parent.
    stack: list[tuple[Iterator[tuple[Any, Any]], Any]] = [(_members(value), None)]
    while stack:
        for key, child in stack[-1][0]:
            if (isinstance(key, str) and search(key)) or (
                isinstance(child, str) and search(child)
            ):
                return _location([frame[1] for frame in stack[1:]] + [key])
            if isinstance(child, (dict, list, tuple)):
                stack.append((_members(child), key))
                break
        else:
            stack.pop()
    return None


def without_unpaired_surrogates(value: Any) -> Any:
    """*value* with every unpaired surrogate in its strings replaced by U+FFFD.

    For a JSON-shaped record about to be written out as UTF-8. When *value*
    already encodes, or is not something ``json`` can write, it comes back
    unchanged, the same object: a valid record's bytes stay as they were, and
    the caller's own serialization still raises what it raised. Otherwise a
    copy is built without recursion. Tuples become lists. A key that held a
    surrogate takes a ``#2``, ``#3``... suffix when its cleaned form is already
    a key, so no value is dropped and no valid key is renamed.
    """
    if isinstance(value, str):
        return replace_unpaired_surrogates(value)
    try:
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        return _cleaned_copy(value)
    except (TypeError, ValueError, RecursionError):
        return value
    return value


def _members(node: Any) -> Iterator[tuple[Any, Any]]:
    return iter(node.items()) if isinstance(node, dict) else enumerate(node)


def _location(keys: list[Any]) -> str:
    parts = []
    for key in keys:
        if isinstance(key, str) and len(key) > _KEY_SHOWN:
            key = key[:_KEY_SHOWN] + "..."
        parts.append(f"[{key!r}]")
    if len(parts) > _PARTS_SHOWN:
        parts = parts[:3] + ["[...]"] + parts[-4:]
    return "".join(parts)


def _cleaned_copy(value: Any) -> Any:
    root = _empty_like(value)
    stack = [(_cleaned_members(value), root)]
    while stack:
        members, target = stack[-1]
        for key, child in members:
            if isinstance(child, (dict, list, tuple)):
                copy = _empty_like(child)
                _put(target, key, copy)
                stack.append((_cleaned_members(child), copy))
                break
            _put(target, key, replace_unpaired_surrogates(child) if isinstance(child, str) else child)
        else:
            stack.pop()
    return root


def _empty_like(node: Any) -> Any:
    return {} if isinstance(node, dict) else []


def _cleaned_members(node: Any) -> Iterator[tuple[Any, Any]]:
    if not isinstance(node, dict):
        return enumerate(node)
    search = UNPAIRED_SURROGATE_RE.search
    held = [(k, v) for k, v in node.items() if isinstance(k, str) and search(k)]
    if not held:
        return iter(node.items())
    # Valid keys first, so a cleaned key never takes the name of a valid one.
    kept = [(k, v) for k, v in node.items() if not (isinstance(k, str) and search(k))]
    return iter(kept + [(replace_unpaired_surrogates(k), v) for k, v in held])


def _put(target: Any, key: Any, value: Any) -> None:
    if isinstance(target, list):
        target.append(value)
        return
    name, n = key, 1
    while name in target:
        n += 1
        name = f"{key}#{n}"
    target[name] = value
