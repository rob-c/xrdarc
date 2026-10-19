"""How the fake A-REX speaks: its XML tree, and A-REX's JSON, XML and HTML renderings of it.

A-REX builds every answer as an XML tree (``Arc::XMLNode``) and renders it
in the format the ``Accept`` header picked (``ProcessAcceptedFormat``):
XML as is, JSON by ``RenderToJson`` (rest.cpp) - the root element dropped,
every value a string, attributes of leaf elements lost, and a per-endpoint
list of *forced arrays* that are lists even with one member - or an HTML
table for a client that asked for neither. :class:`_Node` is that tree and
the ``_render_*`` functions are ports of those renderers; clients' JSON
bodies are parsed back as ``ParseFromJson`` parses them, bugs included (a
non-string scalar loses its first character).

The JSON renderer is the part clients depend on: ``xrdarc.rest`` must
accept A-REX's shapes (one job as an object, several as a list), and the
tests in ``test_fake_arex.py`` pin them against rest.cpp's behaviour.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from xml.sax.saxutils import escape, quoteattr

from xrdcore import safexml

#: ``Accept`` media types A-REX recognises -> (renderer, the ``Content-Type`` it answers).
_FORMATS = {
    "application/json": ("json", "application/json"),
    "text/xml": ("xml", "application/xml"),
    "application/xml": ("xml", "application/xml"),
    "text/html": ("html", "text/html"),
}


# ---------------------------------------------------------------------------
# A small XML tree, rendered as A-REX renders its responses
# ---------------------------------------------------------------------------


@dataclass
class _Node:
    """An element: what A-REX builds before rendering it as JSON, XML or HTML."""

    name: str
    text: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[_Node] = field(default_factory=list)
    #: A default namespace declaration; XML shows it, JSON (like libxml2) does not.
    xmlns: str = ""

    def add(self, name: str, text: str = "", attrs: dict[str, str] | None = None) -> _Node:
        """Append a child element and return it, so trees are built top-down in one line each."""
        child = _Node(name, text, dict(attrs or {}))
        self.children.append(child)
        return child

    def first(self, name: str) -> _Node | None:
        """The first child called ``name``, if any."""
        return next((child for child in self.children if child.name == name), None)


def _jstr(text: str) -> str:
    """A JSON string literal; non-ASCII kept as is, as A-REX writes UTF-8."""
    return json.dumps(text, ensure_ascii=False)


def _render_json(node: _Node, paths: tuple[str, ...], show_empty: bool, depth: int = 0) -> str:
    """A port of ``RenderToJson`` (rest.cpp): ``paths`` are the forced arrays below ``node``.

    ``show_empty`` writes a forced array with no members as ``[]``; ``depth``
    is how far below the rendered root ``node`` is (the root itself is
    never named: A-REX drops it).
    """
    return _json(node, _Walk(paths, show_empty, depth))


@dataclass(frozen=True, slots=True)
class _Walk:
    """Where the JSON renderer is: the forced arrays from here down, and the depth."""

    paths: tuple[str, ...]
    show_empty: bool
    depth: int

    def below(self, name: str) -> _Walk:
        """The walk inside a child called ``name``: its share of the forced-array paths."""
        inner = tuple(path[len(name) + 1 :] for path in self.paths if path.startswith(name + "/"))
        return _Walk(inner, self.show_empty, self.depth + 1)


def _json(node: _Node, walk: _Walk) -> str:
    """``node`` as JSON: an object of its children (and ``_attributes``), or a leaf's text."""
    here = [path for path in walk.paths if "/" not in path]
    if not node.children and not here:
        # A leaf: its attributes are lost, and an empty root is no body at all.
        return _jstr(node.text) if walk.depth or node.text else ""
    members = [
        f"{_jstr(name)}:{_json_member(node, name, count, walk)}"
        for name, count in _json_counts(node, here, walk.show_empty).items()
    ]
    if node.attrs:
        pairs = ",".join(f"{_jstr(key)}:{_jstr(value)}" for key, value in node.attrs.items())
        members.append(f'"_attributes":{{{pairs}}}')
    return "{" + ",".join(members) + "}"


def _json_counts(node: _Node, forced: list[str], show_empty: bool) -> dict[str, int]:
    """Children by name, in order; a forced array counts as two more (so it is a list)."""
    counts: dict[str, int] = {}
    for child in node.children:
        counts[child.name] = counts.get(child.name, 0) + 1
    for name in forced:
        if name in counts:
            counts[name] += 2
        elif show_empty:
            counts[name] = 2
    return counts


def _json_member(node: _Node, name: str, count: int, walk: _Walk) -> str:
    """The JSON value of ``node``'s children called ``name``: one object, or an array.

    ``count`` above one (or a forced array, counted as two more by
    :func:`_json_counts`) makes an array, which is the whole of A-REX's rule.
    """
    group = [child for child in node.children if child.name == name]
    if not group:
        return "[]"  # a forced array with nothing in it
    items = [_json(child, walk.below(name)) for child in group]
    return items[0] if count == 1 else "[" + ",".join(items) + "]"


def _render_xml(node: _Node) -> str:
    """The tree as XML: attributes, a namespace declaration where one was set, empty tags short."""
    attrs = "".join(f" {key}={quoteattr(value)}" for key, value in node.attrs.items())
    if node.xmlns:
        attrs = f" xmlns={quoteattr(node.xmlns)}" + attrs
    inner = escape(node.text) + "".join(_render_xml(child) for child in node.children)
    if not inner:
        return f"<{node.name}{attrs}/>"
    return f"<{node.name}{attrs}>{inner}</{node.name}>"


def _render_html(node: _Node, depth: int = 0) -> str:
    """``RenderToHtml``: what a client that forgets ``Accept`` gets.

    Nested tables, element name in the first column; useless to a program,
    which is the point of serving it: a client must name JSON or XML.
    """
    if node.children:
        rows = "".join(
            f"<tr><td>{child.name}</td><td>{_render_html(child, depth + 1)}</td></tr>"
            for child in node.children
        )
        body = f'<table border="1">{rows}</table>'
    else:
        body = escape(node.text)
    if depth:
        return body
    return f"<HTML><HEAD>{node.name}</HEAD><BODY>{body}</BODY></HTML>"


def _local(tag: str) -> str:
    """An ElementTree tag without its ``{namespace}``."""
    return tag.rpartition("}")[2]


def _from_element(element: ET.Element, namespace: str = "") -> _Node:
    """An ElementTree element as a :class:`_Node`, declaring a namespace only where it changes."""
    own = element.tag[1:].partition("}")[0] if element.tag.startswith("{") else ""
    node = _Node(
        _local(element.tag),
        element.text or "",
        {_local(key): value for key, value in element.attrib.items()},
        xmlns=own if own != namespace else "",
    )
    node.children = [_from_element(child, own) for child in element]
    return node


def _parse_xml(data: bytes | str) -> _Node | None:
    """``data`` as a tree, or ``None`` if it is not XML (A-REX then answers as for no body).

    Read through :mod:`xrdcore.safexml`, so a document type declaration makes
    it "not XML" too: the fake expands no entity a test could smuggle in.
    """
    try:
        return _from_element(safexml.fromstring(data))
    except (ET.ParseError, safexml.UnsafeXML):
        return None


# ---------------------------------------------------------------------------
# Client JSON, parsed as ParseFromJson parses it
# ---------------------------------------------------------------------------


def _json_scalar(value: object) -> str:
    """A string as is; anything else loses its first character (the rest.cpp bug).

    ``ParseFromJson`` drops the first character of a non-string scalar's
    text: ``123`` is read as ``23``. A client sending ids as JSON numbers
    therefore asks about the wrong jobs - which is why ``xrdarc.rest``
    always sends strings, and why this is reproduced.
    """
    return value if isinstance(value, str) else json.dumps(value)[1:]


def _json_into(parent: _Node, name: str, value: object) -> None:
    """Add ``value`` under ``parent`` as ``ParseFromJson`` does: a list repeats the element."""
    if isinstance(value, list):
        for item in value:
            _json_into(parent, name, item)
    elif isinstance(value, dict):
        child = parent.add(name)
        for key, item in value.items():
            _json_into(child, key, item)
    else:
        parent.add(name, _json_scalar(value))


def _json_tree(body: bytes) -> _Node:
    """A client's JSON body as the tree A-REX would have parsed (empty when it is not JSON)."""
    root = _Node("jobs")
    try:
        document = json.loads(body)
    except ValueError:
        return root  # rest.cpp keeps what it parsed; this keeps nothing
    if isinstance(document, dict):
        for key, value in document.items():
            _json_into(root, key, value)
    return root


def _job_ids(content_type: str | None, body: bytes) -> list[str]:
    """``ParseJobIds``: only exactly ``application/json``, ``application/xml`` or none.

    Anything else - ``application/json; charset=utf-8`` included - parses as
    no ids at all, which is why ``xrdarc.rest`` sends the bare type.
    """
    root = _id_document(content_type, body)
    entries = root.children if root is not None else []
    found = [job.first("id") for job in entries if job.name == "job"]
    return [node.text for node in found if node is not None and node.text]


def _id_document(content_type: str | None, body: bytes) -> _Node | None:
    """The bulk body as a tree, by its exact ``Content-Type``; ``None``: A-REX would not read it."""
    if content_type == "application/json":
        return _json_tree(body)
    if content_type in (None, "", "application/xml"):
        return _parse_xml(body)
    return None


def _negotiate(accept: str | None) -> tuple[str, str | None]:
    """``ProcessAcceptedFormat``: the first recognised ``Accept`` entry, else HTML.

    Parameters (``;q=0.5``) are ignored, as A-REX ignores them: the first
    type it knows wins, whatever its weight.
    """
    for item in (accept or "").split(","):
        found = _FORMATS.get(item.split(";", 1)[0].strip())
        if found is not None:
            return found
    return "html", None
