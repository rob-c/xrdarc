# Contributing to xrdarc

Changes are welcome when they keep xrdarc correct against real ARC CEs,
compatible with ARC's own tools and files, and pure Python.

## Definition of done

A change is ready when:

- behaviour is covered at the public boundary, and protocol behaviour
  against the fake A-REX (`xrdarc.testing.arex`), whose fidelity to
  `rest.cpp` is part of the change when the protocol is;
- the hermetic suite keeps 100% line and branch coverage, without
  `# pragma: no cover`;
- `ruff check`, `ruff format --check`, `mypy` and `complexipy` are clean;
- anything that changes what is sent to a CE has been run with the interop
  suite against a real one (docs/DEVELOPING.md);
- user-visible changes are in CHANGELOG.md, and deliberate differences from
  ARC are in docs/compatibility.md.
