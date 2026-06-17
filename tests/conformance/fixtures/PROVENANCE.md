# Vendored SEI conformance oracle fixture

`sei-conformance-oracle.json` is a verbatim copy of the shared, normative
fixture from:

    /home/john/loomweave/docs/federation/fixtures/sei-conformance-oracle.json

It is vendored so Legis CI can run the SEI consumer oracle without requiring the
Loomweave checkout. `tests/conformance/test_sei_oracle.py` compares this copy
against the sibling authority fixture when the checkout is present.
