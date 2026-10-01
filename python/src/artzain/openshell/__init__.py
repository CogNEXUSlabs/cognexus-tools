"""ArtzAIn for NVIDIA OpenShell: the sidecar that governs a gateway's writes.

ArtzAIn decides and records; OpenShell enforces. The sidecar runs beside an
OpenShell gateway, answers its interceptor calls from the ArtzAIn Decision
API, and only ever calls out.

* :mod:`artzain.openshell.interceptor`: the rules, pure and without I/O.
* :mod:`artzain.openshell.sidecar`: the process: engine calls with a deadline,
  the post-commit report, inventory, OCSF seals and the HTTP routes. Run it
  with ``artzain openshell sidecar``.

Pinned to OpenShell v0.1.2. Operator steps: the ArtzAIn operator manual,
chapter 17.
"""

from artzain.openshell.interceptor import PINNED_OPENSHELL

__all__ = ["PINNED_OPENSHELL"]
