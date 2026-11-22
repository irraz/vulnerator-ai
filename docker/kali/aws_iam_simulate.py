"""IAM effective-permission simulation script (read-only).

Deterministic BINARY that runs in the Kali server venv (boto3 comes via Prowler). It does NOT
decide nada: dado UN principal IAM concreto, comprueba con ``iam:SimulatePrincipalPolicy``
(API AWS **READ-ONLY**: NO modifica estado) si ese principal PUEDE ejecutar un conjunto FIJO
of classic privesc actions, and writes ONE single JSON document to the ``--out`` path.
El runner STDLIB (``aws_simulate.py``) lo invoca como subproceso con ``tool_streaming``
(kill de grupo/timeout, logs al ring).

It is the per-candidate ANALOG of ``aws_iam_enum.py`` (which is account-wide recon): here
the effective EXPLOITABILITY of a principal is confirmed, stronger than mere enumeration.

Disciplina de seguridad:
  - READ-ONLY: ``SimulatePrincipalPolicy`` SIMULATES policy evaluation; it does NOT execute the
    acciones ni cambia el estado de la cuenta. Las credenciales read-only vienen del entorno
    del contenedor (igual que Prowler/ScoutSuite).
  - FAIL-CLOSED: si el propio ``SimulatePrincipalPolicy`` devuelve ``AccessDenied`` (o cualquier
    otro error del cliente), NO se revienta con un traceback: se escribe un JSON con un ``error``
    clear and ``simulation`` empty, and the runner surfaces it as a failure (UNTRUSTED data).

Deliberately THIN (KISS): no logic that would need a unit test; the testable mechanics
(command construction, execution, output reading, diagnostics) live in
``aws_simulate.py`` (STDLIB puro). Este fichero solo se valida con ``ast.parse`` (no se
imported in tests: boto3 is not in the dev venv).
"""

from __future__ import annotations

import argparse
import json
import sys

import boto3  # provisto por el venv del servidor (Prowler lo arrastra)

# FIXED set of classic IAM PRIVESC actions simulated per principal. These are the
# primitivas con las que un principal con permisos excesivos escala a admin (asumir roles,
# passing roles to services, creating credentials, attaching/writing policies, versioning a
# managed policy, rewriting a role's trust policy). It is a CLOSED set and
# documented: the technique declares scoped expectations, not an arbitrary sweep.
PRIVESC_ACTIONS: tuple[str, ...] = (
    "sts:AssumeRole",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy",
)


def simulate_principal(client, principal_arn: str, actions: tuple[str, ...]) -> dict:
    """Simula ``actions`` sobre ``principal_arn`` y devuelve ``{accion: EvalDecision}``.

    SOLO ``iam:SimulatePrincipalPolicy`` (read-only). ``EvalDecision`` ∈ {``allowed``,
    ``explicitDeny``, ``implicitDeny``}. Se pagina por si la respuesta llega troceada.
    """
    decisions: dict = {}
    paginator = client.get_paginator("simulate_principal_policy")
    for page in paginator.paginate(
        PolicySourceArn=principal_arn, ActionNames=list(actions)
    ):
        for result in page.get("EvaluationResults", []):
            decisions[result.get("EvalActionName")] = result.get("EvalDecision")
    return decisions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simula permisos efectivos de privesc de un principal IAM (read-only, JSON a --out)"
    )
    parser.add_argument("--account", required=True, help="ID de la cuenta AWS autorizada")
    parser.add_argument(
        "--principal-arn",
        required=True,
        dest="principal_arn",
        help="ARN del principal IAM a simular (PolicySourceArn)",
    )
    parser.add_argument("--out", required=True, help="File to write the single JSON to")
    args = parser.parse_args(argv)

    session = boto3.session.Session()
    iam = session.client("iam")

    document: dict = {
        "account": args.account,
        "principal_arn": args.principal_arn,
        "actions": list(PRIVESC_ACTIONS),
    }
    try:
        document["simulation"] = simulate_principal(iam, args.principal_arn, PRIVESC_ACTIONS)
    except Exception as exc:  # noqa: BLE001 - AccessDenied u otro: fail-closed, NO revienta
        # El propio Simulate puede estar denegado para la credencial read-only. Se deja
        # constancia clara (al ring por stderr y en el JSON) sin tumbar el proceso; el runner
        # lo surfacea como 'failed' leyendo este 'error'.
        document["error"] = f"SimulatePrincipalPolicy no disponible: {exc}"
        document["simulation"] = {}
        print(document["error"], file=sys.stderr, flush=True)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(document, fh, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
