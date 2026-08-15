"""Run every scenario and report what passed.

    python -m acm_showcase           # everything
    python -m acm_showcase digest    # one group
"""

import asyncio
import sys
import traceback

from .checks import all_scenarios

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


async def main(groups: set[str]) -> int:
    scenarios = [s for s in all_scenarios() if not groups or s[0] in groups]
    if not scenarios:
        known = sorted({g for g, _, _ in all_scenarios()})
        print(f"no scenarios match {sorted(groups)}; known groups: {known}")
        return 2

    failures: list[tuple[str, str, BaseException]] = []
    current = ""
    for group, name, run in scenarios:
        if group != current:
            current = group
            print(f"\n{BOLD}{group}{OFF}")
        try:
            detail = await run()
        except Exception as exc:  # noqa: BLE001 - a failing scenario is the point
            failures.append((group, name, exc))
            print(f"  {RED}FAIL{OFF}  {name}")
            print(f"        {RED}{type(exc).__name__}: {exc}{OFF}")
        else:
            print(f"  {GREEN}ok{OFF}    {name}")
            print(f"        {DIM}{detail}{OFF}")

    total = len(scenarios)
    print(f"\n{total - len(failures)}/{total} scenarios passed")
    if failures:
        print(f"\n{BOLD}Tracebacks{OFF}")
        for group, name, exc in failures:
            print(f"\n{RED}{group} / {name}{OFF}")
            traceback.print_exception(type(exc), exc, exc.__traceback__)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(set(sys.argv[1:]))))
