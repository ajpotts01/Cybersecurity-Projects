"""
©AngelaMos | 2026
fix_mypy.py
"""

import re
from pathlib import Path

def remove_unused_ignores(file_path: Path, lines_with_unused: list[int]) -> None:
    """Remove unused type: ignore comments from specific lines"""
    with open(file_path) as f:
        lines = f.readlines()

    for line_num in lines_with_unused:
        idx = line_num - 1
        if idx < len(lines):
            line = lines[idx]
            line = re.sub(r'  # type: ignore\[no-untyped-call\]', '', line)
            line = re.sub(r'  # type: ignore\[no-any-return\]', '', line)
            line = re.sub(r'  # type: ignore\[attr-defined\]', '', line)
            line = re.sub(r'  # type: ignore\[no-untyped-call, no-any-return\]', '', line)
            line = re.sub(r'  # type: ignore', '', line)
            lines[idx] = line

    with open(file_path, 'w') as f:
        f.writelines(lines)

# Clean up User.py
remove_unused_ignores(
    Path("app/models/User.py"),
    [57, 64, 71, 78, 97, 109, 117, 127, 135, 142, 149, 155]
)

# Clean up ScenarioRun.py
remove_unused_ignores(
    Path("app/models/ScenarioRun.py"),
    [63, 71, 80, 81, 89, 97, 104, 111, 120, 127]
)

# Clean up LogEvent.py
remove_unused_ignores(
    Path("app/models/LogEvent.py"),
    [100, 113, 156, 163, 170, 217, 241, 280]
)

# Clean up CorrelationRule.py
remove_unused_ignores(
    Path("app/models/CorrelationRule.py"),
    [58]
)

# Clean up Alert.py
remove_unused_ignores(
    Path("app/models/Alert.py"),
    [88, 125, 132]
)

# Clean up scenario_ctrl.py
remove_unused_ignores(
    Path("app/controllers/scenario_ctrl.py"),
    [43, 53, 63, 74]
)

# Clean up rule_ctrl.py
remove_unused_ignores(
    Path("app/controllers/rule_ctrl.py"),
    [23, 48, 61, 70]
)

print("Removed unused type: ignore comments")
