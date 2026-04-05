"""Auto-detect project languages, ecosystems, and IaC frameworks."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set

# Directories to skip when walking the project tree.
_EXCLUDE_DIRS: Set[str] = {
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "__pycache__",
    "vendor",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".terraform",
    ".next",
    "target",
}

# Extension → language mapping.
_EXT_TO_LANGUAGE = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".swift": "Swift",
    ".scala": "Scala",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".hs": "Haskell",
    ".dart": "Dart",
    ".lua": "Lua",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".r": "R",
    ".R": "R",
    ".tf": "HCL",
}

# Config file → language mapping.
_CONFIG_TO_LANGUAGE = {
    "tsconfig.json": "TypeScript",
    "pyproject.toml": "Python",
    "setup.py": "Python",
    "setup.cfg": "Python",
    "Cargo.toml": "Rust",
    "go.mod": "Go",
    "Gemfile": "Ruby",
    "composer.json": "PHP",
    "build.gradle": "Java",
    "build.gradle.kts": "Kotlin",
    "pom.xml": "Java",
    "Package.swift": "Swift",
    "build.sbt": "Scala",
    "mix.exs": "Elixir",
    "pubspec.yaml": "Dart",
}

# Ecosystem detection (file name → ecosystem label).
_ECOSYSTEM_FILES = {
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "pyproject.toml": "python",
    "setup.py": "python",
    "poetry.lock": "poetry",
    "package.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "go.mod": "go-modules",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Package.swift": "swift-pm",
    "build.sbt": "sbt",
    "mix.exs": "hex",
    "pubspec.yaml": "pub",
    "Makefile": "make",
}

# API spec filenames.
_API_SPEC_FILES: Set[str] = {
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger.json",
}


@dataclass
class ProjectInfo:
    """Detected project metadata."""

    path: str
    languages: List[str] = field(default_factory=list)
    ecosystems: List[str] = field(default_factory=list)
    iac_frameworks: List[str] = field(default_factory=list)
    api_specs: List[str] = field(default_factory=list)
    has_docker: bool = False
    has_ci: bool = False


def detect_project(path: str) -> ProjectInfo:
    """Scan *path* and return a :class:`ProjectInfo` summary.

    The walk respects common exclude directories to stay fast on large trees.
    """
    root = Path(path).resolve()

    languages: Set[str] = set()
    ecosystems: Set[str] = set()
    iac_frameworks: Set[str] = set()
    api_specs: List[str] = []
    has_docker = False
    has_ci = False

    # ------------------------------------------------------------------
    # Quick top-level checks (no recursion needed)
    # ------------------------------------------------------------------
    for name, eco in _ECOSYSTEM_FILES.items():
        if (root / name).exists():
            ecosystems.add(eco)

    for name, lang in _CONFIG_TO_LANGUAGE.items():
        if (root / name).exists():
            languages.add(lang)

    # .csproj files may be anywhere; glob one level deep for speed.
    if any(root.glob("*.csproj")) or any(root.glob("*/*.csproj")):
        ecosystems.add("nuget")
        languages.add("C#")

    # Docker
    if (root / "Dockerfile").exists() or (root / "docker-compose.yml").exists() or (root / "docker-compose.yaml").exists():
        has_docker = True
        iac_frameworks.add("Docker")

    # CI
    if (root / ".github" / "workflows").is_dir():
        has_ci = True
        iac_frameworks.add("GitHub Actions")
    if (root / ".gitlab-ci.yml").exists():
        has_ci = True
        iac_frameworks.add("GitLab CI")
    if (root / "Jenkinsfile").exists():
        has_ci = True
        iac_frameworks.add("Jenkins")
    if (root / "azure-pipelines.yml").exists():
        has_ci = True
        iac_frameworks.add("Azure Pipelines")

    # IaC: Terraform
    if list(root.glob("**/*.tf"))[:1]:
        iac_frameworks.add("Terraform")

    # IaC: Kubernetes manifests (heuristic – YAML with apiVersion)
    if (root / "k8s").is_dir() or (root / "kubernetes").is_dir():
        iac_frameworks.add("Kubernetes")

    # IaC: Ansible
    if (root / "ansible").is_dir() or (root / "playbooks").is_dir():
        iac_frameworks.add("Ansible")

    # IaC: Helm
    if (root / "helm").is_dir() or (root / "charts").is_dir() or (root / "Chart.yaml").exists():
        iac_frameworks.add("Helm")

    # API specs at root
    for spec_name in _API_SPEC_FILES:
        spec_path = root / spec_name
        if spec_path.exists():
            api_specs.append(str(spec_path.relative_to(root)))

    # ------------------------------------------------------------------
    # Walk the tree to detect languages by extension
    # ------------------------------------------------------------------
    for item in _walk(root):
        ext = item.suffix.lower()
        lang = _EXT_TO_LANGUAGE.get(ext)
        if lang:
            languages.add(lang)

        # API specs nested in subdirs
        if item.name.lower() in _API_SPEC_FILES:
            rel = str(item.relative_to(root))
            if rel not in api_specs:
                api_specs.append(rel)

    return ProjectInfo(
        path=str(root),
        languages=sorted(languages),
        ecosystems=sorted(ecosystems),
        iac_frameworks=sorted(iac_frameworks),
        api_specs=sorted(api_specs),
        has_docker=has_docker,
        has_ci=has_ci,
    )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _walk(root: Path, _depth: int = 0, _max_depth: int = 8):
    """Yield files under *root*, skipping excluded directories."""
    if _depth > _max_depth:
        return
    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        return
    for entry in entries:
        if entry.is_dir():
            if entry.name in _EXCLUDE_DIRS or entry.name.startswith("."):
                continue
            yield from _walk(entry, _depth + 1, _max_depth)
        elif entry.is_file():
            yield entry
