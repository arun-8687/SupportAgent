"""Markdown-first definition format: frontmatter skills & custom agents,
with legacy YAML still accepted."""
import pytest

from sre_agent.frontmatter import parse_frontmatter
from sre_agent.skills.registry import SkillRegistry
from sre_agent.subagents.custom_loader import load_custom_agents


# --------------------------------------------------------------------------- #
# Frontmatter parser
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_parse_frontmatter_splits_meta_and_body():
    meta, body = parse_frontmatter("---\nname: x\ntools: [a, b]\n---\n# Guide\nbody text\n")
    assert meta == {"name": "x", "tools": ["a", "b"]}
    assert body.startswith("# Guide")


@pytest.mark.unit
def test_parse_frontmatter_without_block_returns_full_body():
    meta, body = parse_frontmatter("# Just markdown\nno frontmatter")
    assert meta == {}
    assert body.startswith("# Just markdown")


@pytest.mark.unit
def test_parse_frontmatter_malformed_yaml_is_tolerated():
    meta, body = parse_frontmatter("---\n: [broken\n---\nbody")
    assert meta == {}


# --------------------------------------------------------------------------- #
# Skills from SKILL.md frontmatter
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_builtin_skills_are_single_md_files():
    """Metadata now lives in SKILL.md frontmatter — no manifest.yaml."""
    registry = SkillRegistry()
    skill = registry.get("aks-memory-pressure")
    assert skill is not None
    assert not (skill.path / "manifest.yaml").exists()
    assert skill.tools[0].name == "restart_aks_deployment"
    # Guidance body must come back WITHOUT the frontmatter block.
    guidance = skill.read_skill_md()
    assert "# AKS memory pressure troubleshooting" in guidance
    assert "---" not in guidance.split("\n")[0]
    assert "restart_aks_deployment" in guidance  # prose references the tool


@pytest.mark.unit
def test_skill_from_frontmatter_only_directory(tmp_path):
    skill_dir = tmp_path / "disk-cleanup"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        """---
name: disk-cleanup
description: Use when a VM is running out of disk
applies_to: [disk, storage]
tools:
  - name: check_disk
    type: shell
    command: "df -h {mount}"
    parameters: [mount]
    risk: low
---
# Disk cleanup

1. Check usage with `check_disk`.
"""
    )
    registry = SkillRegistry(skills_dir=tmp_path)
    skill = registry.get("disk-cleanup")
    assert skill is not None
    assert skill.get_tool("check_disk").command == "df -h {mount}"
    assert registry.activate("disk-cleanup").startswith("# Disk cleanup")


@pytest.mark.unit
def test_legacy_manifest_yaml_still_loads(tmp_path):
    skill_dir = tmp_path / "legacy-skill"
    skill_dir.mkdir()
    (skill_dir / "manifest.yaml").write_text(
        "name: legacy-skill\ndescription: old format\n"
        "tools:\n  - name: t1\n    type: shell\n    command: 'true'\n"
    )
    (skill_dir / "SKILL.md").write_text("# Legacy guidance\n")
    registry = SkillRegistry(skills_dir=tmp_path)
    skill = registry.get("legacy-skill")
    assert skill is not None
    assert skill.read_skill_md() == "# Legacy guidance\n"


@pytest.mark.unit
def test_builtin_skills_conform_to_agent_skills_spec():
    """agentskills.io rules: naming, dir match, description, spec fields."""
    from sre_agent.skills.registry import MAX_DESCRIPTION_LEN, SKILL_NAME_RE

    registry = SkillRegistry()
    assert registry.all(), "no builtin skills loaded"
    for skill in registry.all():
        assert SKILL_NAME_RE.match(skill.name), skill.name
        assert len(skill.name) <= 64
        assert skill.name == skill.path.name  # name must match directory
        assert 1 <= len(skill.description) <= MAX_DESCRIPTION_LEN
        # Spec optional fields are accepted and preserved.
        assert skill.compatibility  # our builtins document requirements
        assert skill.metadata.get("version")


@pytest.mark.unit
def test_spec_violations_load_with_warning(tmp_path, caplog):
    """Bad names warn (spec enforcement) but don't break an incident."""
    import logging

    skill_dir = tmp_path / "Bad--Name"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: Bad--Name\ndescription: mismatched and invalid\n---\n# x\n"
    )
    with caplog.at_level(logging.WARNING):
        registry = SkillRegistry(skills_dir=tmp_path)
    assert registry.get("Bad--Name") is not None  # still usable
    assert any("Agent Skills spec" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_references_dir_auto_discovered(tmp_path):
    skill_dir = tmp_path / "with-refs"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: with-refs\ndescription: has a references directory\n---\n# g\n"
    )
    refs = skill_dir / "references"
    refs.mkdir()
    (refs / "deep-dive.md").write_text("# Deep dive\ndetails")
    registry = SkillRegistry(skills_dir=tmp_path)
    supporting = registry.get("with-refs").read_supporting_files()
    assert "references/deep-dive.md" in supporting  # not listed in `files`


@pytest.mark.unit
def test_skill_md_without_frontmatter_or_manifest_is_skipped(tmp_path):
    skill_dir = tmp_path / "bare"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# No metadata here\n")
    registry = SkillRegistry(skills_dir=tmp_path)
    assert registry.get("bare") is None
    assert registry.all() == []


# --------------------------------------------------------------------------- #
# Custom agents from markdown
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_shipped_custom_agent_is_md_with_body_as_system_prompt():
    agents = load_custom_agents()
    expert = next(a for a in agents if a.name == "database_expert")
    assert "database specialist" in expert.definition.system_prompt
    assert "frontmatter" not in expert.definition.system_prompt  # comments stay in meta
    assert expert.definition.handoff_description.startswith("Handles SQL")


@pytest.mark.unit
async def test_custom_agent_from_md_directory(tmp_path, azure_monitor_alert):
    from sre_agent.integrations.normalizers import normalize, to_incident

    (tmp_path / "net_expert.md").write_text(
        """---
name: net_expert
handoff_description: Handles VNet, NSG, and load balancer issues
tools: [query_logs]
---
You are a networking specialist. Trace packet paths before blaming DNS.
"""
    )
    agents = load_custom_agents(directory=tmp_path)
    assert len(agents) == 1
    assert agents[0].definition.system_prompt.startswith("You are a networking specialist")

    incident = to_incident(normalize(azure_monitor_alert))
    finding = await agents[0].investigate(incident)
    assert finding.subagent == "net_expert"


@pytest.mark.unit
def test_legacy_yaml_custom_agent_still_loads(tmp_path):
    (tmp_path / "old_expert.yaml").write_text(
        """
name: old_expert
system_prompt: |
  You are a legacy-format specialist.
handoff_description: Legacy YAML definition
"""
    )
    agents = load_custom_agents(directory=tmp_path)
    assert len(agents) == 1
    assert agents[0].definition.system_prompt.strip() == "You are a legacy-format specialist."


@pytest.mark.unit
def test_md_agent_without_frontmatter_is_rejected(tmp_path):
    (tmp_path / "broken.md").write_text("Just prose, no frontmatter.")
    agents = load_custom_agents(directory=tmp_path)
    assert agents == []  # logged and skipped, not crashed
