from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from sinko_probe.engine import POLICY_PROFILE_ID, PlanError, build_plan
from sinko_probe.models import (
    AppProfile,
    Category,
    DomainProbe,
    ExpectedAction,
    SinkoPolicyConfig,
)
from sinko_probe.profiles import BUILTIN_PROFILES

HOMEWORK_POLICY = Path(__file__).resolve().parents[1] / "configs" / "sinko-homework-policy.yaml"

BLOCK, ALLOW, SAFESEARCH = ExpectedAction.BLOCK, ExpectedAction.ALLOW, ExpectedAction.SAFESEARCH


def test_custom_lists_cover_subdomains_and_the_most_specific_entry_wins():
    policy = SinkoPolicyConfig(
        custom_blocklist=["roblox.com"],
        custom_allowlist=["create.roblox.com"],
        category_rules={Category.GAMING: ALLOW},
    )
    assert policy.expectation_for("games.roblox.com", Category.GAMING, ALLOW) == BLOCK
    assert policy.expectation_for("roblox.com", Category.GAMING, ALLOW) == BLOCK
    assert policy.expectation_for("api.create.roblox.com", Category.GAMING, BLOCK) == ALLOW
    # "notroblox.com" is not a subdomain of "roblox.com".
    assert policy.expectation_for("notroblox.com", Category.GAMING, BLOCK) == ALLOW


def test_category_rule_then_probe_default():
    policy = SinkoPolicyConfig(category_rules={Category.SOCIAL: ALLOW})
    assert policy.expectation_for("discord.com", Category.SOCIAL, BLOCK) == ALLOW
    assert policy.expectation_for("discord.com", Category.GAMING, BLOCK) == BLOCK


def test_policy_lists_are_normalized():
    policy = SinkoPolicyConfig(
        custom_blocklist=["*.Roblox.COM.", "roblox.com", " chat.roblox.com "]
    )
    assert policy.custom_blocklist == ["roblox.com", "chat.roblox.com"]


def test_policy_rejects_conflicts_typos_and_bad_domains():
    with pytest.raises(ValidationError, match="both"):
        SinkoPolicyConfig(custom_blocklist=["x.com"], custom_allowlist=["X.com"])
    with pytest.raises(ValidationError, match="custom_blocklst"):
        SinkoPolicyConfig.model_validate({"custom_blocklst": ["x.com"]})  # typo is not ignored
    with pytest.raises(ValidationError):
        SinkoPolicyConfig(category_rules={"adult": "block"})
    with pytest.raises(ValidationError, match="invalid domain"):
        SinkoPolicyConfig(custom_blocklist=["a" * 64 + ".com"])


def test_custom_blocklist_domains_are_actually_probed():
    """The old engine only re-labelled domains that a profile already probed, so the shipped
    policy's 'chat.roblox.com' was never queried at all."""
    policy = SinkoPolicyConfig(
        custom_blocklist=["chat.roblox.com", "www.roblox.com"],
        custom_allowlist=["docs.python.org"],
    )
    plan = build_plan(list(BUILTIN_PROFILES.values()), policy)
    extra = {p.probe.domain: p.expected for p in plan if p.profile.id == POLICY_PROFILE_ID}
    assert extra == {"chat.roblox.com": BLOCK, "docs.python.org": ALLOW}  # www.roblox.com exists


def test_safesearch_policy_needs_markers():
    policy = SinkoPolicyConfig(category_rules={Category.SOCIAL: SAFESEARCH})
    with pytest.raises(PlanError, match="expected_cname_markers"):
        build_plan([BUILTIN_PROFILES["tiktok_snap_social"]], policy)


def test_probe_validation():
    with pytest.raises(ValidationError, match="record_type"):
        DomainProbe(domain="example.com", category=Category.ADS, record_type="MX")
    with pytest.raises(ValidationError, match="expected_cname_markers"):
        DomainProbe(domain="www.google.com", category=Category.SAFE_SEARCH, expected=SAFESEARCH)
    with pytest.raises(ValidationError, match="burst_interval_ms"):
        AppProfile(
            id="x",
            name="X",
            burst_interval_ms=(50, 10),
            probes=[DomainProbe(domain="a.example", category=Category.ADS)],
        )
    probe = DomainProbe(domain="Ads.Example.COM.", category=Category.ADS, record_type="aaaa")
    assert (probe.domain, probe.record_type) == ("ads.example.com", "AAAA")


def test_shipped_homework_policy_is_valid():
    policy = SinkoPolicyConfig.model_validate(yaml.safe_load(HOMEWORK_POLICY.read_text("utf-8")))
    assert policy.category_rules[Category.AI_CHATBOTS] == BLOCK
    plan = build_plan(list(BUILTIN_PROFILES.values()), policy)
    expectations = {p.probe.domain: p.expected for p in plan}
    assert expectations["chat.roblox.com"] == BLOCK
    assert expectations["gemini.google.com"] == BLOCK
    assert expectations["www.khanacademy.org"] == ALLOW
    assert expectations["www.google.com"] == SAFESEARCH


def test_builtin_profiles_are_consistent():
    for profile_id, profile in BUILTIN_PROFILES.items():
        assert profile.id == profile_id
        domains = [(p.domain, p.record_type) for p in profile.probes]
        assert len(domains) == len(set(domains)), profile_id
