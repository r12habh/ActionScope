"""Tests for script injection detection in issue_comment and discussion event contexts.

Issue #58: Add test coverage for additional untrusted GitHub event contexts.
"""

from actionscope.analyzers.script_injection import (
    analyze_step_for_injection,
    find_untrusted_expressions_in_text,
)
from actionscope.models import RiskLevel


class TestCommentAndDiscussionUntrustedExpressions:
    """Verify that comment.body and discussion.body are recognized as untrusted."""

    def test_find_issue_comment_body_as_untrusted(self) -> None:
        expressions = find_untrusted_expressions_in_text(
            "${{ github.event.comment.body }}"
        )
        assert expressions == ["${{ github.event.comment.body }}"]

    def test_find_discussion_body_as_untrusted(self) -> None:
        expressions = find_untrusted_expressions_in_text(
            "${{ github.event.discussion.body }}"
        )
        assert expressions == ["${{ github.event.discussion.body }}"]


class TestDirectInjectionInCommentAndDiscussion:
    """Direct interpolation into run: blocks should produce MEDIUM findings."""

    def test_direct_injection_issue_comment_body(self) -> None:
        step = {"run": 'echo "${{ github.event.comment.body }}"'}
        findings = analyze_step_for_injection(
            step, "test", "ci.yml", trigger_context="issue_comment"
        )
        assert len(findings) >= 1
        assert findings[0].risk_level is RiskLevel.MEDIUM
        assert findings[0].injection_method == "direct"
        assert (
            "comment" in findings[0].untrusted_expression
            or "comment.body" in findings[0].untrusted_expression
        )

    def test_direct_injection_discussion_body(self) -> None:
        step = {"run": 'echo "${{ github.event.discussion.body }}"'}
        findings = analyze_step_for_injection(
            step, "test", "ci.yml", trigger_context="discussion"
        )
        assert len(findings) >= 1
        assert findings[0].risk_level is RiskLevel.MEDIUM
        assert findings[0].injection_method == "direct"
        assert (
            "discussion" in findings[0].untrusted_expression
            or "discussion.body" in findings[0].untrusted_expression
        )


class TestIndirectInjectionInCommentAndDiscussion:
    """Interpolation through env vars should yield no direct finding (env-gated)."""

    def test_indirect_injection_issue_comment_body(self) -> None:
        step = {
            "env": {"COMMENT_BODY": "${{ github.event.comment.body }}"},
            "run": 'echo "$COMMENT_BODY"',
        }
        findings = analyze_step_for_injection(
            step, "test", "ci.yml", trigger_context="issue_comment"
        )
        # When via env, the direct scan produces no finding — that's the env gate
        assert len(findings) == 0

    def test_indirect_injection_discussion_body(self) -> None:
        step = {
            "env": {"DISCUSSION_BODY": "${{ github.event.discussion.body }}"},
            "run": 'echo "$DISCUSSION_BODY"',
        }
        findings = analyze_step_for_injection(
            step, "test", "ci.yml", trigger_context="discussion"
        )
        assert len(findings) == 0
