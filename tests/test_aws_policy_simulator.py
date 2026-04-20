from providers.aws_policy_simulator import AWSPolicySimulator


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        assert "PolicySourceArn" in kwargs
        assert "ActionNames" in kwargs
        return self._pages


class _FakeIAMClient:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, name):
        assert name == "simulate_principal_policy"
        return _FakePaginator(self._pages)


def test_simulate_high_risk_actions_splits_allowed_and_denied():
    pages = [
        {
            "EvaluationResults": [
                {"EvalActionName": "iam:PassRole", "EvalDecision": "allowed"},
                {"EvalActionName": "iam:CreateAccessKey", "EvalDecision": "explicitDeny"},
            ]
        }
    ]
    sim = AWSPolicySimulator(iam_client=_FakeIAMClient(pages))

    result = sim.simulate_high_risk_actions(
        principal_arn="arn:aws:iam::123456789012:user/test",
        actions=["iam:PassRole", "iam:CreateAccessKey"],
    )

    assert result.allowed_actions == ["iam:PassRole"]
    assert result.denied_actions == ["iam:CreateAccessKey"]


def test_simulate_high_risk_actions_empty_actions_returns_empty_result():
    sim = AWSPolicySimulator(iam_client=_FakeIAMClient([]))

    result = sim.simulate_high_risk_actions(
        principal_arn="arn:aws:iam::123456789012:role/test",
        actions=[],
    )

    assert result.evaluated_actions == []
    assert result.allowed_actions == []
    assert result.denied_actions == []
