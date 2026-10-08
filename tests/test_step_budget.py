"""Step budget: counting, the hard stop, and reset."""

from __future__ import annotations

import pytest

from zts.step_budget import StepBudget, StepBudgetExhausted


def test_spends_up_to_the_limit_without_error():
    budget = StepBudget(max_steps=3)
    budget.spend()
    budget.spend(2)
    assert budget.steps_used == 3
    assert budget.exhausted
    assert budget.remaining == 0


def test_going_past_the_limit_raises():
    budget = StepBudget(max_steps=2)
    budget.spend(2)
    with pytest.raises(StepBudgetExhausted):
        budget.spend()


def test_reset_restores_the_full_budget():
    budget = StepBudget(max_steps=2)
    budget.spend(2)
    budget.reset()
    assert budget.remaining == 2
    assert not budget.exhausted


def test_limit_must_be_positive():
    with pytest.raises(ValueError):
        StepBudget(max_steps=0)


def test_spend_must_be_positive():
    with pytest.raises(ValueError):
        StepBudget(max_steps=5).spend(0)
