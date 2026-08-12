"""Small CLI integration target for a same-file Joern flow."""

from flask import request

# Safe branch used only to give the integration target a realistic shape.
OPERATORS = {
    "add": lambda left, right: left + right,
    "subtract": lambda left, right: left - right,
}


def safe_calculate(operator, left, right):
    """Evaluate an allowlisted arithmetic operation."""
    function = OPERATORS.get(operator)
    if function is None:
        raise ValueError("unsupported operator")
    return function(left, right)


# The scanner fixture points to line 24 below.

def unsafe_calculate():
    user_input = request.args.get("expression")
    return eval(user_input)
