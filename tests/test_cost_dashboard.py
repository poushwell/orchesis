from __future__ import annotations

from orchesis.dashboard import get_dashboard_html


def test_cost_tab_present() -> None:
    html = get_dashboard_html()
    assert 'id="tab-cost"' in html
    assert "💰 Cost" in html
    assert "switchTab('cost')" in html


def test_cost_section_markup() -> None:
    html = get_dashboard_html()
    assert '<section id="cost"' in html
    assert 'role="tabpanel"' in html
    assert 'id="cost-summary"' in html


def test_poll_cost_function() -> None:
    html = get_dashboard_html()
    assert "async function pollCost()" in html
    assert "Promise.allSettled([" in html
    assert "fetch('/api/v1/cost/analytics')" in html
    assert "fetch('/api/v1/cost-of-freedom/benchmarks')" in html
    assert "renderCost({" in html


def test_cost_of_freedom_widget() -> None:
    html = get_dashboard_html()
    assert 'id="cost-of-freedom-widget"' in html


def test_token_yield_chart_div() -> None:
    html = get_dashboard_html()
    assert 'id="token-yield-chart"' in html
