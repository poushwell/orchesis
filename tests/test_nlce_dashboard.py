from __future__ import annotations

from orchesis.dashboard import get_dashboard_html


def test_research_tab_present() -> None:
    html = get_dashboard_html()
    assert 'id="tab-research"' in html
    assert 'data-tab="research"' in html
    assert "🔬 Research" in html


def test_research_section_markup() -> None:
    html = get_dashboard_html()
    assert '<section id="research"' in html
    assert 'class="screen tab-section hidden"' in html
    assert 'role="tabpanel"' in html


def test_poll_research_function() -> None:
    html = get_dashboard_html()
    assert "async function pollResearch()" in html
    assert "Promise.allSettled([" in html
    assert "fetch('/api/v1/nlce/metrics')" in html
    assert "fetch('/api/v1/nlce/impossibility-theorems')" in html
    assert "renderResearch({" in html


def test_nlce_confirmed_results_div() -> None:
    html = get_dashboard_html()
    assert 'id="nlce-confirmed-results"' in html
    assert "Confirmed NLCE results" in html
    assert "Zipf α" in html


def test_nlce_theorems_div() -> None:
    html = get_dashboard_html()
    assert 'id="nlce-theorems"' in html
    assert "Impossibility theorems T1-T5" in html
