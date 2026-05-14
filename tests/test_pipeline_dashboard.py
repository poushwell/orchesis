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
    assert "fetch('/api/v1/pipeline/metrics')" in html
    assert "fetch('/api/v1/pipeline/invariants')" in html
    assert "renderResearch({" in html


def test_nlce_confirmed_results_div() -> None:
    html = get_dashboard_html()
    assert 'id="pipeline-results"' in html
    assert "Confirmed pipeline results" in html
    assert "Zipf α" in html


def test_pipeline_invariants_div() -> None:
    html = get_dashboard_html()
    assert 'id="pipeline-theorems"' in html
    assert "Pipeline invariants" in html
