from __future__ import annotations

from orchesis.dashboard import get_dashboard_html


def test_autopsy_button_present() -> None:
    html = get_dashboard_html()
    assert 'id="autopsy-btn"' in html
    assert 'onclick="openAutopsy()"' in html
    assert "🔬 Autopsy" in html


def test_autopsy_modal_markup() -> None:
    html = get_dashboard_html()
    assert 'id="autopsy-modal"' in html
    assert 'class="modal hidden"' in html
    assert "🔬 Agent Autopsy" in html
    assert 'id="autopsy-result"' in html


def test_autopsy_session_input() -> None:
    html = get_dashboard_html()
    assert 'id="autopsy-session-id"' in html
    assert 'type="text"' in html
    assert 'placeholder="Session ID..."' in html


def test_run_autopsy_function() -> None:
    html = get_dashboard_html()
    assert "async function runAutopsy()" in html
    assert "Enter session ID" in html
    assert "fetch(`/api/v1/autopsy/${sessionId}`" in html


def test_render_autopsy_result_function() -> None:
    html = get_dashboard_html()
    assert "function renderAutopsyResult(data)" in html
    assert "Cause:" in html
    assert "Severity:" in html
    assert "Preventable:" in html
