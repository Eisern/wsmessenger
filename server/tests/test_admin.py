# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
The admin panel without a session.

Sessions live in the server's memory, so a restart - every deploy that touches
server/ - ends them all, and the next page the operator opened answered
{"detail":"Admin auth required"} with no way on. A browser asking for a page
now gets the login form; nothing else about a 401 changes, in the panel or
anywhere else.
"""

from __future__ import annotations

import httpx

HTML = {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


def test_a_page_without_a_session_leads_to_the_login_form(island):
    for path in ("/admin", "/admin/users", "/admin/reports"):
        r = httpx.get(island.base + path, headers=HTML, follow_redirects=False)
        assert r.status_code == 303, (path, r.status_code, r.text)
        assert r.headers["location"] == "/admin/login", path

    r = httpx.get(island.base + "/admin", headers=HTML, follow_redirects=True)
    assert r.status_code == 200
    assert str(r.url).endswith("/admin/login")
    assert 'name="password"' in r.text


def test_the_login_form_itself_is_served_not_redirected(island):
    r = httpx.get(island.base + "/admin/login", headers=HTML, follow_redirects=False)
    assert r.status_code == 200


def test_a_client_that_did_not_ask_for_a_page_still_gets_401(island):
    r = httpx.get(island.base + "/admin/users", headers={"accept": "application/json"},
                  follow_redirects=False)
    assert r.status_code == 401
    assert r.json() == {"detail": "Admin auth required"}


def test_a_form_post_without_a_session_is_not_turned_into_a_redirect(island):
    r = httpx.post(island.base + "/admin/logout", headers=HTML, follow_redirects=False)
    assert r.status_code in (401, 403), r.status_code
    assert "location" not in r.headers


def test_a_401_outside_the_panel_is_untouched(island):
    r = httpx.get(island.base + "/rooms/mine",
                  headers={**HTML, "authorization": "Bearer not-a-token"}, follow_redirects=False)
    assert r.status_code == 401
    assert "location" not in r.headers
    assert "detail" in r.json()


def test_other_errors_keep_their_shape(island):
    r = httpx.get(island.base + "/no-such-endpoint", headers=HTML, follow_redirects=False)
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}
