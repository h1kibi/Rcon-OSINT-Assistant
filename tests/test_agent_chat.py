import pytest
from app.db.database import init_db, get_session
from app.db import repositories as repo


@pytest.fixture
def session():
    init_db("sqlite://")
    s = get_session()
    yield s
    s.close()


class TestAgentChatRepository:
    def test_create_session_generates_title(self, session):
        s = repo.create_agent_session(session)
        assert s.title.startswith("SESSION_")
        assert s.status == "active"
        assert s.id is not None

    def test_append_message_updates_preview(self, session):
        s = repo.create_agent_session(session)
        msg = repo.append_agent_message(session, s.id, "user", "Hello world test message")
        session.refresh(s)
        assert s.message_count == 1
        assert "Hello world" in s.last_message_preview
        assert msg.seq == 1

    def test_list_sessions_excludes_deleted(self, session):
        s1 = repo.create_agent_session(session)
        s2 = repo.create_agent_session(session)
        repo.soft_delete_agent_session(session, s2.id)
        active = repo.list_agent_sessions(session)
        assert any(x.id == s1.id for x in active)
        assert not any(x.id == s2.id for x in active)

    def test_rename_session(self, session):
        s = repo.create_agent_session(session)
        ok = repo.rename_agent_session(session, s.id, "CVE Analysis")
        assert ok
        session.refresh(s)
        assert s.title == "CVE Analysis"

    def test_rename_empty_title_fails(self, session):
        s = repo.create_agent_session(session)
        ok = repo.rename_agent_session(session, s.id, "   ")
        assert not ok

    def test_soft_delete(self, session):
        s = repo.create_agent_session(session)
        ok = repo.soft_delete_agent_session(session, s.id)
        assert ok
        session.refresh(s)
        assert s.status == "deleted"

    def test_get_messages_ordered_by_seq(self, session):
        s = repo.create_agent_session(session)
        repo.append_agent_message(session, s.id, "user", "first")
        repo.append_agent_message(session, s.id, "assistant", "second")
        repo.append_agent_message(session, s.id, "user", "third")
        msgs = repo.get_agent_messages(session, s.id)
        assert len(msgs) == 3
        assert msgs[0].seq == 1
        assert msgs[1].seq == 2
        assert msgs[2].seq == 3

    def test_touch_updates_last_opened(self, session):
        s = repo.create_agent_session(session)
        old = s.last_opened_at
        repo.touch_agent_session(session, s.id)
        session.refresh(s)
        assert s.last_opened_at >= old
