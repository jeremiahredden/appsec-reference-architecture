"""
SQL Injection — vulnerable and secure variants, side by side.

Scenario: a user-lookup function used by an admin tool. The function
accepts an email (authenticated admin input, but still user-controlled)
and returns the matching user record.

Run it locally against a throwaway SQLite DB to see the exploit hit:

    python sql_injection.py

Both variants are implemented with SQLAlchemy 2.x for parity. The
vulnerable one deliberately uses string interpolation with `text()`,
which is the real-world pattern that leads to incidents — developers
who "know about" parameterized queries still reach for f-strings when
they need "just one dynamic bit" in a raw query.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase): ...


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str]
    role: Mapped[str]


# ---------------------------------------------------------------------------
# VULNERABLE: string interpolation into a text() query.
# ---------------------------------------------------------------------------
def get_user_vulnerable(session, email: str):
    """
    Exploit:
        get_user_vulnerable(session, "nobody@x' OR '1'='1")

    The query becomes:
        SELECT id, email, role FROM users WHERE email = 'nobody@x' OR '1'='1'

    Returns the first row in the table — often the earliest-created admin
    account. On a system where this function is part of a "look up user
    and impersonate" admin tool, this is full account takeover.

    A Union-based variant lets the attacker read arbitrary columns from
    other tables:
        "x' UNION SELECT id, password_hash, role FROM users --"
    """
    query = f"SELECT id, email, role FROM users WHERE email = '{email}'"
    return session.execute(text(query)).first()


# ---------------------------------------------------------------------------
# SECURE: parameterized query via SQLAlchemy bindparams.
# ---------------------------------------------------------------------------
def get_user_secure(session, email: str):
    """
    Same behavior for valid input. For the attacker's payload
    "nobody@x' OR '1'='1", the driver binds the entire string as a
    literal, looks for a user with exactly that email, and returns
    None. No injection is possible.

    Key properties:
      - `:email` is a placeholder, not a format specifier.
      - The value is passed as a dict so the driver can type-bind it.
      - Even if `email` contains SQL, it is treated as a string value.
    """
    return session.execute(
        text("SELECT id, email, role FROM users WHERE email = :email"),
        {"email": email},
    ).first()


# ---------------------------------------------------------------------------
# PREFERRED: use the ORM, which parameterizes by construction.
# ---------------------------------------------------------------------------
def get_user_orm(session, email: str):
    """
    The ORM-first version. Every filter expression the ORM builds is
    parameterized. You never write the SQL; you never write the risk.

    When reviewers see `session.query(...).filter(...)` they can move
    on. When they see `text()`, they stop and look for bindparams.
    """
    return session.query(User).filter(User.email == email).one_or_none()


# ---------------------------------------------------------------------------
# Demo harness — run this file to see the vulnerable version exploited.
# ---------------------------------------------------------------------------
def _demo():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    with Session() as s:
        s.add_all([
            User(email="admin@example.com", role="admin"),
            User(email="alice@example.com", role="user"),
            User(email="bob@example.com",   role="user"),
        ])
        s.commit()

        payload = "nobody@x' OR '1'='1"

        vuln_result = get_user_vulnerable(s, payload)
        print("VULNERABLE:", vuln_result)
        # → (1, 'admin@example.com', 'admin')

        secure_result = get_user_secure(s, payload)
        print("SECURE:    ", secure_result)
        # → None

        orm_result = get_user_orm(s, payload)
        print("ORM:       ", orm_result)
        # → None


if __name__ == "__main__":
    _demo()
