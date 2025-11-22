"""
App package for modularized bot components.

Subpackages:
- db: database engine, session, Base
- models: SQLAlchemy ORM models and enums
- services: domain helpers (moderation, security, events, reactions, xp, guild admin, polls, stream)
"""
# 이 패키지는 봇 기능을 모듈별로 분리해 유지보수성과 확장성을 높이도록 구성되어 있습니다.
