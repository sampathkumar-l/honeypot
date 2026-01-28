from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from database import Base

class HoneypotLog(Base):
    __tablename__ = "honeypot_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    password = Column(String)
    ip_address = Column(String)
    user_agent = Column(String)
    country = Column(String)
    isp = Column(String)
    abuse_score = Column(Integer)
    threat_level = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
