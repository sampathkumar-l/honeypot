from fastapi import FastAPI, Request, Depends
from sqlalchemy.orm import Session

from database import SessionLocal, engine
from models import HoneypotLog, Base
from threat_intel import check_ip

app = FastAPI(title="FastAPI Credential Honeypot")

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/admin/login")
async def fake_admin_login(
    request: Request,
    username: str,
    password: str,
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent")

    intel = check_ip(client_ip)

    log = HoneypotLog(
        username=username,
        password=password,
        ip_address=client_ip,
        user_agent=user_agent,
        country=intel["country"],
        isp=intel["isp"],
        abuse_score=intel["score"],
        threat_level=intel["level"]
    )

    db.add(log)
    db.commit()

    # Always fail (honeypot behavior)
    return {"message": "Invalid credentials"}

@app.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    logs = db.query(HoneypotLog).all()

    return {
        "total_attempts": len(logs),
        "malicious": len([l for l in logs if l.threat_level == "Malicious"]),
        "suspicious": len([l for l in logs if l.threat_level == "Suspicious"]),
        "low": len([l for l in logs if l.threat_level == "Low"])
    }
