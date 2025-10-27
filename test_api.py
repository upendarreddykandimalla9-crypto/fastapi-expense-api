from fastapi.testclient import TestClient
from app import app

c = TestClient(app)

def test_flow():
    r = c.post("/signup", json={"email":"a@b.com","password":"x"})
    assert r.status_code==200
    tok = r.json()["token"]
    r = c.post("/expenses", headers={"Authorization": f"Bearer {tok}"}, json={"amount": 12.5, "category":"Meals", "note":"coffee"})
    assert r.status_code==200
    r = c.get("/expenses", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code==200 and len(r.json())>=1
