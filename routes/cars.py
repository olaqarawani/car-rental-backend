from fastapi import APIRouter
from database import get_db

router = APIRouter()

@router.get("/cars")
def get_cars():
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM cars")
        cars = cursor.fetchall()

        db.close()
        return cars

    except Exception as e:
        return {"error": str(e)}