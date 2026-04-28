from fastapi import FastAPI
from routes.cars import router as cars_router

app = FastAPI()

app.include_router(cars_router)

@app.get("/")
def root():
    return {"status": "API is running"}
