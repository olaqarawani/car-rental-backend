from __future__ import annotations

import shutil
import uuid
import base64
import hmac
import json
import os
from datetime import date
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile  # type: ignore[import]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[import]
from fastapi.exceptions import RequestValidationError  # type: ignore[import]
from fastapi.responses import JSONResponse  # type: ignore[import]
from fastapi.staticfiles import StaticFiles  # type: ignore[import]
from pydantic import BaseModel, EmailStr, Field, field_validator  # type: ignore[import]

from database import (
    BASE_DIR,
    IMAGES_DIR,
    get_connection,
    hash_password,
    init_db,
    row_to_dict,
    rows_to_dicts,
    verify_password,
)


app = FastAPI(title="Car Rental API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/images", StaticFiles(directory=IMAGES_DIR), name="images")
SECRET_KEY = os.environ.get("CAR_RENTAL_SECRET", "change-me-before-production")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError):
    first_error = exc.errors()[0] if exc.errors() else {}
    message = first_error.get("msg", "Invalid request")
    return JSONResponse(
        status_code=200,
        content={"success": False, "message": message},
    )


class RegisterRequest(BaseModel):
    name: str = Field(min_length=3)
    email: EmailStr
    password: str = Field(min_length=8)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.strip().split())
        if len(value) < 3:
            raise ValueError("Name must be at least 3 characters")
        return value

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(ch.isalpha() for ch in value) or not any(ch.isdigit() for ch in value):
            raise ValueError("Password must contain letters and numbers")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class CarRequest(BaseModel):
    type: str = Field(min_length=2)
    price_per_day: float = Field(gt=0)
    description: str = ""
    image: str = ""


class CarUpdateRequest(CarRequest):
    id: int


class IdRequest(BaseModel):
    id: int


class BookingCreateRequest(BaseModel):
    customer_id: int
    car_id: int
    pickup_location: str = Field(min_length=2)
    dropoff_location: str = Field(min_length=2)
    start_date: date
    end_date: date


class BookingStatusRequest(BaseModel):
    id: int
    status: str


class BookingCancelRequest(BaseModel):
    booking_id: int | None = None
    customer_id: int | None = None
    id: int | None = None


class UserUpdateRequest(BaseModel):
    name: str = Field(min_length=3)
    email: EmailStr
    profile_image: str = ""

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.strip().split())
        if len(value) < 3:
            raise ValueError("Name must be at least 3 characters")
        return value


def create_token(user: dict) -> str:
    payload = {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_part = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_part.encode("utf-8"),
        "sha256",
    ).digest()
    signature_part = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
    return f"{payload_part}.{signature_part}"


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def health() -> dict:
    return {"success": True, "message": "Car Rental API is running"}


@app.post("/register")
def register(payload: RegisterRequest) -> dict:
    name = payload.name.strip()
    email = payload.email.lower().strip()

    with get_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return {"success": False, "message": "Email already exists"}

        cursor = conn.execute(
            """
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, 'customer')
            """,
            (name, email, hash_password(payload.password)),
        )

        user = {
            "id": cursor.lastrowid,
            "name": name,
            "email": email,
            "role": "customer",
            "profile_image": "",
        }
        return {"success": True, "user": user, "token": create_token(user)}


@app.post("/login")
def login(payload: LoginRequest) -> dict:
    with get_connection() as conn:
        user = conn.execute(
            "SELECT id, name, email, role, password, profile_image FROM users WHERE email = ? LIMIT 1",
            (payload.email.lower().strip(),),
        ).fetchone()

    if not user or not verify_password(payload.password, user["password"]):
        return {"success": False, "message": "Invalid email or password"}

    user_data = {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "profile_image": user["profile_image"],
    }

    return {
        "success": True,
        "user": user_data,
        "token": create_token(user_data),
    }


@app.get("/users/{user_id}")
def get_user(user_id: int) -> dict:
    with get_connection() as conn:
        user = conn.execute(
            """
            SELECT id, name, email, role, profile_image
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    if not user:
        return {"success": False, "message": "User not found"}

    return {"success": True, "user": row_to_dict(user)}


@app.put("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdateRequest) -> dict:
    email = payload.email.lower().strip()

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            (email, user_id),
        ).fetchone()
        if existing:
            return {"success": False, "message": "Email already exists"}

        cursor = conn.execute(
            """
            UPDATE users
            SET name = ?, email = ?, profile_image = ?
            WHERE id = ?
            """,
            (
                payload.name,
                email,
                payload.profile_image.strip(),
                user_id,
            ),
        )
        if cursor.rowcount == 0:
            return {"success": False, "message": "User not found"}

        user = conn.execute(
            """
            SELECT id, name, email, role, profile_image
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    user_data = row_to_dict(user)
    return {
        "success": True,
        "user": user_data,
        "token": create_token(user_data),
    }


@app.get("/cars")
def get_cars() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, type, price_per_day, available, description, image
            FROM cars
            ORDER BY id DESC
            """
        ).fetchall()
    return rows_to_dicts(rows)


@app.get("/cars/available")
def get_available_cars() -> dict:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, type, price_per_day, image
            FROM cars
            WHERE available = 1
            ORDER BY type ASC
            """
        ).fetchall()
    return {"success": True, "data": rows_to_dicts(rows)}


@app.get("/cars/{car_id}")
def get_car(car_id: int) -> dict:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT id, type, price_per_day, available, description, image
            FROM cars
            WHERE id = ?
            """,
            (car_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Car not found")
    return row_to_dict(row)


@app.post("/cars")
def add_car(payload: CarRequest) -> dict:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO cars (type, price_per_day, description, image, available)
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                payload.type.strip(),
                payload.price_per_day,
                payload.description.strip(),
                payload.image.strip(),
            ),
        )
    return {"success": True, "id": cursor.lastrowid}


@app.put("/cars")
def update_car(payload: CarUpdateRequest) -> dict:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE cars
            SET type = ?, price_per_day = ?, description = ?, image = ?
            WHERE id = ?
            """,
            (
                payload.type.strip(),
                payload.price_per_day,
                payload.description.strip(),
                payload.image.strip(),
                payload.id,
            ),
        )
        if cursor.rowcount == 0:
            return {"success": False, "message": "Car not found"}
    return {"success": True}


@app.delete("/cars")
def delete_car(payload: IdRequest) -> dict:
    with get_connection() as conn:
        car = conn.execute("SELECT image FROM cars WHERE id = ?", (payload.id,)).fetchone()
        if not car:
            return {"success": False, "message": "Car not found"}
        conn.execute("DELETE FROM cars WHERE id = ?", (payload.id,))

    if car["image"]:
        image_path = IMAGES_DIR / Path(car["image"]).name
        if image_path.exists():
            image_path.unlink()

    return {"success": True}


@app.post("/upload-image")
def upload_image(image: UploadFile = File(...)) -> dict:
    extension = Path(image.filename or "").suffix.lower()
    if extension not in {".jpg", ".jpeg", ".png", ".webp", ".jfif"}:
        raise HTTPException(status_code=400, detail="Unsupported image type")

    filename = f"{uuid.uuid4().hex}{extension}"
    destination = IMAGES_DIR / filename

    with destination.open("wb") as output:
        shutil.copyfileobj(image.file, output)

    return {"filename": filename}


@app.get("/bookings")
def get_bookings() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                b.id,
                b.car_id,
                b.start_date,
                b.end_date,
                b.status,
                b.pickup_location,
                b.dropoff_location,
                b.total_price,
                c.type AS car_type,
                c.image AS image,
                u.name AS customer_name
            FROM bookings b
            JOIN cars c ON b.car_id = c.id
            JOIN users u ON b.customer_id = u.id
            ORDER BY b.start_date ASC
            """
        ).fetchall()
    return rows_to_dicts(rows)


@app.put("/bookings")
def update_booking_status(payload: BookingStatusRequest) -> dict:
    new_status = payload.status.lower().strip()
    if new_status not in {"pending", "approved", "rejected", "completed"}:
        return {"success": False, "message": "Invalid status"}

    with get_connection() as conn:
        booking = conn.execute(
            "SELECT car_id FROM bookings WHERE id = ?",
            (payload.id,),
        ).fetchone()
        if not booking:
            return {"success": False, "message": "Booking not found"}

        conn.execute(
            "UPDATE bookings SET status = ? WHERE id = ?",
            (new_status, payload.id),
        )

        if new_status == "approved":
            conn.execute("UPDATE cars SET available = 0 WHERE id = ?", (booking["car_id"],))
        elif new_status in {"completed", "rejected"}:
            conn.execute("UPDATE cars SET available = 1 WHERE id = ?", (booking["car_id"],))

    return {"success": True, "booking_id": payload.id, "status": new_status}


@app.post("/bookings")
def create_booking(payload: BookingCreateRequest) -> dict:
    if payload.end_date < payload.start_date:
        return {"success": False, "message": "Invalid date range"}

    with get_connection() as conn:
        car = conn.execute(
            "SELECT price_per_day, available FROM cars WHERE id = ?",
            (payload.car_id,),
        ).fetchone()
        if not car:
            return {"success": False, "message": "Car not found"}
        if int(car["available"]) != 1:
            return {"success": False, "message": "Car is not available"}

        conflict = conn.execute(
            """
            SELECT id FROM bookings
            WHERE car_id = ?
              AND status IN ('pending', 'approved')
              AND NOT (end_date < ? OR start_date > ?)
            LIMIT 1
            """,
            (payload.car_id, payload.start_date.isoformat(), payload.end_date.isoformat()),
        ).fetchone()
        if conflict:
            return {
                "success": False,
                "message": "Car is already booked for the selected dates",
            }

        days = (payload.end_date - payload.start_date).days + 1
        total_price = days * float(car["price_per_day"])
        cursor = conn.execute(
            """
            INSERT INTO bookings
            (customer_id, car_id, start_date, end_date, pickup_location, dropoff_location, total_price, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                payload.customer_id,
                payload.car_id,
                payload.start_date.isoformat(),
                payload.end_date.isoformat(),
                payload.pickup_location.strip(),
                payload.dropoff_location.strip(),
                total_price,
            ),
        )

    return {"success": True, "booking_id": cursor.lastrowid}


@app.get("/bookings/customer/{customer_id}")
def get_customer_bookings(customer_id: int) -> dict:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                b.id,
                b.start_date,
                b.end_date,
                b.status,
                b.pickup_location,
                b.dropoff_location,
                c.type AS car_type,
                c.image
            FROM bookings b
            JOIN cars c ON b.car_id = c.id
            WHERE b.customer_id = ?
            ORDER BY b.start_date DESC
            """,
            (customer_id,),
        ).fetchall()
    return {"success": True, "data": rows_to_dicts(rows)}


@app.get("/bookings/{booking_id}")
def get_booking_details(booking_id: int) -> dict:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                b.id,
                b.start_date,
                b.end_date,
                b.status,
                b.pickup_location AS pickup,
                b.dropoff_location AS dropoff,
                b.total_price,
                c.type AS car_name
            FROM bookings b
            JOIN cars c ON b.car_id = c.id
            WHERE b.id = ?
            """,
            (booking_id,),
        ).fetchone()

    if not row:
        return {"success": False, "message": "Booking not found"}
    return {"success": True, "data": row_to_dict(row)}


@app.post("/bookings/cancel")
def cancel_booking(payload: BookingCancelRequest) -> dict:
    booking_id = payload.booking_id or payload.id
    if booking_id is None:
        return {"success": False, "message": "Missing booking id"}

    with get_connection() as conn:
        params: tuple = (booking_id,)
        customer_clause = ""
        if payload.customer_id is not None:
            customer_clause = " AND customer_id = ?"
            params = (booking_id, payload.customer_id)

        cursor = conn.execute(
            f"""
            DELETE FROM bookings
            WHERE id = ?{customer_clause} AND LOWER(status) = 'pending'
            """,
            params,
        )

    return {"success": cursor.rowcount > 0}
