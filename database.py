from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "car_rental.db"
IMAGES_DIR = BASE_DIR / "images"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [dict(row) for row in rows]


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    ).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, salt, digest = stored_hash.split("$", 2)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    return hash_password(password, salt).split("$", 2)[2] == digest


def init_db() -> None:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)

    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('manager', 'customer')),
                profile_image TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS cars (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                price_per_day REAL NOT NULL,
                available INTEGER NOT NULL DEFAULT 1,
                description TEXT NOT NULL DEFAULT '',
                image TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                car_id INTEGER NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'approved', 'rejected', 'completed')),
                pickup_location TEXT NOT NULL,
                dropoff_location TEXT NOT NULL,
                total_price REAL NOT NULL,
                FOREIGN KEY(customer_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(car_id) REFERENCES cars(id) ON DELETE CASCADE
            );
            """
        )

        user_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "profile_image" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN profile_image TEXT NOT NULL DEFAULT ''"
            )

        user_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if user_count == 0:
            conn.executemany(
                """
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
                """,
                [
                    ("Ola", "admin@carrental.com", hash_password("admin123"), "manager"),
                    ("Customer", "customer@carrental.com", hash_password("customer123"), "customer"),
                ],
            )
        else:
            conn.execute(
                "UPDATE users SET email = ? WHERE email = ?",
                ("admin@carrental.com", "admin@car-rental.test"),
            )
            conn.execute(
                "UPDATE users SET email = ? WHERE email = ?",
                ("customer@carrental.com", "customer@car-rental.test"),
            )

        car_count = conn.execute("SELECT COUNT(*) AS count FROM cars").fetchone()["count"]
        if car_count == 0:
            conn.executemany(
                """
                INSERT INTO cars (type, price_per_day, available, description, image)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    ("SUV", 110, 1, "Spacious SUV suitable for families and long trips.", "suv1.jpg"),
                    ("Sedan", 120, 1, "Comfortable sedan for daily city driving and business trips.", "sedan.jpeg"),
                    ("Hatchback", 160, 1, "Compact hatchback with easy parking and efficient fuel use.", "Hatchback.webp"),
                    ("Luxury", 200, 1, "Premium car with advanced features and a refined cabin.", "Luxury.jpg"),
                    ("Convertible", 250, 1, "Open-road convertible for a stylish driving experience.", "Convertible.jpg"),
                    ("SUV", 220, 1, "High-comfort SUV with extra luggage space.", "suv2.webp"),
                ],
            )
