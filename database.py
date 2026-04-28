import pymysql

def get_db():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="car_rental",
        cursorclass=pymysql.cursors.DictCursor
    )