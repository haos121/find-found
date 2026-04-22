# ==========================================
# FIND & FOUND - BACKEND ПРИЛОЖЕНИЕ
# FastAPI приложение с JWT аутентификацией
# ==========================================

# ===== ИМПОРТЫ СТАНДАРТНОЙ БИБЛИОТЕКИ =====
import time  # для работы с временем
from datetime import timedelta  # для установки времени истечения токена
import hashlib  # для хеширования
import os  # для работы с операционной системой
from pathlib import Path  # для работы с путями файлов
import shutil  # для работы с файлами

# ===== ИМПОРТЫ ДЛЯ АУТЕНТИФИКАЦИИ =====
from jwt import encode, decode  # для создания и проверки JWT токенов

# ===== ИМПОРТЫ FastAPI =====
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, UploadFile, File
from fastapi.staticfiles import StaticFiles  # для обслуживания статических файлов
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer

# ===== ИМПОРТЫ PYDANTIC =====
from pydantic import BaseModel  # для определения моделей данных

# ===== ИМПОРТЫ БАЗЫ ДАННЫХ =====
import sqlite3  # для работы с SQLite базой данных

# ===== ИМПОРТЫ ДЛЯ ХЕШИРОВАНИЯ ПАРОЛЕЙ =====
from passlib.context import CryptContext  # для хеширования паролей

# ===== PYDANTIC МОДЕЛИ ДАННЫХ =====
# Эти модели используются для валидации данных от клиента

class UserCreate(BaseModel):
    """Модель для создания пользователя"""
    username: str  # Имя пользователя
    password: str  # Пароль

class User(BaseModel):
    """Модель для представления пользователя"""
    id: int  # ID пользователя
    username: str  # Имя пользователя

class Token(BaseModel):
    """Модель для JWT токена"""
    access_token: str  # Сам токен
    token_type: str  # Тип токена (обычно "bearer")

class ProductAdd(BaseModel):
    """Модель для добавления товара в корзину"""
    product_id: int  # ID товара
    quantity: int = 1  # Количество (по умолчанию 1)


# ===== ИНИЦИАЛИЗАЦИЯ FastAPI =====
app = FastAPI()

# ===== КОНФИГУРАЦИЯ ЗАГРУЗКИ ФАЙЛОВ =====
# Создаем директорию для хранения загруженных изображений
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# ===== МОНТИРОВАНИЕ СТАТИЧЕСКИХ ФАЙЛОВ =====
# CSS, JavaScript и другие статические файлы
app.mount("/static", StaticFiles(directory="static"), name="static")
# Загруженные изображения товаров
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# ===== КОНФИГУРАЦИЯ JWT =====
SECRET_KEY = "your-secret-key"  # Секретный ключ для подписи токенов
ALGORITHM = "HS256"  # Алгоритм подписи
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Время жизни токена (30 минут)

# ===== КОНФИГУРАЦИЯ ХЕШИРОВАНИЯ ПАРОЛЕЙ =====
# Используем bcrypt для безопасного хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ===== SECURITY BEARER =====
security = HTTPBearer()

# ===== ФУНКЦИИ ДЛЯ РАБОТЫ С JWT =====

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Создает JWT токен для аутентификации пользователя
    
    Args:
        data: Словарь данных для включения в токен (обычно {"sub": username})
        expires_delta: Опциональная дельта времени для истечения токена
    
    Returns:
        str: Закодированный JWT токен
    """
    to_encode = data.copy()
    
    # Устанавливаем время истечения токена
    if expires_delta:
        expire = time.time() + expires_delta.total_seconds()
    else:
        expire = time.time() + 15 * 60  # По умолчанию 15 минут
    
    # Добавляем время истечения в payload
    to_encode.update({"exp": expire})
    
    # Кодируем токен с использованием SECRET_KEY
    encoded_jwt = encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(request: Request):
    """
    Проверяет JWT токен из cookie
    
    Args:
        request: FastAPI Request объект
    
    Returns:
        str: Имя пользователя из токена
    
    Raises:
        HTTPException: Если токен отсутствует или невалиден
    """
    # Получаем токен из httpOnly cookie
    token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Декодируем и проверяем токен
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return username
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# ===== ФУНКЦИИ ДЛЯ РАБОТЫ С ПАРОЛЯМИ =====

def hash_password(password: str):
    """
    Хеширует пароль с использованием SHA256 и bcrypt
    
    Args:
        password: Открытый пароль
    
    Returns:
        str: Хешированный пароль
    """
    # Сначала хешируем с SHA256
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """
    Проверяет, совпадает ли открытый пароль с хешированным
    
    Args:
        plain_password: Открытый пароль
        hashed_password: Хешированный пароль из БД
    
    Returns:
        bool: True если пароли совпадают, False иначе
    """
    
    # Проверяем с хешированным паролем из БД
    return pwd_context.verify(plain_password, hashed_password)

# ===== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ =====

def init_db():
    """
    Инициализирует базу данных SQLite
    Создает таблицы: users, products, basket
    Создает администратора по умолчанию
    """
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    # ТАБЛИЦА ПОЛЬЗОВАТЕЛЕЙ
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    )''')
    
    # ТАБЛИЦА ТОВАРОВ
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        image TEXT
    )''')
    
    # ТАБЛИЦА КОРЗИНЫ
    c.execute('''CREATE TABLE IF NOT EXISTS basket (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (product_id) REFERENCES products (id)
    )''')
    
    # Создаем администратора, если его еще нет
    c.execute("SELECT id FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_password = hash_password("11111111")
        c.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (hashed_password,))
    
    conn.commit()
    conn.close()

# Инициализируем БД при запуске приложения
init_db()


# ===== МАРШРУТЫ СТРАНИЦ =====

@app.get("/", tags=["pages"])
def root():
    """Главная страница с каталогом товаров"""
    return FileResponse("static/main.html")

@app.get("/signin", tags=["pages"])
def get_signin():
    """Страница входа"""
    return FileResponse("static/signin.html")

@app.get("/signup", tags=["pages"])
def get_signup():
    """Страница регистрации"""
    return FileResponse("static/signup.html")

@app.get("/basket", tags=["pages"])
def get_basket(request: Request):
    """Страница корзины (требует авторизации)"""
    username = verify_token(request)
    return FileResponse("static/basket.html")

@app.get("/admin", tags=["pages"])
def get_admin(request: Request):
    """Админ-панель (только для администратора)"""
    username = verify_token(request)
    if username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return FileResponse("static/admin.html")

# ===== МАРШРУТЫ АУТЕНТИФИКАЦИИ =====

@app.post("/signin")
def signin(username: str = Form(...), password: str = Form(...)):
    """
    Вход пользователя в систему
    Проверяет учетные данные и устанавливает JWT cookie
    
    Args:
        username: Имя пользователя
        password: Пароль
    
    Returns:
        RedirectResponse: Перенаправляет на главную страницу при успехе
    """
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    # Ищем пользователя в БД
    c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    # Проверяем пароль
    if result and verify_password(password, result[1]):
        # Создаем JWT токен
        access_token = create_access_token(data={"sub": username})
        
        # Создаем редирект с установкой cookie
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,  # Недоступен для JavaScript
            samesite="lax"   # Защита от CSRF
        )
        return response
    
    raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.post("/signup")
def signup(username: str = Form(...), password: str = Form(...)):
    """
    Регистрация нового пользователя
    Создает учетную запись и автоматически авторизует пользователя
    
    Args:
        username: Новое имя пользователя
        password: Пароль (должен быть минимум 6 символов)
    
    Returns:
        RedirectResponse: Перенаправляет на главную страницу
    """
    # Проверяем минимальную длину пароля
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    # Ограничиваем пароль до 71 символа для bcrypt (max 72 bytes)
    password = password[:71]
    
    # Хешируем пароль
    hashed_password = hash_password(password)
    
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    try:
        # Вставляем нового пользователя
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        
        # Автоматически логиним пользователя после регистрации
        access_token = create_access_token(data={"sub": username})
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="lax"
        )
        return response
    except sqlite3.IntegrityError:
        # Пользователь уже существует
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

@app.get("/logout")
def logout():
    """
    Выход пользователя из системы
    Удаляет JWT cookie
    """
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(key="access_token")
    return response

@app.get("/check-admin")
def check_admin(request: Request):
    """
    Проверяет, авторизован ли пользователь и является ли администратором
    Используется для управления видимостью UI элементов
    
    Returns:
        dict: {"is_admin": bool, "authenticated": bool}
    """
    try:
        username = verify_token(request)
        return {
            "is_admin": username == "admin",
            "authenticated": True
        }
    except:
        return {
            "is_admin": False,
            "authenticated": False
        }

# ===== МАРШРУТЫ АДМИНИСТРАТОРА =====

@app.get("/admin/users")
def get_users(request: Request):
    """
    Получить список всех пользователей (только для администратора)
    
    Returns:
        dict: {"users": [{"username": str}, ...]}
    """
    username = verify_token(request)
    if username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    users = c.fetchall()
    conn.close()
    
    return {"users": [{"username": u[0]} for u in users]}

# ===== МАРШРУТЫ ТОВАРОВ =====

@app.get("/api/products")
def get_products(search: str = ""):
    """
    Получить список товаров с опциональным поиском
    
    Args:
        search: Строка поиска по названию товара
    
    Returns:
        dict: {"products": [{"id": int, "name": str, "price": float, "image": str}, ...]}
    """
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    # Если есть поисковый запрос, фильтруем товары
    if search:
        c.execute(
            "SELECT id, name, price, image FROM products WHERE name LIKE ?",
            (f"%{search}%",)
        )
    else:
        c.execute("SELECT id, name, price, image FROM products")
    
    products = c.fetchall()
    conn.close()
    
    return {
        "products": [
            {
                "id": p[0],
                "name": p[1],
                "price": p[2],
                "image": p[3] or ""
            } for p in products
        ]
    }

@app.post("/api/products")
def create_product(
    request: Request,
    name: str = Form(...),
    price: float = Form(...),
    image: UploadFile = File(None)
):
    """
    Создать новый товар (только для администратора)
    Обрабатывает загрузку изображения товара
    
    Args:
        request: FastAPI Request для проверки авторизации
        name: Название товара
        price: Цена товара
        image: Опциональный файл изображения
    
    Returns:
        dict: Данные созданного товара
    """
    # Проверяем, что пользователь администратор
    username = verify_token(request)
    if username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    image_path = None
    
    # Если изображение загружено
    if image:
        import uuid
        
        # Генерируем уникальное имя файла
        file_ext = Path(image.filename).suffix
        unique_filename = f"{uuid.uuid4()}{file_ext}"
        file_location = UPLOAD_DIR / unique_filename
        
        # Сохраняем файл на диск
        with open(file_location, "wb") as f:
            shutil.copyfileobj(image.file, f)
        
        # Сохраняем путь к изображению
        image_path = f"/uploads/{unique_filename}"
    
    # Вставляем товар в БД
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO products (name, price, image) VALUES (?, ?, ?)",
        (name, price, image_path)
    )
    conn.commit()
    product_id = c.lastrowid
    conn.close()
    
    return {
        "id": product_id,
        "name": name,
        "price": price,
        "image": image_path or ""
    }

@app.delete("/api/products/{product_id}")
def delete_product(request: Request, product_id: int):
    """
    Удалить товар (только для администратора)
    
    Args:
        request: FastAPI Request для проверки авторизации
        product_id: ID товара для удаления
    
    Returns:
        dict: Сообщение об успехе
    """
    # Проверяем, что пользователь администратор
    username = verify_token(request)
    if username != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Удаляем товар из БД
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    c.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    
    return {"message": "Product deleted"}

# ===== МАРШРУТЫ КОРЗИНЫ =====

@app.get("/api/basket")
def get_basket_api(request: Request):
    """
    Получить содержимое корзины текущего пользователя
    
    Returns:
        dict: {"basket": [{"id": int, "product_id": int, "name": str, "price": float, "quantity": int, "image": str}, ...]}
    """
    # Проверяем авторизацию
    username = verify_token(request)
    
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    # Получаем ID пользователя
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()[0]
    
    # Получаем товары из корзины с информацией о товарах
    c.execute("""
        SELECT b.id, p.id, p.name, p.price, b.quantity, p.image 
        FROM basket b 
        JOIN products p ON b.product_id = p.id 
        WHERE b.user_id = ?
    """, (user_id,))
    
    items = c.fetchall()
    conn.close()
    
    return {
        "basket": [
            {
                "id": i[0],           # ID товара в корзине
                "product_id": i[1],   # ID товара
                "name": i[2],         # Название
                "price": i[3],        # Цена
                "quantity": i[4],     # Количество
                "image": i[5] or ""   # Изображение
            } for i in items
        ]
    }

@app.post("/api/basket/add")
def add_to_basket_api(request: Request, product: ProductAdd):
    """
    Добавить товар в корзину или увеличить количество
    Если товар уже в корзине, увеличивает количество
    
    Args:
        request: FastAPI Request для проверки авторизации
        product: Модель с product_id и quantity
    
    Returns:
        dict: Сообщение об успехе
    """
    # Проверяем авторизацию
    username = verify_token(request)
    
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    # Получаем ID пользователя
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()[0]
    
    # Проверяем, есть ли товар уже в корзине
    c.execute(
        "SELECT id, quantity FROM basket WHERE user_id = ? AND product_id = ?",
        (user_id, product.product_id)
    )
    existing = c.fetchone()
    
    if existing:
        # Если товар уже в корзине, увеличиваем количество
        c.execute(
            "UPDATE basket SET quantity = quantity + ? WHERE id = ?",
            (product.quantity, existing[0])
        )
    else:
        # Если товара нет, добавляем его
        c.execute(
            "INSERT INTO basket (user_id, product_id, quantity) VALUES (?, ?, ?)",
            (user_id, product.product_id, product.quantity)
        )
    
    conn.commit()
    conn.close()
    
    return {"message": "Added to basket"}

@app.delete("/api/basket/{item_id}")
def remove_from_basket(request: Request, item_id: int):
    """
    Удалить товар из корзины
    
    Args:
        request: FastAPI Request для проверки авторизации
        item_id: ID товара в корзине
    
    Returns:
        dict: Сообщение об успехе
    """
    # Проверяем авторизацию
    username = verify_token(request)
    
    conn = sqlite3.connect('find_found.db')
    c = conn.cursor()
    
    # Проверяем, существует ли товар в корзине
    c.execute("SELECT user_id FROM basket WHERE id = ?", (item_id,))
    result = c.fetchone()
    
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="Item not found")
    
    # Получаем ID пользователя
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = c.fetchone()[0]
    
    # Проверяем, что товар принадлежит текущему пользователю
    if result[0] != user_id:
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Удаляем товар
    c.execute("DELETE FROM basket WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    
    return {"message": "Item removed"}

# ===== ЗАПУСК ПРИЛОЖЕНИЯ =====

if __name__ == "__main__":
    """
    Запуск FastAPI приложения с использованием Uvicorn
    
    Parameters:
        host: Адрес, на котором слушается сервер (127.0.0.1 - только локально)
        port: Порт сервера (8657)
        reload: Автоматическая перезагрузка при изменении файлов (для разработки)
    """
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8657,
        reload=True
    )