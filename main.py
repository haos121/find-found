# time и jwt для создания токена
import time
from datetime import timedelta
# from jwt import encode, decode


# FastAPI
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.exceptions import HTTPException
# from fastapi.templating import Jinja2Templates


# база данных
import sqlite3


# pydentic схемы
# from schemes import Form, Token, Post, Coment, Reaction, DeletePost


# подключение к FastAPI
app = FastAPI()

# путь к статическим файлам таким как CSS
app.mount("/static", StaticFiles(directory="static"), name="static")


# ссылки на все страницы
@app.get("/", tags=["lincs"])
def root():
    return FileResponse("pages/main.html")


# запуск веб приложения
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8657,
        reload=True
    )