
from fastapi import FastAPI
import database
import auth
import crud
import audit

app = FastAPI()

# Importar routers
app.include_router(auth.router)
app.include_router(crud.router)
app.include_router(audit.router)


@app.on_event("startup")
def startup_event():
    database.init_db()
    auth.create_admin_user()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
