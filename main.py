import uvicorn
from fastapi import FastAPI
from users_router import users_router

app = FastAPI()
app.include_router(users_router)
    

if __name__ == '__main__':
    uvicorn.run(app)
    
print('Hello World')
print('2')