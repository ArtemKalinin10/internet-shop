import pymysql as pymy
from classes import UserModel, UserModelUpdate, TokenModel
from httpexceptions import registered_user, inc_user_or_pas, inv_ref_tk, exp_token, credentials_exception
from secr import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_MINUTES, USER_DATA_BASE, PASSWORD_DATA_BASE, DB_NAME
from sh_ps import decrypt, encrypt
from fastapi import APIRouter
from jose import JWTError, jwt, ExpiredSignatureError
from datetime import timedelta, datetime


users_router = APIRouter(prefix='/users', tags=['registration and authorization'])

connection = pymy.connect(
    port=3306,
    user=USER_DATA_BASE,
    password=PASSWORD_DATA_BASE,
    db=DB_NAME,
    cursorclass=pymy.cursors.DictCursor
)

def get_user(usern: str):
    with connection.cursor() as cur:
        cur.execute("SELECT password FROM users WHERE name = %s", usern)
        a = cur.fetchone()
        return a['password'] if a else None


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire.timestamp()})
    return jwt.encode(to_encode, key=SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta if expires_delta else timedelta(days=7))
    to_encode.update({"exp": expire.timestamp()})
    return jwt.encode(to_encode, key=SECRET_KEY, algorithm=ALGORITHM)


@users_router.post('/reg')
def register(usermodel: UserModel):
    try:
        with connection.cursor() as con:
            con.execute("INSERT INTO users (name, password) VALUES (%s, %s)", (usermodel.usern, encrypt(usermodel.pas)))
            connection.commit()
    except pymy.IntegrityError:
        raise registered_user
    else:
        return {'responce': 'User registered successfully'}


@users_router.post('/authorization')
def authorization(usermodel: UserModel):
    ans = get_user(usermodel.usern)
    if ans is None:
        raise inc_user_or_pas
    elif decrypt(ans) == usermodel.pas:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": usermodel.usern}, expires_delta=access_token_expires)
        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
        refresh_token = create_refresh_token(data={"sub": usermodel.usern}, expires_delta=refresh_token_expires)
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    raise inc_user_or_pas


@users_router.post("/refresh_token")
def refresh_token(tokenmodel: TokenModel):
    try:
        payload = jwt.decode(tokenmodel.token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise inv_ref_tk
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(data={"sub": username}, expires_delta=access_token_expires)

        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
        new_refresh_token = create_refresh_token(data={"sub": username}, expires_delta=refresh_token_expires)

        return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except JWTError:
        raise inv_ref_tk

@users_router.get("/me")
def read_users_me(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise exp_token
    except JWTError:
        raise credentials_exception

    return {"username": username}

@users_router.patch("/update")
def update_user(user: UserModelUpdate):
    try:
        with connection.cursor() as cur:
            cur.execute('UPDATE users SET name = %s, password = %s WHERE name = %s', (user.newusern, encrypt(user.newpas), user.usern))
            connection.commit()
    except pymy.IntegrityError:
        raise registered_user
    else:
        return {'responce': 'Name Changed'}