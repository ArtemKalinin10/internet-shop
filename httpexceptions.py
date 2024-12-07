from fastapi import HTTPException

registered_user =  HTTPException(status_code=400, detail="User already registered")
inc_user_or_pas = HTTPException(status_code=401, detail="Incorrect username or password")
inv_ref_tk =  HTTPException(status_code=401, detail="Invalid refresh token")
exp_token = HTTPException(status_code=401, detail="Token has expired")
credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
