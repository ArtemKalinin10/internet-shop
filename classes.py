from pydantic import BaseModel

class UserModel(BaseModel):
    usern: str
    pas: str

class UserModelUpdate(BaseModel):
    usern: str
    newusern: str
    newpas: str
    
class TokenModel(BaseModel):
    token: str