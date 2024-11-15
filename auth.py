from fastapi import HTTPException, Security
import jwt
from passlib.context import CryptContext
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from datetime import datetime, timedelta, timezone

class AuthHandler():
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = 'tanmay_boss'
    
    def get_password_hash(self, password):
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def encode_token(self, user_id):
        payload = {
            'exp': datetime.now(timezone.utc) + timedelta(days=0, minutes=5),
            'iat': datetime.now(timezone.utc),
            'sub': user_id
        }
        return jwt.encode(
            payload, 
            self.secret,
            algorithm='HS256'
        )
    
    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invlalid Token')
        
    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)): 
        return self.decode_token(auth.credentials)

    # the last function paramter check if the token is present in the header with Bearer word


