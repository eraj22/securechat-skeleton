"""
Protocol message models using Pydantic
"""
from typing import Optional
from pydantic import BaseModel


class HelloMessage(BaseModel):
    type: str = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64


class ServerHelloMessage(BaseModel):
    type: str = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64


class RegisterMessage(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64


class LoginMessage(BaseModel):
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str  # base64


class DHClientMessage(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p


class DHServerMessage(BaseModel):
    type: str = "dh_server"
    B: int  # g^b mod p


class ChatMessage(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int  # unix timestamp in milliseconds
    ct: str  # base64 ciphertext
    sig: str  # base64 RSA signature


class SessionReceipt(BaseModel):
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64 RSA signature


class ResponseMessage(BaseModel):
    type: str = "response"
    status: str  # "ok" or "error"
    message: Optional[str] = None
