"""
Secure Chat Server
Handles client connections, authentication, and encrypted messaging
"""
import os
import json
import socket
import threading
from dotenv import load_dotenv
from app.common.protocol import *
from app.common.utils import *
from app.crypto.pki import *
from app.crypto.dh import *
from app.crypto.aes import *
from app.crypto.sign import *
from app.storage.db import Database
from app.storage.transcript import Transcript

load_dotenv()


class SecureChatServer:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        
        # Load server certificate and key
        self.server_cert = load_certificate_from_file(os.getenv('SERVER_CERT_PATH'))
        self.server_key = load_private_key_from_file(os.getenv('SERVER_KEY_PATH'))
        self.ca_cert = load_certificate_from_file(os.getenv('CA_CERT_PATH'))
        
        # Database
        self.db = Database()
        
        print(f"[SERVER] Initialized on {self.host}:{self.port}")
        print(f"[SERVER] Server CN: {get_common_name(self.server_cert)}")
    
    def handle_client(self, conn: socket.socket, addr):
        """Handle individual client connection"""
        print(f"\n[SERVER] New connection from {addr}")
        
        client_cert = None
        session_key = None
        authenticated_user = None
        seqno = 0
        transcript = None
        
        try:
            # Phase 1: Certificate Exchange (Hello)
            print("[SERVER] Phase 1: Certificate Exchange")
            data = conn.recv(8192).decode()
            hello_msg = json.loads(data)
            
            if hello_msg['type'] != 'hello':
                conn.sendall(json.dumps({"type": "response", "status": "error", 
                                        "message": "Expected hello"}).encode())
                return
            
            # Validate client certificate
            client_cert = load_certificate(hello_msg['client_cert'])
            is_valid, error_msg = validate_certificate(client_cert, self.ca_cert)
            
            if not is_valid:
                print(f"[SERVER] {error_msg}")
                conn.sendall(json.dumps({"type": "response", "status": "error", 
                                        "message": error_msg}).encode())
                return
            
            print(f"[SERVER] Client certificate validated: {get_common_name(client_cert)}")
            
            # Send server hello
            server_hello = ServerHelloMessage(
                server_cert=export_certificate_pem(self.server_cert),
                nonce=b64encode_str(os.urandom(32))
            )
            conn.sendall(json.dumps(server_hello.dict()).encode())
            
            # Phase 2: Initial DH for Registration/Login
            print("[SERVER] Phase 2: Temporary DH for Authentication")
            data = conn.recv(8192).decode()
            dh_client_msg = json.loads(data)
            
            if dh_client_msg['type'] != 'dh_client':
                conn.sendall(json.dumps({"type": "response", "status": "error", 
                                        "message": "Expected dh_client"}).encode())
                return
            
            # Perform DH exchange
            temp_key, public_B = perform_dh_exchange_server(
                dh_client_msg['p'], 
                dh_client_msg['g'], 
                dh_client_msg['A']
            )
            
            dh_server_msg = DHServerMessage(B=public_B)
            conn.sendall(json.dumps(dh_server_msg.dict()).encode())
            
            print("[SERVER] Temporary session key established")
            
            # Phase 3: Registration or Login
            print("[SERVER] Phase 3: Authentication")
            data = conn.recv(8192).decode()
            encrypted_payload = json.loads(data)
            
            # Decrypt authentication message
            ciphertext = b64decode_str(encrypted_payload['payload'])
            auth_json = aes_decrypt(ciphertext, temp_key).decode()
            auth_msg = json.loads(auth_json)
            
            if auth_msg['type'] == 'register':
                print(f"[SERVER] Registration request for: {auth_msg['username']}")
                salt = b64decode_str(auth_msg['salt'])
                pwd_hash = auth_msg['pwd']
                
                success, message = self.db.register_user(
                    auth_msg['email'],
                    auth_msg['username'],
                    salt,
                    pwd_hash
                )
                
                response = ResponseMessage(
                    status="ok" if success else "error",
                    message=message
                )
                conn.sendall(json.dumps(response.dict()).encode())
                
                if not success:
                    return
                
                authenticated_user = auth_msg['username']
                print(f"[SERVER] User registered: {authenticated_user}")
            
            elif auth_msg['type'] == 'login':
                print(f"[SERVER] Login request for: {auth_msg['email']}")
                
                # Get user salt
                user = self.db.get_user_credentials(auth_msg['email'])
                if not user:
                    conn.sendall(json.dumps({"type": "response", "status": "error", 
                                            "message": "Invalid credentials"}).encode())
                    return
                
                # Send salt to client
                salt_response = {
                    "type": "response",
                    "status": "ok",
                    "salt": b64encode_str(user['salt'])
                }
                conn.sendall(json.dumps(salt_response).encode())
                
                # Receive password hash from client
                data = conn.recv(8192).decode()
                pwd_msg = json.loads(data)
                
                # Verify credentials
                success, username = self.db.verify_login(auth_msg['email'], pwd_msg['pwd_hash'])
                
                if not success:
                    conn.sendall(json.dumps({"type": "response", "status": "error", 
                                            "message": "Invalid credentials"}).encode())
                    return
                
                authenticated_user = username
                response = ResponseMessage(status="ok", message=f"Welcome back, {username}!")
                conn.sendall(json.dumps(response.dict()).encode())
                print(f"[SERVER] User logged in: {authenticated_user}")
            
            else:
                conn.sendall(json.dumps({"type": "response", "status": "error", 
                                        "message": "Invalid auth type"}).encode())
                return
            
            # Phase 4: Session DH for Chat
            print("[SERVER] Phase 4: Session Key Establishment")
            data = conn.recv(8192).decode()
            dh_client_msg = json.loads(data)
            
            session_key, public_B = perform_dh_exchange_server(
                dh_client_msg['p'],
                dh_client_msg['g'],
                dh_client_msg['A']
            )
            
            dh_server_msg = DHServerMessage(B=public_B)
            conn.sendall(json.dumps(dh_server_msg.dict()).encode())
            
            print("[SERVER] Chat session key established")
            
            # Initialize transcript
            transcript = Transcript(f"transcripts/server_{authenticated_user}_{now_ms()}.txt")
            client_fingerprint = get_certificate_fingerprint(client_cert)
            
            # Phase 5: Encrypted Chat
            print("[SERVER] Phase 5: Encrypted Messaging Started")
            print("[SERVER] Type messages to send (or 'quit' to exit):\n")
            
            # Start thread for sending messages
            def send_messages():
                nonlocal seqno
                while True:
                    try:
                        msg = input()
                        if msg.lower() == 'quit':
                            break
                        
                        seqno += 1
                        timestamp = now_ms()
                        
                        # Encrypt message
                        ciphertext = aes_encrypt(msg.encode(), session_key)
                        ct_b64 = b64encode_str(ciphertext)
                        
                        # Sign message
                        digest_input = f"{seqno}{timestamp}{ct_b64}".encode()
                        digest = sha256_digest(digest_input)
                        signature = sign_data(digest, self.server_key)
                        sig_b64 = b64encode_str(signature)
                        
                        # Create message
                        chat_msg = ChatMessage(
                            seqno=seqno,
                            ts=timestamp,
                            ct=ct_b64,
                            sig=sig_b64
                        )
                        
                        conn.sendall(json.dumps(chat_msg.dict()).encode())
                        
                        # Add to transcript
                        server_fingerprint = get_certificate_fingerprint(self.server_cert)
                        transcript.add_entry(seqno, timestamp, ct_b64, sig_b64, server_fingerprint)
                        
                        print(f"[SENT] {msg}")
                    except:
                        break
            
            send_thread = threading.Thread(target=send_messages, daemon=True)
            send_thread.start()
            
            # Receive messages
            last_client_seqno = 0
            while True:
                data = conn.recv(8192).decode()
                if not data:
                    break
                
                msg = json.loads(data)
                
                if msg['type'] == 'msg':
                    # Verify sequence number
                    if msg['seqno'] <= last_client_seqno:
                        print(f"[SERVER] REPLAY detected! Rejecting message.")
                        continue
                    
                    last_client_seqno = msg['seqno']
                    
                    # Verify signature
                    digest_input = f"{msg['seqno']}{msg['ts']}{msg['ct']}".encode()
                    digest = sha256_digest(digest_input)
                    signature = b64decode_str(msg['sig'])
                    
                    if not verify_signature_with_cert(digest, signature, client_cert):
                        print(f"[SERVER] SIG_FAIL! Message rejected.")
                        continue
                    
                    # Decrypt message
                    ciphertext = b64decode_str(msg['ct'])
                    plaintext = aes_decrypt(ciphertext, session_key).decode()
                    
                    print(f"[RECEIVED] {plaintext}")
                    
                    # Add to transcript
                    transcript.add_entry(
                        msg['seqno'],
                        msg['ts'],
                        msg['ct'],
                        msg['sig'],
                        client_fingerprint
                    )
                
                elif msg['type'] == 'receipt':
                    print(f"[SERVER] Received client session receipt")
                    # Could verify receipt here
                    break
        
        except Exception as e:
            print(f"[SERVER ERROR] {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Generate session receipt
            if transcript:
                transcript_hash = transcript.compute_transcript_hash()
                first_seq, last_seq = transcript.get_sequence_range()
                
                # Sign transcript hash
                signature = sign_data(transcript_hash.encode(), self.server_key)
                
                receipt = SessionReceipt(
                    peer="server",
                    first_seq=first_seq,
                    last_seq=last_seq,
                    transcript_sha256=transcript_hash,
                    sig=b64encode_str(signature)
                )
                
                # Save receipt
                receipt_path = f"transcripts/server_receipt_{authenticated_user}_{now_ms()}.json"
                with open(receipt_path, 'w') as f:
                    json.dump(receipt.dict(), f, indent=2)
                
                print(f"\n[SERVER] Session receipt saved to: {receipt_path}")
                transcript.close()
            
            conn.close()
            print(f"[SERVER] Connection closed for {authenticated_user or 'unknown'}")
    
    def start(self):
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        print("[SERVER] Waiting for connections...\n")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            server_socket.close()
            self.db.close()


if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
