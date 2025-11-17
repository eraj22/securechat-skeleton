"""
Secure Chat Client
Connects to server, performs authentication, and exchanges encrypted messages
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
from app.storage.transcript import Transcript

load_dotenv()


class SecureChatClient:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        
        # Load client certificate and key
        self.client_cert = load_certificate_from_file(os.getenv('CLIENT_CERT_PATH'))
        self.client_key = load_private_key_from_file(os.getenv('CLIENT_KEY_PATH'))
        self.ca_cert = load_certificate_from_file(os.getenv('CA_CERT_PATH'))
        
        self.socket = None
        self.server_cert = None
        self.session_key = None
        self.transcript = None
        self.username = None
        
        print(f"[CLIENT] Initialized")
        print(f"[CLIENT] Client CN: {get_common_name(self.client_cert)}")
    
    def connect(self):
        """Connect to server and perform initial handshake"""
        try:
            print(f"[CLIENT] Connecting to {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print("[CLIENT] Connected to server")
            
            # Phase 1: Send Hello with certificate
            print("\n[CLIENT] Phase 1: Certificate Exchange")
            hello_msg = HelloMessage(
                client_cert=export_certificate_pem(self.client_cert),
                nonce=b64encode_str(os.urandom(32))
            )
            self.socket.sendall(json.dumps(hello_msg.dict()).encode())
            
            # Receive Server Hello
            data = self.socket.recv(8192).decode()
            server_hello = json.loads(data)
            
            if server_hello['type'] == 'response' and server_hello['status'] == 'error':
                print(f"[CLIENT ERROR] {server_hello['message']}")
                return False
            
            # Validate server certificate
            self.server_cert = load_certificate(server_hello['server_cert'])
            is_valid, error_msg = validate_certificate(self.server_cert, self.ca_cert)
            
            if not is_valid:
                print(f"[CLIENT] {error_msg}")
                return False
            
            print(f"[CLIENT] Server certificate validated: {get_common_name(self.server_cert)}")
            return True
        
        except Exception as e:
            print(f"[CLIENT ERROR] Connection failed: {e}")
            return False
    
    def authenticate(self):
        """Perform registration or login"""
        try:
            # Phase 2: Temporary DH for authentication
            print("\n[CLIENT] Phase 2: Temporary DH for Authentication")
            dh, public_A = perform_dh_exchange_client()
            
            dh_client_msg = DHClientMessage(
                g=dh.g,
                p=dh.p,
                A=public_A
            )
            self.socket.sendall(json.dumps(dh_client_msg.dict()).encode())
            
            # Receive server DH response
            data = self.socket.recv(8192).decode()
            dh_server_msg = json.loads(data)
            
            temp_key = finalize_dh_exchange_client(dh, dh_server_msg['B'])
            print("[CLIENT] Temporary session key established")
            
            # Phase 3: Registration or Login
            print("\n[CLIENT] Phase 3: Authentication")
            choice = input("Do you want to (r)egister or (l)ogin? ").lower()
            
            if choice == 'r':
                email = input("Enter email: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                
                # Generate salt and hash password
                salt = os.urandom(16)
                pwd_hash = sha256_hex(salt + password.encode())
                
                register_msg = RegisterMessage(
                    email=email,
                    username=username,
                    pwd=pwd_hash,
                    salt=b64encode_str(salt)
                )
                
                # Encrypt and send
                auth_json = json.dumps(register_msg.dict())
                ciphertext = aes_encrypt(auth_json.encode(), temp_key)
                encrypted_payload = {
                    "type": "encrypted_auth",
                    "payload": b64encode_str(ciphertext)
                }
                self.socket.sendall(json.dumps(encrypted_payload).encode())
                
                # Receive response
                data = self.socket.recv(8192).decode()
                response = json.loads(data)
                
                if response['status'] == 'error':
                    print(f"[CLIENT] Registration failed: {response['message']}")
                    return False
                
                print(f"[CLIENT] Registration successful!")
                self.username = username
            
            elif choice == 'l':
                email = input("Enter email: ")
                password = input("Enter password: ")
                
                login_msg = LoginMessage(
                    email=email,
                    pwd="",  # Will send after receiving salt
                    nonce=b64encode_str(os.urandom(16))
                )
                
                # Encrypt and send
                auth_json = json.dumps(login_msg.dict())
                ciphertext = aes_encrypt(auth_json.encode(), temp_key)
                encrypted_payload = {
                    "type": "encrypted_auth",
                    "payload": b64encode_str(ciphertext)
                }
                self.socket.sendall(json.dumps(encrypted_payload).encode())
                
                # Receive salt
                data = self.socket.recv(8192).decode()
                response = json.loads(data)
                
                if response['status'] == 'error':
                    print(f"[CLIENT] Login failed: {response['message']}")
                    return False
                
                # Compute password hash with received salt
                salt = b64decode_str(response['salt'])
                pwd_hash = sha256_hex(salt + password.encode())
                
                # Send password hash
                pwd_msg = {"pwd_hash": pwd_hash}
                self.socket.sendall(json.dumps(pwd_msg).encode())
                
                # Receive final response
                data = self.socket.recv(8192).decode()
                response = json.loads(data)
                
                if response['status'] == 'error':
                    print(f"[CLIENT] Login failed: {response['message']}")
                    return False
                
                print(f"[CLIENT] {response['message']}")
                self.username = email.split('@')[0]  # Extract username from email
            
            else:
                print("[CLIENT] Invalid choice")
                return False
            
            return True
        
        except Exception as e:
            print(f"[CLIENT ERROR] Authentication failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def establish_session_key(self):
        """Establish session key for chat"""
        try:
            # Phase 4: Session DH
            print("\n[CLIENT] Phase 4: Session Key Establishment")
            dh, public_A = perform_dh_exchange_client()
            
            dh_client_msg = DHClientMessage(
                g=dh.g,
                p=dh.p,
                A=public_A
            )
            self.socket.sendall(json.dumps(dh_client_msg.dict()).encode())
            
            # Receive server DH response
            data = self.socket.recv(8192).decode()
            dh_server_msg = json.loads(data)
            
            self.session_key = finalize_dh_exchange_client(dh, dh_server_msg['B'])
            print("[CLIENT] Chat session key established")
            
            # Initialize transcript
            self.transcript = Transcript(f"transcripts/client_{self.username}_{now_ms()}.txt")
            
            return True
        
        except Exception as e:
            print(f"[CLIENT ERROR] Session key establishment failed: {e}")
            return False
    
    def chat(self):
        """Start encrypted chat session"""
        print("\n[CLIENT] Phase 5: Encrypted Messaging Started")
        print("[CLIENT] Type messages to send (or 'quit' to exit):\n")
        
        seqno = 0
        last_server_seqno = 0
        server_fingerprint = get_certificate_fingerprint(self.server_cert)
        client_fingerprint = get_certificate_fingerprint(self.client_cert)
        
        # Thread for receiving messages
        def receive_messages():
            nonlocal last_server_seqno
            while True:
                try:
                    data = self.socket.recv(8192).decode()
                    if not data:
                        break
                    
                    msg = json.loads(data)
                    
                    if msg['type'] == 'msg':
                        # Verify sequence number
                        if msg['seqno'] <= last_server_seqno:
                            print(f"\n[CLIENT] REPLAY detected! Rejecting message.")
                            continue
                        
                        last_server_seqno = msg['seqno']
                        
                        # Verify signature
                        digest_input = f"{msg['seqno']}{msg['ts']}{msg['ct']}".encode()
                        digest = sha256_digest(digest_input)
                        signature = b64decode_str(msg['sig'])
                        
                        if not verify_signature_with_cert(digest, signature, self.server_cert):
                            print(f"\n[CLIENT] SIG_FAIL! Message rejected.")
                            continue
                        
                        # Decrypt message
                        ciphertext = b64decode_str(msg['ct'])
                        plaintext = aes_decrypt(ciphertext, self.session_key).decode()
                        
                        print(f"\n[RECEIVED] {plaintext}")
                        print("> ", end="", flush=True)
                        
                        # Add to transcript
                        self.transcript.add_entry(
                            msg['seqno'],
                            msg['ts'],
                            msg['ct'],
                            msg['sig'],
                            server_fingerprint
                        )
                
                except Exception as e:
                    print(f"\n[CLIENT] Receive error: {e}")
                    break
        
        receive_thread = threading.Thread(target=receive_messages, daemon=True)
        receive_thread.start()
        
        # Send messages
        try:
            while True:
                print("> ", end="", flush=True)
                msg = input()
                
                if msg.lower() == 'quit':
                    break
                
                seqno += 1
                timestamp = now_ms()
                
                # Encrypt message
                ciphertext = aes_encrypt(msg.encode(), self.session_key)
                ct_b64 = b64encode_str(ciphertext)
                
                # Sign message
                digest_input = f"{seqno}{timestamp}{ct_b64}".encode()
                digest = sha256_digest(digest_input)
                signature = sign_data(digest, self.client_key)
                sig_b64 = b64encode_str(signature)
                
                # Create message
                chat_msg = ChatMessage(
                    seqno=seqno,
                    ts=timestamp,
                    ct=ct_b64,
                    sig=sig_b64
                )
                
                self.socket.sendall(json.dumps(chat_msg.dict()).encode())
                
                # Add to transcript
                self.transcript.add_entry(seqno, timestamp, ct_b64, sig_b64, client_fingerprint)
        
        except KeyboardInterrupt:
            print("\n[CLIENT] Exiting...")
        
        finally:
            self.close()
    
    def close(self):
        """Close connection and generate session receipt"""
        if self.transcript:
            transcript_hash = self.transcript.compute_transcript_hash()
            first_seq, last_seq = self.transcript.get_sequence_range()
            
            # Sign transcript hash
            signature = sign_data(transcript_hash.encode(), self.client_key)
            
            receipt = SessionReceipt(
                peer="client",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=transcript_hash,
                sig=b64encode_str(signature)
            )
            
            # Send receipt to server
            try:
                self.socket.sendall(json.dumps(receipt.dict()).encode())
            except:
                pass
            
            # Save receipt
            receipt_path = f"transcripts/client_receipt_{self.username}_{now_ms()}.json"
            with open(receipt_path, 'w') as f:
                json.dump(receipt.dict(), f, indent=2)
            
            print(f"\n[CLIENT] Session receipt saved to: {receipt_path}")
            self.transcript.close()
        
        if self.socket:
            self.socket.close()
            print("[CLIENT] Disconnected from server")


def main():
    client = SecureChatClient()
    
    if not client.connect():
        return
    
    if not client.authenticate():
        return
    
    if not client.establish_session_key():
        return
    
    client.chat()


if __name__ == "__main__":
    main()
