import base64
import os

import dotenv
import ed25519
import jwt
import requests
import supabase

dotenv.load_dotenv()


def test_jwt():
    secret = os.getenv("SUPABASE_JWT_SECRET")
    myemail = os.getenv("KESTREL_USER")
    mypass = os.getenv("KESTREL_PASSWORD")
    client = supabase.create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    try:
        signedin = client.auth.sign_in(email=myemail, password=mypass)
        import ipdb; ipdb.set_trace()
        result = jwt.decode(signedin.access_token, secret, ['HS256'], audience='authenticated')
        print(signedin.access_token)
        response = requests.post(
            # 'https://kestrel.substructure.workers.dev',
            'http://localhost:8787/jwt',
            json={
                'jwt': signedin.access_token,
            }
        )
        print(response.text)
        assert response.status_code == 200
    finally:
        client.auth.sign_out()

def test_signedmessage():
    myemail = os.getenv("KESTREL_USER")
    mypass = os.getenv("KESTREL_PASSWORD")
    client = supabase.create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    signing_key, verifying_key = ed25519.create_keypair()
    message = "this is a test message".encode('utf-8')
    signature = signing_key.sign(message)
    publickey = verifying_key.to_bytes()
    import ipdb; ipdb.set_trace()
    try:
        signedin = client.auth.sign_in(email=myemail, password=mypass)
        response = requests.post(
            'http://localhost:8787/signature',
            json={
                'jwt': signedin.access_token,
                'message_b64': base64.b64encode(message).decode(),
                'signature_b64': base64.b64encode(signature).decode(),
                'key_b64': base64.b64encode(publickey).decode(),
            }
        )
    finally:
        client.auth.sign_out()
