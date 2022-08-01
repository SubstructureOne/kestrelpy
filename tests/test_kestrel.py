import base64
import os

import dotenv
import ed25519
import jwt
import pytest
import requests
import supabase

from kestrelpy.kestrel import KestrelClient, LOCAL_KESTREL_URL, KestrelApiError

dotenv.load_dotenv()


def test_jwt():
    secret = os.getenv("SUPABASE_JWT_SECRET")
    myemail = os.getenv("KESTREL_USER")
    mypass = os.getenv("KESTREL_PASSWORD")
    client = supabase.create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_ANON_KEY"))
    try:
        signedin = client.auth.sign_in(email=myemail, password=mypass)
        # import ipdb; ipdb.set_trace()
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
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_anon_key = os.getenv("SUPABASE_ANON_KEY")
    signing_key, verifying_key = ed25519.create_keypair()
    message = "this is a test message".encode('utf-8')
    signature = signing_key.sign(message)
    publickey = verifying_key.to_bytes()
    client = KestrelClient(supabase_url, supabase_anon_key, LOCAL_KESTREL_URL)
    client.signin(myemail, mypass)
    try:
        # expected to fail because we haven't saved this key
        with pytest.raises(KestrelApiError):
            client.verifysignature(message, signature, publickey)
        client.addkey(publickey, "custom")
        client.verifysignature(message, signature, publickey)
        client.deletekey(publickey)
    finally:
        client.signout()


def test_listkeys():
    myemail = os.getenv("KESTREL_USER")
    mypass = os.getenv("KESTREL_PASSWORD")
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_anon_key = os.getenv("SUPABASE_ANON_KEY")
    client = KestrelClient(supabase_url, supabase_anon_key, LOCAL_KESTREL_URL)
    client.signin(myemail, mypass)
    try:
        keys = client.listkeys()
        print(keys)
    finally:
        client.signout()


def test_externaldeposit():
    myemail = os.getenv("KESTREL_USER")
    mypass = os.getenv("KESTREL_PASSWORD")
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_anon_key = os.getenv("SUPABASE_ANON_KEY")
    client = KestrelClient(supabase_url, supabase_anon_key, LOCAL_KESTREL_URL)
    client.signin(myemail, mypass)
    try:
        client.externaldeposit(100.)
    finally:
        client.signout()
