import os

import dotenv
import requests
import supabase

dotenv.load_dotenv()


def test_jwt():
    myemail = os.getenv("KESTREL_USER")
    mypass = os.getenv("KESTREL_PASSWORD")
    client = supabase.create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    signedin = client.auth.sign_in(email=myemail, password=mypass)
    try:
        print(signedin.access_token)
        response = requests.post(
            # 'https://kestrel.substructure.workers.dev',
            'http://localhost:8787',
            json={
                'jwt': signedin.access_token,
            }
        )
        print(response.text)
        assert response.status_code == 200
    finally:
        client.auth.sign_out()
