import base64
from contextlib import contextmanager
from typing import Optional, TypedDict

import requests
import supabase
from gotrue.types import Session

DEFAULT_KESTREL_URL = 'https://kestrel.substructure.workers.dev'
LOCAL_KESTREL_URL = 'http://localhost:8787'


class KestrelErrorJson(TypedDict):
    error: str


class KestrelApiError(Exception):
    def __init__(self, errorjson: KestrelErrorJson):
        error = errorjson['error']
        super(KestrelApiError, self).__init__(f"Kestrel request failed: {error}")


class KestrelClient:
    def __init__(
            self,
            supabase_url: str,
            supabase_anon_key: str,
            kestrel_url: str = DEFAULT_KESTREL_URL
    ):
        self._client = supabase.create_client(supabase_url, supabase_anon_key)
        self._session: Optional[Session] = None
        self._kestrel_url = kestrel_url

    def signin(self, email: str, password: str):
        self._session = self._client.auth.sign_in(email=email, password=password)

    def signout(self):
        self._client.auth.sign_out()

    def setauth(self, jwt):
        self._session = self._client.auth.set_auth(jwt)

    def jwt(self) -> str:
        if self._session is None:
            raise ValueError("Not signed in")
        return self._session.access_token

    def userid(self) -> str:
        if self._session is None:
            raise ValueError("Not signed in")
        return str(self._session.user.id)

    def addkey(self, newkey: bytes, keytype: str):
        response = requests.post(
            self._createurl('addkey'),
            json={
                'jwt': self.jwt(),
                'key_b64': base64.b64encode(newkey).decode('utf-8'),
                'keytype': keytype,
            }
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())

    def listkeys(self):
        response = requests.post(
            self._createurl('listkeys'),
            json={'jwt': self.jwt()},
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())
        return response.json()['keys']

    def deletekey(self, key: bytes):
        response = requests.post(
            self._createurl('deletekey'),
            json={
                'jwt': self.jwt(),
                'key_b64': base64.b64encode(key).decode('utf-8')
            }
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())
        return response.json()

    def verifysignature(self, message: bytes, signature: bytes, key: bytes):
        response = requests.post(
            self._createurl('signature'),
            json={
                'jwt': self.jwt(),
                'message_b64': base64.b64encode(message).decode('utf-8'),
                'signature_b64': base64.b64encode(signature).decode('utf-8'),
                'key_b64': base64.b64encode(key).decode('utf-8')
            }
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())

    def externaldeposit(self, amount: float):
        response = requests.post(
            self._createurl('deposit'),
            json={
                'jwt': self.jwt(),
                'userid': self.userid(),
                'amount': amount
            }
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())

    def queryuserdata(self, userid: str, appid: str, column: str, operator: str, value: str):
        response = requests.post(
            self._createurl('queryuserdata'),
            json={
                'jwt': self.jwt(),
                'userid': userid,
                'appid': appid,
                'column': column,
                'operator': operator,
                'value': value,
            }
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())
        return response.json()

    def uploadfile(self, userid: str, appid: str, filepath: str):
        with open(filepath, 'rb') as fp:
            filedata = fp.read()
        filedata_b64 = base64.b64encode(filedata).decode('utf-8')
        response = requests.post(
            self._createurl('uploadfile'),
            json={
                'jwt': self.jwt(),
                'userid': userid,
                'appid': appid,
                'path': 'testpath',
                'filedata_b64': filedata_b64,
            }
        )
        if response.status_code != 200:
            raise KestrelApiError(response.json())
        return response.json()

    def _createurl(self, service: str):
        return f'{self._kestrel_url}/{service}'
