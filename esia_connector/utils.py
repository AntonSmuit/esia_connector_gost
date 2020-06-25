import base64
import json
import datetime
import shlex
from subprocess import Popen, PIPE
import pytz
import requests
import jwt


from esia_connector.exceptions import IncorrectJsonError, HttpError


def make_request(url, method='GET', headers=None, data=None):
    try:
        response = requests.request(method, url, headers=headers, data=data)
        response.raise_for_status()
        return json.loads(response.content.decode())
    except requests.HTTPError as e:
        raise HttpError(e)
    except ValueError as e:
        raise IncorrectJsonError(e)


def sign_params_gost(params, public_cert_file_path, private_key_file_path) :

    plaintext = params.get('scope', '') + params.get('timestamp', '') + params.get('client_id', '') + params.get('state', '')
    cmd = f"openssl smime  -sign -engine gost -binary -outform DER -noattr -signer {public_cert_file_path} -inkey {private_key_file_path}"  #-nodetach

    p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE)

    raw_client_secret = p.communicate(plaintext.encode())[0]

    params.update(
        client_secret=base64.urlsafe_b64encode(raw_client_secret).decode('utf-8'),
    )
    return params

def get_timestamp():
    return datetime.datetime.now(pytz.utc).strftime('%Y.%m.%d %H:%M:%S %z').strip()


def parse_token(token):
    return jwt.decode(token, verify=False)
