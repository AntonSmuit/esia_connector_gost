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


# def sign_params(params, certificate_file, private_key_file):
#     """
#     Signs params adding client_secret key, containing signature based on `scope`, `timestamp`, `client_id` and `state`
#     keys values.
#     :param dict params: requests parameters
#     :param str certificate_file: path to certificate file
#     :param str private_key_file: path to private key file
#     :return:signed request parameters
#     :rtype: dict
#     """
#     plaintext = params.get('scope', '') + params.get('timestamp', '') + params.get('client_id', '') + params.get('state', '')
#     cmd = 'openssl smime  -sign -md md_gost12_256 -signer {cert} -inkey {key} -outform DER'.format(
#         cert=certificate_file,
#         key=private_key_file
#     )
#     p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE)
#     raw_client_secret = p.communicate(plaintext.encode())[0]
#
#     params.update(
#         client_secret=base64.urlsafe_b64encode(raw_client_secret).decode('utf-8'),
#     )
#     return params

def sign_params_gost(params, public_cert_file_path, private_key_file_path) :
    # public_cert_file_path = os.path.join(os.getcwd(), "last", "mdapp_public.cer")
    # public_cert_file_path = os.path.join(os.getcwd(), "last", "mdapp3.pem")
    # print(public_cert_file_path)
    # private_key_file_path = os.path.join(os.getcwd(), "last", "mdapp3.pem")
    # print(private_key_file_path)

    plaintext = params.get('scope', '') + params.get('timestamp', '') + params.get('client_id', '') + params.get('state', '')
    # cmd = f"openssl smime  -sign -md md_gost12_256 -signer {public_cert_file_path} -inkey {private_key_file_path} -outform DER"  #-noattr -binary -nodetach
    cmd = f"openssl smime  -sign -engine gost -binary -outform DER -noattr -signer {public_cert_file_path} -inkey {private_key_file_path}"  #-nodetach
    #For Esia
    # /usr/local/gost/bin/openssl smime -sign  -engine gost -binary -outform DER -noattr -signer ./server.crt -inkey ./server.key -in ./message.txt -out ./sign.out    p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE)
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
