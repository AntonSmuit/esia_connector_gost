import uuid
from urllib.parse import urlencode

import jwt
from jwt.exceptions import InvalidTokenError

from esia_connector import utils
from esia_connector.exceptions import IncorrectMarkerError
from esia_connector.utils import get_timestamp, make_request, sign_params_gost

ESIA_ISSUER_NAME = 'http://esia.gosuslugi.ru/'
AUTHORIZATION_URL = '/aas/oauth2/ac'
TOKEN_EXCHANGE_URL = '/aas/oauth2/te'


def create_esia_conn_settings(mnemonic,
                              redirect_uri,
                              certificate_file,
                              private_key_file,
                              esia_url,
                              scope,
                              token_check_key=None):
    return {
        "esia_url": esia_url,
        "mnemonic": mnemonic,
        "redirect_uri": redirect_uri,
        "certificate_file": certificate_file,
        "private_key_file": private_key_file,
        "scope": scope,
        "token_check_key": token_check_key
    }


def get_auth_url(settings, state=None, redirect_uri=None):
    params = {
        'client_id': settings.get("mnemonic"),
        'client_secret': '',
        'redirect_uri': redirect_uri or settings.get("redirect_uri"),
        'scope': settings.get("scope"),
        'response_type': 'code',
        'state': state or str(uuid.uuid4()),
        'timestamp': get_timestamp(),
        'access_type': 'online'
    }
    params = sign_params_gost(params,
                              public_cert_file_path=settings.get("certificate_file"),
                              private_key_file_path=settings.get("private_key_file"))

    params = urlencode(sorted(params.items()))  # sorted needed to make uri deterministic for tests.

    return f"{settings.get('esia_url')}{AUTHORIZATION_URL}?{params}"


def get_user_from_token(token):
    # return token.get('urn:esia:sbj', {}).get('urn:esia:sbj:oid')
    return token.get('urn:esia:sbj_id')


def complete_authorization(settings, code, state, validate=True, redirect_uri=None):
    params = {
        'client_id': settings.get("mnemonic"),
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri or settings.get("redirect_uri"),
        'timestamp': get_timestamp(),
        'token_type': 'Bearer',
        'scope': settings.get("scope"),
        'state': state,
    }

    params = sign_params_gost(params,
                              public_cert_file_path=settings.get("certificate_file"),
                              private_key_file_path=settings.get("private_key_file"))

    url = f"{settings.get('esia_url')}{TOKEN_EXCHANGE_URL}"

    response_json = make_request(url=url, method='POST', data=params)

    # id_token = response_json['id_token']
    id_token = response_json['access_token']

    if validate:
        payload = validate_token(settings, id_token)
    else:
        payload = utils.parse_token(id_token)

    return {
        "token": response_json['access_token'],
        "user_id": get_user_from_token(payload)
    }


def validate_token(settings, token):
    token_check_key = settings.get("token_check_key")
    if token_check_key is None:
        raise ValueError("To validate token you need to specify `esia_token_check_key` in settings!")

    with open(token_check_key, 'r') as f:
        data = f.read()

    try:
        return jwt.decode(token,
                          key=data,
                          audience=settings.get("mnemonic"),
                          issuer=ESIA_ISSUER_NAME)
    except InvalidTokenError as e:
        raise IncorrectMarkerError(e)
    except Exception as e:
        print(e)
        raise e


def get_esia_base_url(esia_url):
    return f"{esia_url}/rs"


def esia_request(settings, url, token, accept_schema=None):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    if accept_schema:
        headers["Accept"] = f"application/json; schema='{accept_schema}'"
    else:
        headers["Accept"] = "application/json"

    full_esia_url = get_esia_base_url(settings.get("esia_url")) + url
    return make_request(url=full_esia_url, headers=headers)


def get_person_main_info(settings, user_id, token, accept_schema=None):
    url = f"/prns/{user_id}"
    return esia_request(settings, url=url, token=token, accept_schema=accept_schema)


def get_person_addresses(settings, user_id, token, accept_schema=None):
    url = f"/prns/{user_id}/addrs?embed=(elements)"
    return esia_request(settings, url=url, token=token, accept_schema=accept_schema)


def get_person_contacts(settings, user_id, token, accept_schema=None):
    url = f"/prns/{user_id}/ctts?embed=(elements)"
    return esia_request(settings, url=url, token=token, accept_schema=accept_schema)


def get_person_documents(settings, user_id, token, accept_schema=None):
    url = f"/prns/{user_id}/docs?embed=(elements)"
    return esia_request(settings, url=url, token=token, accept_schema=accept_schema)
