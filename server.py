import json
import os

from flask import Flask, request

from esia_connector import client


def get_res_file(name):
    return os.path.join(os.path.dirname(__file__), 'cert', name)


ESIA_SETTINGS = client.create_esia_conn_settings(
    mnemonic='SGMU006301',
    redirect_uri='http://localhost:5000/info',
    certificate_file=get_res_file('mdapp3.pem'),
    private_key_file=get_res_file('mdapp3.pem'),
    token_check_key=get_res_file('RSA_TESIA.cer'),
    esia_url='https://esia-portal1.test.gosuslugi.ru',
    scope='fullname birthdate snils gender')

assert os.path.exists(ESIA_SETTINGS.get("certificate_file")), "Please place your certificate in res/test.crt !"
assert os.path.exists(ESIA_SETTINGS.get("private_key_file")), "Please place your private key in res/test.key!"
assert os.path.exists(ESIA_SETTINGS.get("token_check_key")), "Please place ESIA public key in res/esia_pub.key !"

app = Flask(__name__)


@app.route("/")
def index():
    url = generate_url()
    return "Start here: <a href='"+ url + "'>" + url + "</a>"

@app.route("/generate_url")
def generate_url():
    url = client.get_auth_url(ESIA_SETTINGS)
    print("url: " + url + "\n")
    return url


@app.route("/info")
def process():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error_description')
    print(error)
    esia_response_data = client.complete_authorization(ESIA_SETTINGS, code, state, validate=False)
    token = esia_response_data.get("token")
    user_id = esia_response_data.get("user_id")
    print("userId: " + user_id)
    inf = client.get_person_main_info(ESIA_SETTINGS, user_id, token)
    # print("info: " + str(inf))
    return json.dumps(inf, ensure_ascii=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
