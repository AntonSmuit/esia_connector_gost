import json
import os
import pprint

from dotenv import load_dotenv

print("Loading system enviroment variables from .env if it exist...\n")
load_dotenv(verbose=True)

from flask import Flask, request

from esia_connector import client

# for item, value in os.environ.items():
#     print(f"{item}: {value}")

ESIA_SETTINGS = client.init_esia_conn_settings()
pprint.pprint(ESIA_SETTINGS)


assert os.path.exists(ESIA_SETTINGS.get("certificate_file")), "public key not found!"
assert os.path.exists(ESIA_SETTINGS.get("private_key_file")), "private key not found!"
assert os.path.exists(ESIA_SETTINGS.get("token_check_key")), "ESIA public key not found!"

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
