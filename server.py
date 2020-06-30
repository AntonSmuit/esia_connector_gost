import json
import os
import logging

from dotenv import load_dotenv

print("Loading system enviroment variables from .env if it exist...\n")
load_dotenv(verbose=True)

from flask import Flask, request

from esia_connector import client

app = Flask(__name__)

logger = logging.getLogger(__name__)
# for item, value in os.environ.items():
#     print(f"{item}: {value}")

# logger = logging.getLogger('werkzeug')
# access_handler = logging.FileHandler(os.path.join("logs", "access.log"))
# logger.addHandler(access_handler)
# app.logger.addHandler(handler)
os.makedirs('logs', exist_ok=True)

fileHandler = logging.FileHandler(os.path.join("logs", "app.log"))
fileHandler.setLevel(logging.DEBUG)
# fileHandler.setFormatter(utils.LOGGING_FORMATTER)
streamHandler = logging.StreamHandler()
streamHandler.setLevel(logging.DEBUG)
# streamHandler.setFormatter(utils.LOGGING_FORMATTER)
app.logger.addHandler(fileHandler)
app.logger.addHandler(streamHandler)
app.logger.info("Logging is set up.")

ESIA_SETTINGS = client.init_esia_conn_settings()
logger.info(str(ESIA_SETTINGS))

assert os.path.exists(ESIA_SETTINGS.get("certificate_file")), "public key not found!"
assert os.path.exists(ESIA_SETTINGS.get("private_key_file")), "private key not found!"
assert os.path.exists(ESIA_SETTINGS.get("token_check_key")), "ESIA public key not found!"


def generate_esia_login_url():
    url = client.get_auth_url(ESIA_SETTINGS)
    logger.info("url: " + url + "\n")
    return url


@app.route("/")
def index():
    url = generate_esia_login_url()
    return "Start here: <a href='" + url + "'>" + url + "</a>"


@app.route("/generate_url")
def get_esia_login_url():
    url = generate_esia_login_url()
    return json.dumps({"url": url}, ensure_ascii=False)


@app.route("/esia_response")
def process():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error_description')
    logger.info("esia code : " + str(code or ''))
    logger.info("esia state : " + str(state or ''))
    logger.error("esia error : " + str(error or ''))
    esia_response_data = client.complete_authorization(ESIA_SETTINGS, code, state, validate=False)
    token = esia_response_data.get("token")
    user_id = esia_response_data.get("user_id")
    logger.info("userId: " + str(user_id or ''))
    inf = client.get_person_main_info(ESIA_SETTINGS, user_id, token)
    inf["esia_user_id"] = user_id
    # print("info: " + str(inf))
    return json.dumps(inf, ensure_ascii=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
