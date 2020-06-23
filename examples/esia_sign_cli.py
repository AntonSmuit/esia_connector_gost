import base64
from subprocess import Popen, PIPE
import shlex
import datetime
import pytz
import uuid
import os


def get_timestamp():
    return datetime.datetime.now(pytz.utc).strftime('%Y.%m.%d %H:%M:%S %z').strip()


if __name__ == '__main__':
    # public_cert_file_path = os.path.join(os.getcwd(), "last", "mdapp_public.cer")
    public_cert_file_path = os.path.join(os.getcwd(), "last", "mdapp3.pem")
    print(public_cert_file_path)
    private_key_file_path = os.path.join(os.getcwd(), "last", "mdapp3.pem")
    print(private_key_file_path)

    plaintext = 'fullname birthdate snils gender' + get_timestamp() + 'SGMU006301' + str(uuid.uuid4())
    # cmd = f"openssl smime  -sign -md md_gost12_256 -signer {public_cert_file_path} -inkey {private_key_file_path} -outform DER"  #-noattr -binary -nodetach
    cmd = f"openssl smime  -sign -engine gost -binary -outform DER -noattr -signer {public_cert_file_path} -inkey {private_key_file_path}"  #-nodetach
#For Esia
# /usr/local/gost/bin/openssl smime -sign  -engine gost -binary -outform DER -noattr -signer ./server.crt -inkey ./server.key -in ./message.txt -out ./sign.out    p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE)
    p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE)

    raw_client_secret = p.communicate(plaintext.encode())[0]

    client_secret = base64.urlsafe_b64encode(raw_client_secret).decode('utf-8'),

    print(client_secret)
