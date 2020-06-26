FROM rnix/openssl-gost:latest

EXPOSE 5000

RUN apt-get update && apt-get install python3 python3-pip -y

COPY . /app

WORKDIR /app

RUN pip3 install -r requirements.txt

#ENTRYPOINT ["python"]

#CMD ["flask_app.py"]

#CMD ["python3", "--version"]

CMD python3 server.py