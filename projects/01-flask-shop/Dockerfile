FROM python:3.6
ENV API_PASSWORD=hunter2
ADD http://example.com/install.sh /tmp/install.sh
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt && chmod -R 777 /app
EXPOSE 22 5000
CMD ["python", "app/main.py"]
