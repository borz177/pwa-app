FROM python:3.10

WORKDIR /app
COPY . .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

ENV PORT 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
