FROM python:3.9

RUN pip install Flask>=2.0.3 
RUN pip install gunicorn
RUN pip install requests>=2.27.1
RUN pip install Jinja2>=3.0.3

COPY src/ /app
WORKDIR /app

ENV PORT 8080

CMD exec gunicorn --bind :$PORT --workers 2 --threads 8 app:app