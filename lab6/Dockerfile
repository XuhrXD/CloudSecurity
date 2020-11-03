FROM python
RUN mkdir /app
COPY . /app/
WORKDIR /app
RUN pip install Flask \
  python-dotenv \
  psycopg2
EXPOSE 8080
CMD ["python", "main.py"]