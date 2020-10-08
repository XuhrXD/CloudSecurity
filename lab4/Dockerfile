FROM python
RUN mkdir /app
COPY server.py /app/
WORKDIR /app
RUN pip install flask
EXPOSE 8080
ENV FLASK_APP=server.py
CMD ["python", "server.py"]

