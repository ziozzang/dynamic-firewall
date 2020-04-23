FROM python:3

COPY ./ /proxy/
WORKDIR /proxy

RUN pip install -r requirements.txt

# Expose Service ports
EXPOSE 53,80,443,5000

ENTRYPOINT ["python"]
CMD ["proxy.py"]
