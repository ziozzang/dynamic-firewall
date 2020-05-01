FROM python:3

COPY ./ /proxy/
WORKDIR /proxy

RUN pip install -r requirements.txt

# Expose Service ports
EXPOSE 53
EXPOSE 80
EXPOSE 443
EXPOSE 5555


ENTRYPOINT ["python"]
CMD ["proxy.py"]
