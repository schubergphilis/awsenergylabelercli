FROM python:3.9-slim

RUN pip install awsenergylabelercli/

CMD aws-energy-labeler