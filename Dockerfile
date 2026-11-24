FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r sbomsentry && useradd -r -g sbomsentry -d /home/sbomsentry -m sbomsentry
WORKDIR /app

COPY --from=builder /root/.local /home/sbomsentry/.local
COPY --chown=sbomsentry:sbomsentry . /app

ENV PATH=/home/sbomsentry/.local/bin:$PATH
ENV PYTHONPATH=/app

USER sbomsentry

ENTRYPOINT ["python3", "-m", "sbomsentry.cli"]
CMD ["--help"]
