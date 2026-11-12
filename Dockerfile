# pruefstand im Container (ohne PDF – dafür Chromium nötig, siehe README)
#   docker build -t pruefstand .
#   docker run --rm pruefstand beispiel.ch
#   docker run --rm -v "$PWD:/daten" pruefstand beispiel.ch --html /daten/bericht.html
FROM python:3.12-slim
RUN useradd --create-home pruefer
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache
USER pruefer
ENTRYPOINT ["pruefstand", "--ohne-verlauf"]
