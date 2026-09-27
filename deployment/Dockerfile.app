FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/* \
    && npm install -g bun
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
RUN jac install
EXPOSE 8080
# In-process guard is used only if GUARD_URL is empty; production sets GUARD_URL.
CMD ["sh", "-c", "jac start main.jac --port ${PORT:-8080}"]
