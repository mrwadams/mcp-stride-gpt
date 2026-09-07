FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY server ./server
# The companion skill is served over the MCP resources API.
COPY skills ./skills
COPY app.py ./

EXPOSE 8787

CMD ["python", "app.py"]
