FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY server ./server
# The companion skill is served over the MCP resources API.
COPY skills ./skills
COPY app.py ./

# The container has its own network namespace; published ports are the boundary.
ENV MCP_HOST=0.0.0.0

# Nothing here writes to disk, so the network-facing process does not need to be root.
RUN useradd --system --create-home --uid 10001 app
USER app

EXPOSE 8787

CMD ["python", "app.py"]
