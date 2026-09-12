# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# A relay holds no database, no user data and no island certificate.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY relay.py .

# Mount your own config at /app/relay.config.json
ENV RELAY_CONFIG=/app/relay.config.json
EXPOSE 8800
RUN useradd --system --no-create-home relay
USER relay

CMD ["uvicorn", "relay:app", "--host", "0.0.0.0", "--port", "8800"]
