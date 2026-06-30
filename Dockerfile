FROM python:3.12-slim
WORKDIR /app
COPY main.py .
# No EXPOSE: the app binds the platform-injected $PORT. Under host networking
# EXPOSE is a no-op anyway, and there is no fixed port to advertise.

# Declare the configure-then-freeze entry point. The Privasys deploy
# pipeline reads this label to populate the per-app `config_api`
# field, so that the runtime keeps every other path 503 until the
# deployer hits POST /configure.
LABEL org.privasys.config_api="POST /configure"

CMD ["python", "main.py"]
