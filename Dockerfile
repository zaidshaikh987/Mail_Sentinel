# One image: the React dashboard, the Spring Boot API, and the Python engine.
#
# The engine is installed by scripts/setup.sh — the *same* script a developer
# runs locally. That is deliberate. This file used to carry its own sequence of
# pip commands, and the two installation procedures drifted: the image ended up
# with the engine installed in a virtualenv *and* a second copy on PYTHONPATH,
# so which one actually executed depended on the working directory. A model
# trained into one was invisible to the other. One script, one procedure, one
# copy of the code, in both places.
#
# Everything the tool needs at runtime is baked in — the trained model, the IANA
# cipher registry, the rule base and a CA bundle — so the running container
# never reaches for the network. That is what makes `--network none` a
# demonstrable claim rather than a promise.

# ---------- 1. frontend ----------
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- 2. backend ----------
FROM maven:3.9-eclipse-temurin-17 AS backend
WORKDIR /build
# Dependencies first, so a source-only change does not re-resolve the world.
COPY backend/pom.xml ./pom.xml
RUN mvn -B -q dependency:go-offline
COPY backend/src/main ./src/main
COPY --from=frontend /build/dist ./src/main/resources/static
RUN mvn -B -q -Dmaven.test.skip=true package

# ---------- 3. runtime ----------
FROM eclipse-temurin:17-jre-jammy AS runtime

# curl is for the HEALTHCHECK: the temurin base is Ubuntu-minimal and ships
# neither curl nor wget, so a healthcheck assuming one would report the
# container permanently unhealthy while the app was fine.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The engine source and the captures it is verified against. setup.sh installs
# from here in editable mode, so this tree is the one copy that runs.
COPY engine/ /app/engine/
COPY demo-pcaps/ /app/demo-pcaps/
COPY ["demo captures/", "/app/demo captures/"]
COPY scripts/setup.sh /app/scripts/setup.sh

# Drop any model committed to the repo before installing: setup.sh trains one
# against the scikit-learn resolved *here*, and two artifacts built by two
# different versions is exactly the ambiguity this image should not contain.
RUN rm -rf /app/engine/mailsentinel/ml/artifacts

# Install and train the model without running sample analyses or test suites.
# Tests run explicitly in development/CI against isolated databases.
RUN PIP_NO_CACHE_DIR=1 bash /app/scripts/setup.sh --venv /opt/venv --quiet --skip-smoke-test

COPY --from=backend /build/target/*.jar /app/mailsentinel.jar

RUN useradd --system --uid 10001 --create-home sms \
 && mkdir -p /app/data/uploads \
 && chown -R sms:sms /app /opt/venv
USER sms

EXPOSE 8080

# SMS_PYTHON is the only engine setting, and it means the same thing here as it
# does on a laptop: the interpreter the engine was installed into.
ENV SMS_PYTHON=/opt/venv/bin/python \
    SMS_DEMO_DIR=/app/demo-pcaps \
    SMS_UPLOAD_DIR=/app/data/uploads

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD ["sh", "-c", "curl -fsS http://localhost:8080/api/health || exit 1"]

ENTRYPOINT ["java", "-jar", "/app/mailsentinel.jar"]
