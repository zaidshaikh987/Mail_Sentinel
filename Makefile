# MailSentinel - common tasks.
#
#   make setup     install the engine and the dashboard's dependencies
#   make run       build everything and start the application on :8080
#   make test      run the engine test suite
#   make verify    end-to-end check: real API + real engine + real captures
#   make train     retrain the posture model
#   make docker    build and start the whole stack in containers
#   make clean     remove build output
#
# SMS_PYTHON must point at the interpreter the engine is installed into.
# `make setup` creates it at .venv and prints the export line.

SMS_PYTHON ?= $(CURDIR)/.venv/bin/python
FRONT       = frontend
BACK        = backend

.PHONY: help setup run test verify train docker clean

help:
	@grep -E '^#   ' Makefile | sed 's/^#   //'

setup:
	./scripts/setup.sh
	cd $(FRONT) && npm install

# The dashboard is built first so Maven's bundled-ui profile picks it up and
# the jar serves the API and the UI on one port.
run:
	cd $(FRONT) && npm run build
	mvn -f $(BACK)/pom.xml -DskipTests package
	SMS_PYTHON="$(SMS_PYTHON)" java -jar $(BACK)/target/securemailscope-1.0.0.jar

test:
	"$(SMS_PYTHON)" -m pytest engine/tests -q

verify:
	mvn -f $(BACK)/pom.xml -DskipTests package
	SMS_PYTHON="$(SMS_PYTHON)" ./scripts/verify-e2e.sh

train:
	"$(SMS_PYTHON)" -m securemailscope.ml.train

docker:
	docker compose up --build

clean:
	rm -rf out $(FRONT)/dist $(BACK)/target
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name .pytest_cache -type d -prune -exec rm -rf {} +
	find . -name '*.egg-info' -type d -prune -exec rm -rf {} +
	rm -rf engine/build
