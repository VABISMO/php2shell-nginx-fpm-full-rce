.PHONY: help test lint validate ci build-nginx build-8.4.26 build-8.4.27 labs-up labs-down labs-status labs-smoke labs-test

help:                          ## Show this help
	@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

test:                          ## Run the unit test suite
	python3 -m unittest discover -s tests -v

lint:                          ## Run ruff
	ruff check tools tests

validate:                      ## Validate the FPM profile against its schema
	python3 -c "import json, jsonschema; jsonschema.validate( 	  json.load(open('profiles/8.4.26-fpm.json')), 	  json.load(open('profiles/schema.json'))); print('profile valid')"

ci: lint test validate         ## Run the fast CI checks locally

build-nginx:                   ## Build nginx into lab/fpm/runtime
	lab/fpm/build_nginx.sh

build-8.4.26:                  ## Build vulnerable PHP 8.4.26
	lab/fpm/build_php.sh 8.4.26

build-8.4.27:                  ## Build fixed PHP 8.4.27 (patchcheck)
	lab/fpm/build_php.sh 8.4.27

labs-up:                       ## Start the local nginx+FPM labs
	python3 tools/php2shell_fpm_labs.py up

labs-down:                     ## Stop the local nginx+FPM labs
	python3 tools/php2shell_fpm_labs.py down

labs-status:                   ## Show lab status
	python3 tools/php2shell_fpm_labs.py status

labs-smoke:                    ## Check both lab endpoints
	python3 tools/php2shell_fpm_labs.py smoke

labs-test:                     ## Run primitive + endgame against the lab
	python3 tools/php2shell_fpm_labs.py test
