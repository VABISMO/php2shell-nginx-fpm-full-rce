.PHONY: help test lint validate ci build-nginx build-8.4.25 build-8.4.26 build-8.4.27 profile-draft labs-up labs-down labs-status labs-smoke labs-test

help:                          ## Show this help
	@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

test:                          ## Run the unit test suite
	python3 -m unittest discover -s tests -v

lint:                          ## Run ruff
	ruff check tools tests

validate:                      ## Validate all FPM profiles against the schema
	python3 -c "import glob, json, jsonschema; s = json.load(open('profiles/schema.json')); [jsonschema.validate(json.load(open(p)), s) for p in glob.glob('profiles/*-fpm.json')]; print('profiles valid')"

ci: lint test validate         ## Run the fast CI checks locally

build-nginx:                   ## Build nginx into lab/fpm/runtime
	lab/fpm/build_nginx.sh

build-8.4.25:                  ## Build vulnerable PHP 8.4.25
	lab/fpm/build_php.sh 8.4.25

build-8.4.26:                  ## Build vulnerable PHP 8.4.26
	lab/fpm/build_php.sh 8.4.26

build-8.4.27:                  ## Build fixed PHP 8.4.27 (patchcheck)
	lab/fpm/build_php.sh 8.4.27

profile-draft:                 ## Generate a draft profile (PHP_FPM=... VERSION=...)
	@test -n "$(PHP_FPM)" -a -n "$(VERSION)" || \
	  (echo "usage: make profile-draft PHP_FPM=/path/to/php-fpm VERSION=8.4.25"; exit 2)
	python3 tools/php2shell_fpm_profile.py --php-fpm "$(PHP_FPM)" --version "$(VERSION)"

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
