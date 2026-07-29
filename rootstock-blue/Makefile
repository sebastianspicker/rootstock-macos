.PHONY: bootstrap test content-validate cli xcode help check-non-goals sample-case

help:
	@echo "rootstock-blue targets:"
	@echo "  make bootstrap         - resolve SPM"
	@echo "  make test              - swift test"
	@echo "  make content-validate  - rules must have fixtures"
	@echo "  make cli               - build rootstock-blue CLI"
	@echo "  make sample-case       - create Fixtures/cases/sample.rsbcase"
	@echo "  make xcode             - generate Xcode project (requires xcodegen)"
	@echo "  make check-non-goals   - scan product docs for forbidden claims"

bootstrap:
	@bash Tools/scripts/bootstrap.sh

test:
	swift test

cli:
	swift build --product rootstock-blue

content-validate:
	@set -e; \
	missing=0; \
	for f in Content/detections/*/*.yaml Content/detections/*/*.yml; do \
	  [ -f "$$f" ] || continue; \
	  case "$$f" in */fixtures/*) continue ;; esac; \
	  dir=$$(dirname "$$f"); \
	  fixture=$$(grep -E '^fixture:' "$$f" | head -1 | sed 's/^fixture:[[:space:]]*//' | tr -d '"'); \
	  if [ -z "$$fixture" ]; then echo "FAIL: no fixture in $$f"; missing=1; continue; fi; \
	  if [ ! -f "$$dir/fixtures/$$fixture" ]; then echo "FAIL: missing $$dir/fixtures/$$fixture for $$f"; missing=1; fi; \
	done; \
	if [ "$$missing" -ne 0 ]; then exit 1; fi; \
	echo "content-validate OK"

sample-case:
	@bash Tools/scripts/package_case_sample.sh

check-non-goals:
	@bash Tools/scripts/check_non_goals.sh

xcode:
	@command -v xcodegen >/dev/null || { echo "install xcodegen: brew install xcodegen"; exit 1; }
	cd Apps && xcodegen generate
	@echo "Generated Apps/RootstockBlue.xcodeproj"
