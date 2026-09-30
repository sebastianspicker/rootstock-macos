.PHONY: bootstrap test content-validate cli help check-field-taxonomy check-non-goals

help:
	@echo "rootstock-blue targets:"
	@echo "  make bootstrap         - resolve SPM"
	@echo "  make test              - swift test"
	@echo "  make content-validate  - rules must have fixtures"
	@echo "  make cli               - build rootstock-blue CLI"
	@echo "  make check-non-goals   - scan product docs for forbidden claims"

bootstrap:
	@bash Tools/scripts/bootstrap.sh

test:
	sh ../scripts/swift-test -Xswiftc -warnings-as-errors

cli:
	swift build --product rootstock-blue -Xswiftc -warnings-as-errors

content-validate: check-field-taxonomy
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

check-field-taxonomy:
	@python3 Tools/scripts/check-field-taxonomy.py

check-non-goals:
	@bash Tools/scripts/check_non_goals.sh
