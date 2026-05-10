.PHONY: smoke smoke-negative test clean

smoke:
	./tools/run_smoke_pipeline.sh

smoke-negative:
	./tools/run_smoke_negative.sh

test:
	PYTHONPATH=. pytest -q

clean:
	rm -rf demo/out demo/out_negative
	rm -f crash-* leak-* timeout-*