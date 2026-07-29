#checkov:skip=CKV_DOCKER_2:ClusterFuzzLite uses this image only to build fuzzers; it exposes no service to health-check.
#checkov:skip=CKV_DOCKER_3:The upstream OSS-Fuzz builder controls build identity and writable SRC, OUT, and WORK directories.
FROM gcr.io/oss-fuzz-base/base-builder-python:ubuntu-24-04

COPY . $SRC/rootstock
WORKDIR $SRC/rootstock

RUN python3 -m pip install --require-hashes -r fuzz/requirements.txt

COPY fuzz/fuzz_validate_scan.py $SRC/
COPY .clusterfuzzlite/build.sh $SRC/build.sh
