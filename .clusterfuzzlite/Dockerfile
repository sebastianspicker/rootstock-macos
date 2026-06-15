FROM gcr.io/oss-fuzz-base/base-builder-python:ubuntu-24-04

COPY . $SRC/rootstock
WORKDIR $SRC/rootstock

RUN python3 -m pip install --require-hashes -r fuzz/requirements.txt

COPY fuzz/fuzz_validate_scan.py $SRC/
COPY .clusterfuzzlite/build.sh $SRC/build.sh
