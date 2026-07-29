#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
EXPECTED_VERSION="$(<"${REPO_ROOT}/VERSION")"
VERSION="${1:-${EXPECTED_VERSION}}"
OUTPUT_DIR="${REPO_ROOT}/release"
ARCHIVE_NAME="rootstock-collector-v${VERSION}-macos-universal"
PRODUCT_NAME="RootstockCLI"

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
	echo "ERROR: invalid release version: ${VERSION}" >&2
	exit 2
fi

if [[ "${VERSION}" != "${EXPECTED_VERSION}" ]]; then
	echo "ERROR: version ${VERSION} does not match VERSION (${EXPECTED_VERSION})" >&2
	echo "Update VERSION and product metadata before building a release." >&2
	exit 2
fi

echo "Building Rootstock Collector v${VERSION} (universal macOS binary)..."

cd "${REPO_ROOT}/collector"
swift build -c release --arch arm64 --arch x86_64
BIN_DIR="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"

mkdir -p "${OUTPUT_DIR}"
STAGING_DIR="$(mktemp -d "${OUTPUT_DIR}/.rootstock-release.XXXXXX")"
trap 'rm -rf "${STAGING_DIR}"' EXIT
PACKAGE_DIR="${STAGING_DIR}/${ARCHIVE_NAME}"
mkdir -p "${PACKAGE_DIR}"

install -m 0755 "${BIN_DIR}/${PRODUCT_NAME}" "${PACKAGE_DIR}/rootstock-collector"
install -m 0644 "${REPO_ROOT}/LICENSE" "${PACKAGE_DIR}/LICENSE"
install -m 0644 "${REPO_ROOT}/collector/README.md" "${PACKAGE_DIR}/README.md"
install -m 0644 "${REPO_ROOT}/CHANGELOG.md" "${PACKAGE_DIR}/CHANGELOG.md"

for REQUIRED_FILE in rootstock-collector LICENSE README.md CHANGELOG.md; do
	if [[ ! -s "${PACKAGE_DIR}/${REQUIRED_FILE}" ]]; then
		echo "ERROR: release archive input is missing or empty: ${REQUIRED_FILE}" >&2
		exit 1
	fi
done

VERSION_OUTPUT="$("${PACKAGE_DIR}/rootstock-collector" --version)"
if [[ "${VERSION_OUTPUT}" != "rootstock-collector ${VERSION}" ]]; then
	echo "ERROR: binary reports '${VERSION_OUTPUT}', expected '${VERSION}'" >&2
	exit 1
fi

ARCHITECTURES="$(lipo -archs "${PACKAGE_DIR}/rootstock-collector")"
for REQUIRED_ARCHITECTURE in arm64 x86_64; do
	case " ${ARCHITECTURES} " in
		*" ${REQUIRED_ARCHITECTURE} "*) ;;
		*)
			echo "ERROR: release binary is missing ${REQUIRED_ARCHITECTURE}; found: ${ARCHITECTURES}" >&2
			exit 1
			;;
	esac
done

ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}.tar.gz"
(
	cd "${STAGING_DIR}"
	tar -czf "${ARCHIVE_PATH}" "${ARCHIVE_NAME}"
)

(
	cd "${OUTPUT_DIR}"
	shasum -a 256 "${ARCHIVE_NAME}.tar.gz" >"${ARCHIVE_NAME}.tar.gz.sha256"
)

tar -tzf "${ARCHIVE_PATH}" >/dev/null
EXPECTED_ARCHIVE_LISTING="$(
	printf '%s\n' \
		"${ARCHIVE_NAME}/" \
		"${ARCHIVE_NAME}/CHANGELOG.md" \
		"${ARCHIVE_NAME}/LICENSE" \
		"${ARCHIVE_NAME}/README.md" \
		"${ARCHIVE_NAME}/rootstock-collector" | LC_ALL=C sort
)"
ACTUAL_ARCHIVE_LISTING="$(tar -tzf "${ARCHIVE_PATH}" | LC_ALL=C sort)"
if [[ "${ACTUAL_ARCHIVE_LISTING}" != "${EXPECTED_ARCHIVE_LISTING}" ]]; then
	echo "ERROR: release archive contains an unexpected file set" >&2
	exit 1
fi

echo ""
echo "Archive: ${ARCHIVE_PATH}"
echo "Checksum: ${ARCHIVE_PATH}.sha256"
echo "Binary version: ${VERSION_OUTPUT}"
echo "Architectures: ${ARCHITECTURES}"
