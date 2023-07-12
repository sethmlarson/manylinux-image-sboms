import os
import json
import pathlib

images = [
    "manylinux1_i686",
    "manylinux1_x86_64",
    "manylinux2010_i686",
    "manylinux2010_x86_64",
    "manylinux2014_aarch64",
    "manylinux2014_i686",
    "manylinux2014_ppc64le",
    "manylinux2014_s390x",
    "manylinux2014_x86_64",
    "manylinux_2_24_aarch64",
    "manylinux_2_24_i686",
    "manylinux_2_24_ppc64le",
    "manylinux_2_24_s390x",
    "manylinux_2_24_x86_64",
    "manylinux_2_28_aarch64",
    "manylinux_2_28_ppc64le",
    "manylinux_2_28_s390x",
    "manylinux_2_28_x86_64",
    "musllinux_1_1_aarch64",
    "musllinux_1_1_i686",
    "musllinux_1_1_ppc64le",
    "musllinux_1_1_s390x",
    "musllinux_1_1_x86_64",
]


def post_process_sbom(filepath: pathlib.Path):
    with filepath.open(mode="r") as f:
        data = json.loads(f.read())

    # Remove variable fields for consistency.
    data.pop("scanned", None)
    data.get("detector", {}).pop("version", None)

    with filepath.open(mode="w") as f:
        f.truncate()
        f.write(json.dumps(data, indent=2, sort_keys=True))


def main():
    for image in images:
        sbom_path = pathlib.Path(f"sboms/{image}/sbom.json")
        sbom_path.parent.mkdir(parents=True, exist_ok=True)

        exit_code = os.system(
            f"syft quay.io/pypa/{image} -o github > {sbom_path.absolute()}"
        )
        assert exit_code == 0

        post_process_sbom(sbom_path)


if __name__ == "__main__":
    main()
