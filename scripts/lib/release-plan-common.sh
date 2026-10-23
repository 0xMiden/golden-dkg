#!/bin/bash

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: Required command '$1' is not installed or not in PATH" >&2
        exit 1
    fi
}

crates_io_get() {
    local path="$1"
    local output_file="$2"
    local status

    if ! status="$(
        curl -sS -A "${CRATES_IO_USER_AGENT:-golden-dkg-release-plan}" \
            -o "$output_file" \
            -w "%{http_code}" \
            "https://crates.io/api/v1/${path}"
    )"; then
        echo "ERROR: could not query crates.io path '$path'" >&2
        exit 1
    fi

    printf '%s' "$status"
}

download_published_crate() {
    local package="$1"
    local version="$2"
    local output_file="$3"
    local status

    if ! status="$(
        curl -sS -L -A "${CRATES_IO_USER_AGENT:-golden-dkg-release-plan}" \
            -o "$output_file" \
            -w "%{http_code}" \
            "https://crates.io/api/v1/crates/${package}/${version}/download"
    )"; then
        echo "ERROR: could not download $package v$version from crates.io" >&2
        exit 1
    fi

    case "$status" in
        200)
            ;;
        404)
            return 1
            ;;
        *)
            echo "ERROR: crates.io returned HTTP $status while downloading $package v$version" >&2
            exit 1
            ;;
    esac
}

latest_published_version() {
    local package="$1"
    local body_file="$RELEASE_PLAN_TMPDIR/${package}.latest.json"
    local status

    status="$(crates_io_get "crates/${package}" "$body_file")"

    case "$status" in
        200)
            jq -r '.crate.max_stable_version // .crate.max_version // empty' "$body_file"
            ;;
        404)
            printf ''
            ;;
        *)
            echo "ERROR: crates.io returned HTTP $status while checking $package" >&2
            exit 1
            ;;
    esac
}

published_version_info() {
    local package="$1"
    local version="$2"
    local body_file="$RELEASE_PLAN_TMPDIR/${package}-${version}.json"
    local status

    status="$(crates_io_get "crates/${package}/${version}" "$body_file")"

    case "$status" in
        200)
            printf '%s' "$body_file"
            return 0
            ;;
        404)
            return 1
            ;;
        *)
            echo "ERROR: crates.io returned HTTP $status while checking $package v$version" >&2
            exit 1
            ;;
    esac
}

crate_version_exists() {
    local package="$1"
    local version="$2"

    published_version_info "$package" "$version" >/dev/null
}

baseline_commit_for() {
    local package="$1"
    local version="$2"
    local body_file sha tag

    if body_file="$(published_version_info "$package" "$version")"; then
        sha="$(jq -r '.version.trustpub_data.sha // empty' "$body_file")"
        if [[ -n "$sha" ]] && git cat-file -e "${sha}^{commit}" 2>/dev/null; then
            printf '%s\n' "$sha"
            return 0
        fi
    fi

    tag="v$version"
    if git rev-parse --verify --quiet "${tag}^{commit}" >/dev/null; then
        git rev-parse "${tag}^{commit}"
        return 0
    fi

    git fetch --no-tags origin "+refs/tags/${tag}:refs/tags/${tag}" >/dev/null 2>&1 || true

    if [[ -n "${sha:-}" ]] && git cat-file -e "${sha}^{commit}" 2>/dev/null; then
        printf '%s\n' "$sha"
        return 0
    fi

    if git rev-parse --verify --quiet "${tag}^{commit}" >/dev/null; then
        git rev-parse "${tag}^{commit}"
        return 0
    fi

    return 1
}

package_archive_matches_published() {
    local package="$1"
    local version="$2"
    local workspace_root="$3"
    local package_target_dir local_archive published_archive local_dir published_dir

    check_command "diff"
    check_command "tar"

    package_target_dir="$RELEASE_PLAN_TMPDIR/package-target/$package"
    local_archive="$package_target_dir/package/$package-$version.crate"
    published_archive="$RELEASE_PLAN_TMPDIR/published-crates/$package-$version.crate"
    local_dir="$RELEASE_PLAN_TMPDIR/package-compare/$package/local"
    published_dir="$RELEASE_PLAN_TMPDIR/package-compare/$package/published"

    mkdir -p "$(dirname "$published_archive")" "$local_dir" "$published_dir"

    cargo package \
        --manifest-path "$workspace_root/Cargo.toml" \
        --package "$package" \
        --locked \
        --allow-dirty \
        --no-verify \
        --target-dir "$package_target_dir" >/dev/null

    if [[ ! -f "$local_archive" ]]; then
        echo "ERROR: cargo package did not create $local_archive" >&2
        exit 1
    fi

    download_published_crate "$package" "$version" "$published_archive"

    tar -xzf "$local_archive" -C "$local_dir"
    tar -xzf "$published_archive" -C "$published_dir"

    find "$local_dir" "$published_dir" -name .cargo_vcs_info.json -delete
    diff -qr "$local_dir" "$published_dir" >/dev/null
}

version_cmp() {
    local left="$1"
    local right="$2"

    awk -v left="$left" -v right="$right" '
        function core(version, parts) {
            sub(/\+.*/, "", version)
            split(version, prerelease_parts, "-")
            split(prerelease_parts[1], parts, ".")
        }

        BEGIN {
            core(left, left_parts)
            core(right, right_parts)

            for (i = 1; i <= 3; i++) {
                left_part = left_parts[i] + 0
                right_part = right_parts[i] + 0

                if (left_part > right_part) {
                    print 1
                    exit
                }

                if (left_part < right_part) {
                    print -1
                    exit
                }
            }

            print 0
        }
    '
}

semver_release_type() {
    local current_version="$1"
    local baseline_version="$2"
    local cmp

    cmp="$(version_cmp "$current_version" "$baseline_version")"
    if [[ "$cmp" -le 0 ]]; then
        echo "ERROR: cannot classify non-increasing release $baseline_version -> $current_version" >&2
        return 1
    fi

    # Rust semver treats a bump of the leftmost nonzero component as breaking:
    # 1.x -> 2.x, 0.4 -> 0.5, and 0.0.1 -> 0.0.2 are all major releases.
    # Explicit classification is also needed for prebuilt rustdoc JSON, where
    # cargo-semver-checks cannot always recover the current package version.
    awk -v current="$current_version" -v baseline="$baseline_version" '
        BEGIN {
            sub(/[-+].*/, "", current)
            sub(/[-+].*/, "", baseline)
            split(current, current_parts, ".")
            split(baseline, baseline_parts, ".")

            if (current_parts[1] + 0 > baseline_parts[1] + 0) {
                print "major"
            } else if (current_parts[2] + 0 > baseline_parts[2] + 0) {
                print (baseline_parts[1] + 0 == 0 ? "major" : "minor")
            } else {
                print (baseline_parts[1] + 0 == 0 && baseline_parts[2] + 0 == 0 ? "major" : "patch")
            }
        }
    '
}

package_has_library_target() {
    local package="$1"

    # shellcheck disable=SC2154
    printf '%s' "$metadata_json" |
        jq -e --arg package "$package" '
          . as $m
          | $m.packages[]
          | select(.name == $package and (.id as $id | $m.workspace_members | index($id)))
          | .targets[]
          | select(.kind | index("lib"))
        ' >/dev/null
}

published_package_root() {
    local package="$1"
    local version="$2"
    local archive root

    check_command "tar"

    archive="$RELEASE_PLAN_TMPDIR/published-baselines/$package-$version.crate"
    root="$RELEASE_PLAN_TMPDIR/published-baselines/$package-$version"
    if [[ ! -f "$root/$package-$version/Cargo.toml" ]]; then
        mkdir -p "$(dirname "$archive")" "$root"
        download_published_crate "$package" "$version" "$archive" || return
        tar -xzf "$archive" -C "$root" || return
    fi
    printf '%s/%s-%s\n' "$root" "$package" "$version"
}

published_package_has_library_target() {
    local package="$1"
    local version="$2"
    local root metadata

    root="$(published_package_root "$package" "$version")" || return
    metadata="$(
        cargo metadata \
            --manifest-path "$root/Cargo.toml" \
            --no-deps \
            --format-version 1
    )" || return

    printf '%s' "$metadata" |
        jq -e --arg package "$package" '
          .packages[]
          | select(.name == $package)
          | .targets[]
          | select(.kind | index("lib"))
        ' >/dev/null
}

package_feature_names() {
    local package="$1"
    local source_root="$2"

    cargo metadata \
        --manifest-path "$source_root/Cargo.toml" \
        --no-deps \
        --format-version 1 |
        jq -er --arg package "$package" '
          .packages[] | select(.name == $package) | .features | keys | sort
        '
}

package_rustdoc_name() {
    local package="$1"

    # shellcheck disable=SC2154
    printf '%s' "$metadata_json" |
        jq -r --arg package "$package" '
          . as $m
          | $m.packages[]
          | select(.name == $package and (.id as $id | $m.workspace_members | index($id)))
          | .targets[]
          | select(.kind | index("lib"))
          | .name
          | gsub("-"; "_")
        ' |
        head -n 1
}

publishable_packages() {
    # metadata_json is set by the calling release-plan script.
    # shellcheck disable=SC2154
    printf '%s' "$metadata_json" |
        jq -r '
          . as $m
          | $m.packages[]
          | select((.id as $id | $m.workspace_members | index($id)) and .publish != [])
          | [.name, .version] | @tsv
        ' |
        sort
}

build_rustdoc_json() {
    local package="$1"
    local source_root="$2"
    local target_dir="$3"
    local rustdoc_name
    shift 3

    rustdoc_name="$(package_rustdoc_name "$package")" || return
    RUSTC_BOOTSTRAP=1 RUSTDOCFLAGS="-Z unstable-options --output-format json" cargo rustdoc \
        --manifest-path "$source_root/Cargo.toml" \
        --package "$package" \
        --lib \
        --locked \
        --target-dir "$target_dir" \
        "$@" >/dev/null || return

    printf '%s/doc/%s.json\n' "$target_dir" "$rustdoc_name"
}

run_semver_check() {
    local package="$1"
    local baseline_version="$2"
    local workspace_root="$3"
    local baseline_commit="${4:-}"
    local current_version="$5"
    local semver_cmd semver_cargo_home semver_target_dir semver_workdir
    local baseline_root current_json baseline_json release_type
    local current_features baseline_features shared_features public_features compat_features removed_features
    local index profile features
    local profiles=(default)
    local feature_sets=("")
    local rustdoc_feature_args=()
    local semver_feature_args=()

    if ! release_type="$(semver_release_type "$current_version" "$baseline_version")"; then
        return 1
    fi
    echo "Rust semver release type for $package: $release_type ($baseline_version -> $current_version)"

    check_command "cargo-semver-checks"
    semver_cmd="$(command -v cargo-semver-checks)"
    semver_cargo_home="${CARGO_SEMVER_CARGO_HOME:-$RELEASE_PLAN_TMPDIR/cargo-home}"
    semver_target_dir="${CARGO_SEMVER_TARGET_DIR:-$RELEASE_PLAN_TMPDIR/target}"
    semver_workdir="$RELEASE_PLAN_TMPDIR/semver-workdir"
    mkdir -p "$semver_cargo_home" "$semver_target_dir" "$semver_workdir"

    if ! package_has_library_target "$package"; then
        echo "Skipping semver for $package because it has no library target."
        return 0
    fi

    if [[ -n "$baseline_commit" ]]; then
        baseline_root="$RELEASE_PLAN_TMPDIR/baseline-source/$package-$baseline_commit"
        mkdir -p "$baseline_root"
        git archive "$baseline_commit" | tar -x -C "$baseline_root" || return
    else
        baseline_root="$(published_package_root "$package" "$baseline_version")" || return
    fi

    current_features="$(package_feature_names "$package" "$workspace_root")" || return
    baseline_features="$(package_feature_names "$package" "$baseline_root")" || return
    removed_features="$(
        jq -rn --argjson current "$current_features" --argjson baseline "$baseline_features" '
          $baseline - $current - ["default", "insecure-revealed-witness"] | join(",")
        '
    )" || return
    if [[ "$release_type" != major && -n "$removed_features" ]]; then
        echo "ERROR: $package removes public features without a breaking version bump: $removed_features" >&2
        return 1
    fi
    shared_features="$(
        jq -cn --argjson current "$current_features" --argjson baseline "$baseline_features" '
          $current | map(select(. as $feature | $baseline | index($feature)))
        '
    )" || return
    public_features="$(
        printf '%s' "$shared_features" |
            jq -r '. - ["default", "insecure-revealed-witness", "bulletproofs-compat"] | join(",")'
    )" || return
    if [[ -n "$public_features" ]]; then
        profiles+=(public-features)
        feature_sets+=("$public_features")
    fi
    if printf '%s' "$shared_features" | jq -e 'index("bulletproofs-compat") != null' >/dev/null; then
        compat_features="$(
            printf '%s' "$shared_features" |
                jq -r '. - ["default", "insecure-revealed-witness", "cycle-pedersen"] | join(",")'
        )" || return
        profiles+=(compat)
        feature_sets+=("$compat_features")
    fi

    for index in "${!profiles[@]}"; do
        profile="${profiles[$index]}"
        features="${feature_sets[$index]}"
        echo "Checking $package profile $profile${features:+ ($features)}"
        rustdoc_feature_args=(--features "")
        semver_feature_args=(--default-features)
        if [[ "$profile" != default ]]; then
            rustdoc_feature_args=(--no-default-features --features "$features")
            semver_feature_args=(--only-explicit-features --features "$features")
        fi

        if [[ -n "$baseline_commit" ]]; then
            current_json="$(build_rustdoc_json "$package" "$workspace_root" "$RELEASE_PLAN_TMPDIR/rustdoc/current/$package/$profile" "${rustdoc_feature_args[@]}")" || return
            baseline_json="$(build_rustdoc_json "$package" "$baseline_root" "$RELEASE_PLAN_TMPDIR/rustdoc/baseline/$package/$profile" "${rustdoc_feature_args[@]}")" || return

            (
                cd "$semver_workdir" || return
                CARGO_HOME="$semver_cargo_home" CARGO_TARGET_DIR="$semver_target_dir" \
                    "$semver_cmd" semver-checks \
                    --current-rustdoc "$current_json" \
                    --baseline-rustdoc "$baseline_json" \
                    --release-type "$release_type" \
                    --color never
            ) || return
        else
            (
                cd "$semver_workdir" || return
                CARGO_HOME="$semver_cargo_home" CARGO_TARGET_DIR="$semver_target_dir" \
                    "$semver_cmd" semver-checks \
                    --manifest-path "$workspace_root/Cargo.toml" \
                    --package "$package" \
                    --baseline-version "$baseline_version" \
                    --release-type "$release_type" \
                    "${semver_feature_args[@]}" \
                    --color never
            ) || return
        fi
    done
}
