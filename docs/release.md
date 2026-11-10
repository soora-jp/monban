# Release

## Branches

- `develop`: integration branch. All pull requests target `develop`.
- `main`: released code. Only updated by merging `develop` for a release.

CI ([ci.yml](../.github/workflows/ci.yml)) runs on pull requests and pushes to
both branches: formatting, `go mod tidy`, `go vet`, staticcheck, govulncheck,
race tests, and a Docker build.

Publishing a GitHub Release runs [release.yml](../.github/workflows/release.yml),
which tests, builds, and pushes `ghcr.io/soora-jp/monban:<tag>` and
`ghcr.io/soora-jp/monban:latest`. `latest` always points to the most recently
published release.

## One-time setup

1. Set `develop` as the default branch.
2. Protect `develop` and `main`: require a pull request and the
   `Go checks (fmt, vet, staticcheck, govulncheck, race tests)` and
   `Docker build` checks.
3. Enable **Private vulnerability reporting** under Settings → Security.
4. After the first release, open the `monban` package on GitHub, set its
   visibility to **Public**, and check that it is linked to this repository.

## Steps

Versions use `MAJOR.MINOR.PATCH` with no `v` prefix, for example `0.2.0`.

1. **Update the image tag** in [deploy/kubernetes.yaml](../deploy/kubernetes.yaml)
   with a pull request to `develop`.

2. **Merge `develop` into `main`** with a pull request titled `Release 0.2.0`.
   Wait for CI to pass, then merge.

3. **Publish the release** from `main`:

   ```sh
   gh release create 0.2.0 --target main --generate-notes
   ```

   Or use **Releases → Draft a new release** on GitHub, create the tag `0.2.0`
   on `main`, and publish.

4. **Check the image** once the Release workflow succeeds:

   ```sh
   docker run --rm ghcr.io/soora-jp/monban:0.2.0 --version   # prints 0.2.0
   ```

## If the release fails

- **Before the image is pushed** (tag format, tests, or build failed): delete the
  release and its tag, fix the problem on `develop`, and start again from step 2.

  ```sh
  gh release delete 0.2.0 --cleanup-tag --yes
  ```

- **After the image is pushed:** do not replace it. Fix the problem and release a
  new patch version.
