# PyPI Release Runbook

This runbook documents trusted publishing for `mvar` and the tag-based publish flow.

## Setup Trusted Publisher

Configure a trusted publisher in PyPI with these exact fields:

- PyPI project name: `mvar`
- GitHub repository: `mvar-security/mvar`
- Workflow filename: `pypi-publish.yml`
- Environment name: `pypi`

## Release Steps

1. Ensure `main` is green and the intended release commit is merged.
2. Create and push a release tag:

```bash
git tag vX.X.X
git push origin vX.X.X
```

3. Tag push triggers `.github/workflows/pypi-publish.yml` and uploads package artifacts to PyPI via OIDC trusted publishing.

## Post-publish verification

```bash
pip install mvar==<version>
python -c "from mvar import protect; print('install verified')"
```
