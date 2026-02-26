# Developer Install Notes

Use this when working in restricted or offline environments.

## Offline/Sandbox Install

```bash
./scripts/venv_install.sh /tmp/mvar-launch-final
```

## Verify CLI Resolution

```bash
which mvar-demo
python -c "import mvar_core; print('mvar_core OK')"
```

`which mvar-demo` must point to your virtualenv `bin/` directory.

## Optional: system-site-packages fallback

If your environment requires shared site-packages:

```bash
USE_SYSTEM_SITE_PACKAGES=1 ./scripts/venv_install.sh /tmp/mvar-launch-final
```
