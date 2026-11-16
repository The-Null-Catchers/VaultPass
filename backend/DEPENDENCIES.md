# Python dependency locks

`requirements.lock` pins the runtime dependencies used by the Docker image.
`requirements-dev.lock` adds the test, typing and audit tools and constrains all
runtime versions to `requirements.lock`. CI installs the development lock, then
installs the editable project without resolving dependencies again. `pip check`
rejects a lock that no longer satisfies `pyproject.toml`.

To regenerate after changing `pyproject.toml`, use Python 3.12 and uv:

```sh
uv pip compile pyproject.toml --upgrade --no-annotate --output-file requirements.lock --python 3.12
uv pip compile pyproject.toml --extra dev --constraint requirements.lock --upgrade --no-annotate --output-file requirements-dev.lock --python 3.12
pip install -r requirements-dev.lock
pip install --no-deps -e '.[dev]'
pip check
pip-audit -r requirements.lock
pip-audit -r requirements-dev.lock
```

Run the backend tests with Redis available, then validate PostgreSQL migrations
and the web E2E flows. A successful historical audit is not evidence that the
same dependency versions remain free of newly reported vulnerabilities.

The runtime remains Python 3.12. The proposed Python 3.15 image upgrade needs its
own wheel/build compatibility validation; it is not part of this security fix.
