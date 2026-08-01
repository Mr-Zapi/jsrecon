source .venv/bin/activate
# No env vars needed: the API token is auto-generated and stored in
# $JSRECON_DATA/token, and the MCP/bearer principal acts as the owner account
# automatically. Run `python -m jsrecon.admin status` to print the token.
uvicorn jsrecon.server:app --host 127.0.0.1 --port 8777
