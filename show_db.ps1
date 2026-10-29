# Shows what the Oracle database really stores (ciphertext, blind indexes, wrapped keys).
# Run while `docker compose up` is running.
Set-Location $PSScriptRoot
docker compose cp tools/show_db.sql oracle:/tmp/show_db.sql | Out-Null
docker compose exec -T oracle sqlplus -s trustgate/TrustGate_1@//localhost:1521/FREEPDB1 "@/tmp/show_db.sql"
