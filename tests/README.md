# ESS integration tests

Folder ini terpisah dari `src/` dan dipakai untuk smoke test serta orchestration tiga node.

## Isi
- `assert_logs.sh` — menunggu pola log tertentu muncul
- `run_smoke.sh` — test lokal satu node
- `run_three_node.sh` — test tiga node via SSH

## Smoke test lokal

Jalankan di masing-masing server:

```bash
chmod +x tests/*.sh
NODE_ROLE=supernode PUBLIC_IP=13.41.78.146 tests/run_smoke.sh
