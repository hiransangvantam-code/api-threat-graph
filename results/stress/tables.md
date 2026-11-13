## Table 21. Stress test: system size (Phases 3-4 on PostgreSQL)

ShopLite's EUJF (one real scan) cloned k times behind one gateway, so the rules fire as they do on ShopLite. One run per row in a fresh process with fresh tables, stopped after 300 s. Version 1.2 is the code before this test; 1.3 adds ANALYZE after loading the graph and the faster fix planner (same paths and same plans). Times above 10 s are in seconds.

| Copies k | Services | Endpoints | Graph nodes | Graph edges | Findings | Attack paths | Path query 1.2 (ms) | Path query 1.3 (ms) | Fix plan 1.2 (ms) | Fix plan 1.3 (ms) | Phase 3 1.2 (ms) | Phase 3 1.3 (ms) | Phase 4 + exports 1.3 (ms) | Peak memory 1.3 (MB) | Dashboard (KB) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 4 | 12 | 69 | 132 | 37 | 122 | 8 | 4 | 10 | 3 | 39 | 37 | 15 | 44 | 232 |
| 2 | 7 | 23 | 121 | 252 | 70 | 236 | 31 | 6 | 96 | 5 | 180 | 48 | 16 | 46 | 387 |
| 5 | 16 | 56 | 277 | 612 | 169 | 578 | 103 | 11 | 804 | 27 | 1,011 | 112 | 49 | 52 | 844 |
| 10 | 31 | 111 | 537 | 1,212 | 334 | 1,148 | 374 | 30 | 6,366 | 177 | 6,865 | 414 | 106 | 62 | 1,618 |
| 20 | 61 | 221 | 1,057 | 2,412 | 664 | 2,288 | 2,125 | 87 | 54.9 s | 476 | 57.3 s | 921 | 125 | 80 | 3,159 |
| 50 | 151 | 551 | 2,617 | 6,012 | 1,654 | 5,708 | – | 232 | – | 3,096 | > 300 s | 4,510 | 562 | 136 | 7,800 |
| 100 | 301 | 1101 | 5,217 | 12,012 | 3,304 | 11,408 | not run | 360 | not run | 15.1 s | not run | 20.7 s | 997 | 226 | 15,517 |

## Table 22. Stress test: call-chain density (Phases 3-4 on PostgreSQL)

k = 10 copies (31 services, 111 endpoints) plus d random endpoint-to-endpoint calls per backend endpoint, across copies. Attack paths follow CALLS chains up to 9 hops, so their number grows quickly with d.

| Calls per endpoint d | CALLS edges | Attack paths | Path query 1.2 (ms) | Path query 1.3 (ms) | Fix plan 1.2 (ms) | Fix plan 1.3 (ms) | Phase 3 1.2 (ms) | Phase 3 1.3 (ms) | Peak memory 1.3 (MB) |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 20 | 1,148 | 374 | 31 | 6,366 | 97 | 6,865 | 278 | 62 |
| 0.5 | 73 | 1,677 | 1,056 | 66 | 10.9 s | 325 | 12.2 s | 684 | 65 |
| 1 | 126 | 3,497 | 3,198 | 218 | 24.6 s | 1,006 | 28.1 s | 1,592 | 78 |
| 1.5 | 180 | 5,874 | 18.0 s | 565 | 40.9 s | 1,896 | 59.4 s | 2,956 | 109 |
| 2 | 233 | 9,325 | 98.2 s | 1,874 | 74.8 s | 3,532 | 173.6 s | 6,198 | 234 |
| 2.5 | 287 | 11,583 | – | 6,776 | – | 5,316 | > 300 s | 13.0 s | 514 |
| 3 | 337 | 12,813 | not run | 15.6 s | not run | 6,062 | not run | 23.2 s | 919 |
| 4 | – | – | not run | out of temp space | not run | – | not run | out of temp space | – |
| 5 | – | – | not run | out of temp space | not run | – | not run | out of temp space | – |
| 6 | – | – | not run | out of temp space | not run | – | not run | out of temp space | – |

Machine: 2 CPU cores, Python 3.13.18, PostgreSQL 16 in Docker on the same host, its data folder in memory (tmpfs, 4 GB). 'Out of temp space': the recursive attack path query needed more than the 4 GB of temporary space PostgreSQL had, because the number of paths up to 9 hops grows exponentially with d.
