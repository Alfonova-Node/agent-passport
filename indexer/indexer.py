#!/usr/bin/env python3
"""
Agent Passport Indexer v1 — ERC-8183 track-record indexer + signed stats writer.

Single file, stdlib-only. Keccak via eth_utils when available, else `cast keccak`.
Signing/broadcast delegated to foundry `cast` (EIP-191 behavior proven identical
to PassportRegistry on-chain verification: `cast wallet sign <digest>` prefixes
"\\x19Ethereum Signed Message:\\n32" — matches the contract's ethHash).

Modes:
  scan   — read commerce events over a block range, aggregate per-provider facts
  settle — write indexer-signed stats for claimed passports (skips unclaimed)
  watch  — scan+settle loop every --epoch seconds
  demo   — inject one synthetic record through the real settle write-path

State: sqlite at --db (default ./indexer_state.db).
"""
import argparse, json, os, sqlite3, subprocess, sys, time, urllib.request

EVENT_SIGS = {
    "JobCreated":      "JobCreated(uint256,address,address,uint256,address,address)",
    "JobFunded":       "JobFunded(uint256,address,address,uint256)",
    "JobSubmitted":    "JobSubmitted(uint256,address,bytes32)",
    "JobCompleted":    "JobCompleted(uint256,address,bytes32)",
    "JobRejected":     "JobRejected(uint256,address,bytes32)",
    "JobExpired":      "JobExpired(uint256)",
    "PaymentReleased": "PaymentReleased(uint256,address,uint256)",
    "ProviderSet":     "ProviderSet(uint256,address)",
}

def keccak_hex(data_hex: str) -> str:
    """keccak256 of 0x-prefixed hex data -> 0x-hex."""
    try:
        from eth_utils import keccak
        return "0x" + keccak(bytes.fromhex(data_hex[2:])).hex()
    except ImportError:
        out = subprocess.run(["cast", "keccak", data_hex], capture_output=True, text=True)
        return out.stdout.strip()

def keccak_text(text: str) -> str:
    try:
        from eth_utils import keccak
        return "0x" + keccak(text=text).hex()
    except ImportError:
        out = subprocess.run(["cast", "keccak", text], capture_output=True, text=True)
        return out.stdout.strip()

def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(f"RPC error {method}: {out['error']}")
    return out["result"]

def topic0_map():
    return {name: keccak_text(sig) for name, sig in EVENT_SIGS.items()}

def w_addr(topic: str) -> str:
    return "0x" + topic[-40:]

def w_int(hexstr: str) -> int:
    return int(hexstr, 16)

def decode(name: str, log: dict):
    t, d = log["topics"], log["data"][2:]
    if name == "JobCreated":
        return {"jobId": w_int(t[1]), "provider": w_addr(t[3])}
    if name == "ProviderSet":
        return {"jobId": w_int(t[1]), "provider": w_addr(t[2])}
    if name == "JobFunded":
        return {"jobId": w_int(t[1]), "provider": w_addr(t[3]), "amount": w_int("0x" + d[:64])}
    if name == "JobSubmitted":
        return {"jobId": w_int(t[1]), "provider": w_addr(t[2])}
    if name in ("JobCompleted", "JobRejected"):
        return {"jobId": w_int(t[1])}
    if name == "JobExpired":
        return {"jobId": w_int(t[1])}
    if name == "PaymentReleased":
        return {"jobId": w_int(t[1]), "provider": w_addr(t[2]), "amount": w_int("0x" + d[:64])}
    return None

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(jobId TEXT PRIMARY KEY, provider TEXT);
CREATE TABLE IF NOT EXISTS stats(provider TEXT PRIMARY KEY, completed INTEGER DEFAULT 0,
  rejected INTEGER DEFAULT 0, expired INTEGER DEFAULT 0, volume TEXT DEFAULT '0',
  settledAt INTEGER DEFAULT 0, epoch INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY CHECK (id=1), lastBlock INTEGER);
"""

def db_open(path):
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db

def get_cursor(db):
    row = db.execute("SELECT lastBlock FROM cursor WHERE id=1").fetchone()
    return row[0] if row else None

def set_cursor(db, blk):
    db.execute("INSERT INTO cursor(id,lastBlock) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET lastBlock=excluded.lastBlock", (blk,))
    db.commit()

def upsert_provider(db, job_id, provider):
    db.execute("INSERT INTO jobs(jobId,provider) VALUES(?,?) ON CONFLICT(jobId) DO NOTHING", (str(job_id), provider))

def bump(db, provider, field, amount=1):
    db.execute(f"INSERT INTO stats(provider) VALUES(?) ON CONFLICT(provider) DO NOTHING", (provider,))
    cur = db.execute(f"SELECT {field} FROM stats WHERE provider=?", (provider,)).fetchone()
    db.execute(f"UPDATE stats SET {field}=? WHERE provider=?", (int(cur[0] or 0) + amount, provider))

def apply_event(db, name, ev):
    if name in ("JobCreated", "ProviderSet", "JobFunded", "JobSubmitted"):
        upsert_provider(db, ev["jobId"], ev["provider"])
        if name == "JobFunded":
            bump(db, ev["provider"], "volume", ev["amount"])
    elif name in ("JobCompleted", "JobRejected", "JobExpired"):
        row = db.execute("SELECT provider FROM jobs WHERE jobId=?", (str(ev["jobId"]),)).fetchone()
        if not row:
            return
        field = {"JobCompleted": "completed", "JobRejected": "rejected", "JobExpired": "expired"}[name]
        bump(db, row[0], field)
    elif name == "PaymentReleased":
        bump(db, ev["provider"], "volume", ev["amount"])

def scan(cfg, t0, db):
    last = get_cursor(db)
    start = (last + 1) if last is not None else cfg.from_block
    head = w_int(rpc(cfg.rpc, "eth_blockNumber", []))
    if start > head:
        print(f"[scan] up to date (head {head})")
        return
    total = 0
    chunk = cfg.chunk
    for lo in range(start, head + 1, chunk):
        hi = min(lo + chunk - 1, head)
        for name in EVENT_SIGS:
            filt = {"address": cfg.commerce, "topics": [t0[name]],
                    "fromBlock": hex(lo), "toBlock": hex(hi)}
            for log in rpc(cfg.rpc, "eth_getLogs", [filt]):
                ev = decode(name, log)
                if ev:
                    apply_event(db, name, ev)
                    total += 1
        set_cursor(db, hi)
    db.commit()
    print(f"[scan] {start}->{head}: {total} events indexed")
    for row in db.execute("SELECT provider, completed, rejected, expired, volume FROM stats ORDER BY completed DESC LIMIT 15"):
        print(f"  {row[0]}  c={row[1]} r={row[2]} e={row[3]} vol={row[4]}")

def call_registry(cfg, calldata):
    return rpc(cfg.rpc, "eth_call", [{"to": cfg.registry, "data": calldata}, "latest"])

def cast(args, quiet=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 and not quiet:
        print(r.stderr, file=sys.stderr)
    return r.stdout.strip()

def encode_stats_digest(agent, c, rj, e, vol, last_settled, next_epoch):
    words = [int(agent, 16), c, rj, e, vol, last_settled, next_epoch]
    blob = b"".join(v.to_bytes(32, "big") for v in words)
    return keccak_hex("0x" + blob.hex())

def settle_one(cfg, provider, c, rj, e, vol, ts):
    # claimed check
    cd = cast(["cast", "calldata", "claimed(address)", provider])
    if w_int(call_registry(cfg, cd)) != 1:
        print(f"  [skip] {provider}: no passport claimed")
        return False
    # read current struct: passports(address) -> (completed, rejected, expired, volume, lastSettled, epoch)
    cd = cast(["cast", "calldata", "passports(address)", provider])
    raw = call_registry(cfg, cd)[2:]
    words = [int(raw[i * 64:(i + 1) * 64], 16) for i in range(6)]
    prev_settled, epoch = words[4], words[5]
    last_settled = max(prev_settled, ts)
    next_epoch = epoch + 1
    digest = encode_stats_digest(provider, c, rj, e, vol, last_settled, next_epoch)
    sig = cast(["cast", "wallet", "sign", digest, "--private-key", cfg.key])
    out = cast(["cast", "send", cfg.registry,
                "updateStats(address,uint64,uint64,uint64,uint128,uint64,bytes)",
                provider, str(c), str(rj), str(e), str(vol), str(last_settled), sig,
                "--private-key", cfg.key, "--rpc-url", cfg.rpc,
                "--gas-price", "30gwei", "--priority-gas-price", "1gwei"], quiet=False)
    ok = "status" in out and "1 (success)" in out
    print(f"  [settle] {provider}: epoch {epoch}->{next_epoch} c={c} r={rj} e={e} vol={vol} -> {'OK' if ok else 'FAIL'}")
    if ok:
        db = sqlite3.connect(cfg.db)
        db.execute("""INSERT INTO stats(provider,completed,rejected,expired,volume,settledAt,epoch)
                      VALUES(?,?,?,?,?,?,?)
                      ON CONFLICT(provider) DO UPDATE SET completed=?, rejected=?, expired=?,
                      volume=?, settledAt=?, epoch=?""",
                   (provider, c, rj, e, str(vol), last_settled, next_epoch,
                    c, rj, e, str(vol), last_settled, next_epoch))
        db.commit()
        db.close()
    return ok

def settle(cfg, t0, db):
    ts = w_int(rpc(cfg.rpc, "eth_blockTimestamp" if False else "eth_getBlockByNumber", ["latest", False])["timestamp"])
    rows = db.execute("SELECT provider, completed, rejected, expired, volume FROM stats").fetchall()
    if not rows:
        print("[settle] nothing aggregated yet — run scan first")
        return
    print(f"[settle] {len(rows)} provider(s)")
    for provider, c, rj, e, vol in rows:
        settle_one(cfg, provider, c, rj, e, int(vol or 0), ts)

def demo(cfg, t0, db):
    ts = w_int(rpc(cfg.rpc, "eth_getBlockByNumber", ["latest", False])["timestamp"])
    print(f"[demo] synthetic record for {cfg.agent} through the real settle path")
    settle_one(cfg, cfg.agent, cfg.completed, cfg.rejected, cfg.expired, cfg.volume, ts)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["scan", "settle", "watch", "demo"])
    ap.add_argument("--rpc", default="https://data-seed-prebsc-1-s1.binance.org:8545")
    ap.add_argument("--registry", default="0x007618dCaD3d47D6C5c183c9A3FE29053dE47d13")
    ap.add_argument("--commerce", default="0xea4daa3100a767e86fded867729ae7446476eba6")
    ap.add_argument("--from-block", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--chunk", type=int, default=5000)
    ap.add_argument("--epoch", type=int, default=60)
    ap.add_argument("--db", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "indexer_state.db"))
    ap.add_argument("--key", default="/tmp/pp_wallet.txt")
    ap.add_argument("--agent", default="0x6CCd682f852FF61b1AC1fa88C291C3b44fDE609a")
    ap.add_argument("--completed", type=int, default=7)
    ap.add_argument("--rejected", type=int, default=2)
    ap.add_argument("--expired", type=int, default=1)
    ap.add_argument("--volume", type=lambda x: int(x, 0), default=3 * 10**18)
    cfg = ap.parse_args()
    cfg.key = [l for l in open(cfg.key).read().split() if len(l) == 66 and l.startswith("0x")][0]
    t0 = topic0_map()
    db = db_open(cfg.db)
    if cfg.mode == "scan":
        scan(cfg, t0, db)
    elif cfg.mode == "settle":
        settle(cfg, t0, db)
    elif cfg.mode == "demo":
        demo(cfg, t0, db)
    elif cfg.mode == "watch":
        while True:
            scan(cfg, t0, db)
            settle(cfg, t0, db)
            time.sleep(cfg.epoch)

if __name__ == "__main__":
    main()
