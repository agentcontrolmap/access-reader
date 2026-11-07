#!/usr/bin/env python3
"""
access_reader.py - read-only "who can do what, and how fast" for OpenZeppelin AccessManager based systems
(for example IPOR Fusion vaults).

Copyright (c) 2026 agentcontrolmap. MIT License (see LICENSE). Keep this notice when you copy or modify the file.

For each manager it prints, from the chain:
  * which roles exist and who holds each role right now (hasRole, not just history),
  * the execution delay of every holder (0 = can act immediately; N = must schedule and wait N seconds),
  * each role's admin role, guardian role and grant delay,
  * what the holder is: a plain key (no code at the address), a key with an EIP-7702 delegation marker,
    a Safe (threshold and owners, one level), or another contract,
  * for chosen contract functions: which role gates them and who can call them fastest.

Where holders come from: an AccessManager cannot be enumerated from state, so holders come from RoleGranted logs.
Log sources, first that works: "logs_file" (JSON saved from an explorer), "etherscan_chainid" (Etherscan v2 API, free key in the
environment variable ETHERSCAN_API_KEY), "blockscout" (public Blockscout API v2 base url), "rpc_logs" (eth_getLogs from block 0;
many public RPCs refuse). "holders_hint" ([[role, address], ...]) adds candidates by hand. If the log list may be incomplete,
the report says so.

Read-only: eth_call, eth_getCode, and HTTP GET of public logs. No keys, no transactions.
Limits (also printed in the report):
  * "plain key" means no code at the address. MPC, hardware or an off-chain multisig behind a key is not visible.
  * A Safe is shown one level deep: its owners are listed, nested Safes are not expanded.
  * Role names are the IPOR Fusion names unless the target gives its own "role_names"; other protocols show numbers.
  * Delay 0 is the delay stored for that holder in the manager. A target may also have an admin delay or be closed; both are shown.
  * The report is a map of who can act and how fast. It is not a statement that anything is wrong.

Usage:  RPC_URL=https://... python3 access_reader.py targets.json [--json out.json]
        python3 access_reader.py --selftest
"""
import json, os, sys, time, urllib.request, urllib.parse

T_GRANT = "0xf98448b987f1428e0e230e1f3c6e2ce15b5693eaf31827fbd0b1ec4b424ae7cf"   # RoleGranted(uint64,address,uint32,uint48,bool)
T_REVOKE = "0xf229baa593af28c41b1d16b748cd7688f0c83aaf92d4be41c44005defe84c166"  # RoleRevoked(uint64,address)
S = {"hasRole": "0xd1f856ee", "getAccess": "0x3078f114", "getRoleAdmin": "0x530dd456", "getRoleGuardian": "0x0b0a93ba",
     "getRoleGrantDelay": "0x12be8727", "getTargetFunctionRole": "0x6d5115bd", "getTargetAdminDelay": "0x4c1da1e2",
     "isTargetClosed": "0xa166aa89", "getThreshold": "0xe75235b8", "getOwners": "0xa0e67e2b"}
MAX_PAGES = 80
PUBLIC_ROLE = 2 ** 64 - 1
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"

FUSION_ROLES = {
    0: "ADMIN", 1: "OWNER", 2: "GUARDIAN", 3: "TECH_PLASMA_VAULT", 4: "IPOR_DAO", 5: "TECH_CONTEXT_MANAGER",
    6: "TECH_WITHDRAW_MANAGER", 7: "TECH_VAULT_TRANSFER_SHARES", 100: "ATOMIST", 200: "ALPHA", 300: "FUSE_MANAGER",
    301: "PRE_HOOKS_MANAGER", 400: "TECH_PERFORMANCE_FEE_MANAGER", 500: "TECH_MANAGEMENT_FEE_MANAGER",
    600: "CLAIM_REWARDS", 601: "TECH_REWARDS_CLAIM_MANAGER", 700: "TRANSFER_REWARDS", 800: "WHITELIST",
    900: "CONFIG_INSTANT_WITHDRAWAL_FUSES", 901: "WITHDRAW_MANAGER_REQUEST_FEE", 902: "WITHDRAW_MANAGER_WITHDRAW_FEE",
    1000: "UPDATE_MARKETS_BALANCES", 1100: "UPDATE_REWARDS_BALANCE", 1200: "PRICE_ORACLE_MIDDLEWARE_MANAGER",
}


def word(n):
    return "%064x" % n


def pad_addr(a):
    return a[2:].lower().rjust(64, "0")


def uint_from_word(w):
    return int(w, 16) if w and len(w) == 66 else None


def is_tech(name):
    return name.startswith("TECH_") or name == "IPOR_DAO"


# ---------------------------------------------------------------- JSON-RPC (read-only)
class Rpc:
    def __init__(self, url):
        self.url = url
        self.cache = {}

    def call(self, method, params, tries=4):
        key = json.dumps([method, params])
        if key in self.cache:
            return self.cache[key]
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        err = None
        for i in range(tries):
            try:
                req = urllib.request.Request(self.url, body, {"Content-Type": "application/json", "User-Agent": "access-reader/1"})
                d = json.loads(urllib.request.urlopen(req, timeout=40).read())
                if d.get("error"):
                    raise ValueError(str(d["error"])[:120])
                self.cache[key] = d.get("result")
                return self.cache[key]
            except ValueError:
                raise
            except Exception as e:  # network error, rate limit, timeout
                err = e
                time.sleep(1.5 * (i + 1))
        raise RuntimeError("rpc failed: %s" % str(err)[:80])

    def eth_call(self, to, data):
        return self.call("eth_call", [{"to": to, "data": data}, "latest"])


# ---------------------------------------------------------------- event sources
def parse_events(logs):
    """RoleGranted / RoleRevoked logs (explorer or RPC shape) -> ordered list of (kind, role, account)."""
    ev = []
    for pos, lg in enumerate(logs):
        t = [x for x in (lg.get("topics") or []) if x]
        if len(t) < 3 or t[0].lower() not in (T_GRANT, T_REVOKE):
            continue
        blk = lg.get("blockNumber", lg.get("block_number", 0))
        blk = int(blk, 16) if isinstance(blk, str) else int(blk or 0)
        idx = lg.get("logIndex", lg.get("index", pos))
        idx = int(idx, 16) if isinstance(idx, str) else int(idx or 0)
        ev.append((blk, idx, "grant" if t[0].lower() == T_GRANT else "revoke", int(t[1], 16), "0x" + t[2][-40:].lower()))
    ev.sort()
    return [(k, r, a) for _, _, k, r, a in ev]


def http_json(url, tries=4):
    err = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "access-reader/1", "Accept": "application/json"})
            return json.loads(urllib.request.urlopen(req, timeout=60).read())
        except Exception as e:  # noqa
            err = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError("http failed: %s" % str(err)[:80])


def blockscout_logs(base, addr):
    items, params, pages = [], {}, 0
    while True:
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        j = http_json("%s/api/v2/addresses/%s/logs%s" % (base.rstrip("/"), addr, q))
        items += j.get("items", [])
        nxt = j.get("next_page_params")
        pages += 1
        if not nxt:
            return items, True
        if pages >= MAX_PAGES:
            return items, False
        params = nxt
        time.sleep(0.3)


def etherscan_logs(chainid, addr, key):
    """RoleGranted + RoleRevoked logs through the Etherscan v2 API (free key). Returns (items, complete)."""
    items = []
    for topic in (T_GRANT, T_REVOKE):
        page = 1
        while True:
            q = urllib.parse.urlencode({"chainid": chainid, "module": "logs", "action": "getLogs", "address": addr, "fromBlock": 0,
                                        "toBlock": "latest", "topic0": topic, "page": page, "offset": 1000, "apikey": key})
            j = http_json("https://api.etherscan.io/v2/api?" + q)
            res = j.get("result")
            if isinstance(res, list):
                items += res
                if len(res) < 1000:
                    break
            elif "No records found" in str(j.get("message", "")) + str(res):
                break
            else:
                raise RuntimeError("etherscan: %s" % str(res or j.get("message"))[:80])
            page += 1
            if page > 10:
                return items, False
            time.sleep(0.4)
    return items, True


def get_events(rpc, cfg):
    """Returns (events, complete, note)."""
    a = cfg["manager"].lower()
    pre = ""
    if cfg.get("logs") is not None:
        return parse_events(cfg["logs"]), True, "logs: inline"
    if cfg.get("logs_file"):
        j = json.load(open(cfg["logs_file"]))
        logs = j["data"]["result"] if isinstance(j, dict) and "data" in j else j
        return parse_events(logs), bool(cfg.get("logs_file_complete", True)), "logs: file %s" % cfg["logs_file"]
    key = os.environ.get("ETHERSCAN_API_KEY")
    note = ""
    if cfg.get("etherscan_chainid") and key:
        try:
            logs, full = etherscan_logs(cfg["etherscan_chainid"], a, key)
            return parse_events(logs), full, "logs: etherscan v2 (%d role events%s)" % (len(logs), "" if full else ", page cap reached, may be incomplete")
        except Exception as e:  # noqa
            pre = "etherscan failed (%s)" % str(e).replace(key, "***")[:70]
    if cfg.get("blockscout"):
        try:
            logs, full = blockscout_logs(cfg["blockscout"], a)
            return parse_events(logs), full, "logs: blockscout (%d logs%s)" % (len(logs), "" if full else ", page cap reached, may be incomplete")
        except Exception as e:  # noqa
            note = (pre + "; " if pre else "") + "blockscout failed (%s)" % str(e)[:60]
    else:
        note = pre
    if cfg.get("rpc_logs", True):
        try:
            logs = rpc.call("eth_getLogs", [{"address": a, "fromBlock": "0x0", "toBlock": "latest", "topics": [[T_GRANT, T_REVOKE]]}])
        except Exception:  # noqa
            logs = None
        if logs is not None:
            return parse_events(logs), True, (note + "; " if note else "") + "logs: rpc"
        note = (note + "; " if note else "") + "rpc getLogs refused"
    return [], False, note + "; no log source worked: holders come only from holders_hint"


# ---------------------------------------------------------------- who is the holder
def decode_owner_list(h):
    """ABI-encoded address[] -> list of lowercase addresses, or None."""
    try:
        b = h[2:]
        off = int(b[0:64], 16) * 2
        n = int(b[off:off + 64], 16)
        return ["0x" + b[off + 64 + 64 * i + 24: off + 64 + 64 * (i + 1)] for i in range(n)] if 0 < n < 100 else None
    except Exception:  # noqa
        return None


def classify(rpc, a):
    """Short description of an address: plain key / key with 7702 marker / Safe (one level) / other contract."""
    try:
        code = (rpc.call("eth_getCode", [a, "latest"]) or "0x").lower()
    except Exception as e:  # noqa
        return {"kind": "not read", "keys": None, "note": str(e)[:60]}
    if code in ("0x", "0x0"):
        return {"kind": "plain key (no code)", "keys": 1}
    if code.startswith("0xef0100") and len(code) == 48:
        return {"kind": "key with EIP-7702 delegation", "keys": 1, "delegate": "0x" + code[8:48]}
    try:
        t = uint_from_word(rpc.eth_call(a, S["getThreshold"]))
        owners = decode_owner_list(rpc.eth_call(a, S["getOwners"]))
    except Exception:  # noqa
        t, owners = None, None
    if t and owners and 0 < t <= len(owners):
        return {"kind": "Safe %d-of-%d" % (t, len(owners)), "keys": t, "owners": owners}
    return {"kind": "contract (not a Safe, signers not read)", "keys": None}


# ---------------------------------------------------------------- state
def dec_has(w):
    if not w or len(w) != 2 + 128:
        return None
    return int(w[2:66], 16) == 1, int(w[66:130], 16)


def inspect(rpc, cfg):
    mgr = cfg["manager"].lower()
    names = dict(FUSION_ROLES)
    names.update({int(k): v for k, v in cfg.get("role_names", {}).items()})
    rname = lambda r: names.get(r, "role%d" % r) if r != PUBLIC_ROLE else "PUBLIC"
    events, complete, note = get_events(rpc, cfg)
    pairs = []
    for k, r, a in events:
        if k == "grant" and (r, a) not in pairs:
            pairs.append((r, a))
    for r, a in cfg.get("holders_hint", []):
        if (int(r), a.lower()) not in pairs:
            pairs.append((int(r), a.lower()))
    members, gone, unknown = {}, [], []
    for r, a in pairs:
        h = dec_has(rpc.eth_call(mgr, S["hasRole"] + word(r) + pad_addr(a)))
        if h is None:
            unknown.append({"role": r, "account": a})
        elif h[0]:
            members.setdefault(r, []).append({"account": a, "delay": h[1]})
        else:
            gone.append({"role": r, "account": a})
    roles = sorted(set(r for r, _ in pairs))
    meta = {}
    for r in roles:
        meta[r] = {"admin": uint_from_word(rpc.eth_call(mgr, S["getRoleAdmin"] + word(r))),
                   "guardian": uint_from_word(rpc.eth_call(mgr, S["getRoleGuardian"] + word(r))),
                   "grant_delay": uint_from_word(rpc.eth_call(mgr, S["getRoleGrantDelay"] + word(r)))}
    role_rows = []
    for r in roles:
        rows = []
        for m in members.get(r, []):
            who = {"kind": "system contract", "keys": None} if is_tech(rname(r)) else classify(rpc, m["account"])
            rows.append(dict(m, who=who))
        role_rows.append({"role": r, "name": rname(r), "meta": meta[r], "members": rows})
    by_role = {x["role"]: x for x in role_rows}
    fn_rows = []
    for f in cfg.get("functions", []):
        c, sel = f["contract"].lower(), f["selector"].lower()
        rid = uint_from_word(rpc.eth_call(mgr, S["getTargetFunctionRole"] + pad_addr(c) + sel[2:] + "0" * 56))
        closed = uint_from_word(rpc.eth_call(mgr, S["isTargetClosed"] + pad_addr(c)))
        adm = uint_from_word(rpc.eth_call(mgr, S["getTargetAdminDelay"] + pad_addr(c)))
        row = {"label": f.get("label", c + " " + sel), "contract": c, "selector": sel, "role": rid,
               "role_name": rname(rid) if rid is not None else None,
               "target_closed": bool(closed) if closed is not None else None, "target_admin_delay": adm}
        if rid is None:
            row["verdict"] = "not read"
        elif rid == PUBLIC_ROLE:
            row["verdict"] = "PUBLIC: anyone can call"
        elif rid not in by_role:
            row["verdict"] = "role 0 = ADMIN/unset: no holder seen" if rid == 0 else "role %d: no holder seen" % rid
            row["holders"] = []
        else:
            hs = by_role[rid]["members"]
            if not hs:
                row["verdict"] = "role %s: nobody holds it now (nobody can call it)" % rname(rid)
            else:
                best = sorted(hs, key=lambda h: (h["delay"], h["who"]["keys"] if h["who"]["keys"] is not None else 99))[0]
                k = best["who"]["keys"]
                row["verdict"] = "fastest path: %s, delay %ds, %s" % (best["account"], best["delay"], ("%d key(s)" % k) if k is not None else "keys not read")
                row["instant_single_key"] = best["delay"] == 0 and k == 1
        fn_rows.append(row)
    return {"manager": mgr, "name": cfg.get("name", mgr), "log_note": note, "logs_complete": complete, "roles": role_rows,
            "revoked_or_gone": gone, "unreadable_pairs": unknown, "functions": fn_rows, "pairs_checked": len(pairs)}


# ---------------------------------------------------------------- report
def dur(s):
    return "0 (instant)" if s == 0 else "%ds (%.1f days)" % (s, s / 86400.0)


def render(res):
    out = ["### %s (%s)" % (res["name"], res["manager"]), "",
           "Logs: %s; log list %s; %d (role, account) pairs checked." % (res["log_note"], "complete" if res["logs_complete"] else "MAY BE INCOMPLETE", res["pairs_checked"]), "",
           "| role | holder now | what it is | min keys | delay | admin / guardian |", "|---|---|---|---|---|---|"]
    for r in res["roles"]:
        m = r["meta"]
        ag = "%s / %s" % (m["admin"], m["guardian"])
        if not r["members"]:
            out.append("| %s (%d) | nobody | - | - | - | %s |" % (r["name"], r["role"], ag))
        for h in r["members"]:
            w = h["who"]
            keys = "-" if w["keys"] is None else str(w["keys"])
            out.append("| %s (%d) | %s | %s | %s | %s | %s |" % (r["name"], r["role"], h["account"], w["kind"], keys, dur(h["delay"]), ag))
    if res["functions"]:
        out += ["", "| function | gated by | verdict | target closed | target admin delay |", "|---|---|---|---|---|"]
        for f in res["functions"]:
            out.append("| %s | %s | %s%s | %s | %s |" % (f["label"], ("%s (%s)" % (f["role_name"], f["role"])) if f["role"] is not None else "?", f["verdict"],
                                                         "  <-- SINGLE KEY, NO DELAY" if f.get("instant_single_key") else "", f["target_closed"], f["target_admin_delay"]))
    if res["revoked_or_gone"]:
        out += ["", "No longer holding (granted before, hasRole now false): " + ", ".join("%s r%d" % (g["account"][:10], g["role"]) for g in res["revoked_or_gone"])]
    out += ["", "Notes: 'plain key' = no code at the address; MPC/hardware/off-chain multisig behind a key is not visible. A Safe is read one level deep. "
            "Delay 0 means the holder can act without scheduling. A role nobody holds can still be re-granted by the holder of its admin role (see the admin column). "
            "This is a map of who can act and how fast, not a statement that anything is wrong."]
    return "\n".join(out)


def main(argv):
    if "--selftest" in argv:
        return selftest()
    path = argv[1] if len(argv) > 1 and not argv[1].startswith("--") else "targets.json"
    targets = json.load(open(path))
    pool, results = {}, []
    print("## Access manager report (read-only)\n")
    for t in targets:
        url = t.get("rpc") or os.environ.get("RPC_URL", DEFAULT_RPC)
        rpc = pool.setdefault(url, Rpc(url))
        try:
            res = inspect(rpc, t)
        except Exception as e:  # noqa
            res = {"manager": t["manager"].lower(), "name": t.get("name", t["manager"]), "log_note": "failed: %s" % str(e)[:100], "logs_complete": False,
                   "roles": [], "revoked_or_gone": [], "unreadable_pairs": [], "functions": [], "pairs_checked": 0}
        results.append(res)
        print(render(res))
        print()
    if "--json" in argv:
        json.dump(results, open(argv[argv.index("--json") + 1], "w"), indent=1, default=str)
    return 0


# ---------------------------------------------------------------- offline self test
class Fake(Rpc):
    """chain = {address: {"code": hex, "calls": {calldata: return_hex}}}"""
    def __init__(self, chain):
        super().__init__("fake")
        self.chain = chain

    def call(self, method, params, tries=4):
        if method == "eth_getCode":
            return self.chain.get(params[0], {}).get("code", "0x")
        if method == "eth_call":
            return self.chain.get(params[0]["to"], {}).get("calls", {}).get(params[0]["data"], "0x")
        if method == "eth_getLogs":
            v = self.chain.get(params[0]["address"], {}).get("logs")
            if v == "fail":
                raise ValueError("refused")
            return v
        raise ValueError("unsupported " + method)


def selftest():
    A = lambda n: "0x" + ("%040x" % n)
    eoa = {i: A(0x1000 + i) for i in range(8)}
    safe, mgr, tgt = A(0x2000), A(0x3000), A(0x4000)
    owners = [eoa[0], eoa[1], eoa[2]]
    enc = "0x" + word(32) + word(3) + "".join(pad_addr(o) for o in owners)
    chain = {safe: {"code": "0x60" + "00" * 40, "calls": {S["getThreshold"]: "0x" + word(2), S["getOwners"]: enc}}}
    mcalls = {}

    def has(r, a, member, delay):
        mcalls[S["hasRole"] + word(r) + pad_addr(a)] = "0x" + word(1 if member else 0) + word(delay)
    has(1, safe, True, 259200)       # OWNER: Safe 2-of-3, 3 days
    has(902, eoa[3], True, 0)        # fee role: one key, instant
    has(100, eoa[4], False, 0)       # revoked atomist
    has(3, tgt, True, 0)             # system role
    has(800, eoa[7], True, 0)        # whitelist: plain key
    chain[eoa[6]] = {"code": "0xef0100" + "ab" * 20}
    has(200, eoa[6], True, 0)        # alpha: key with a 7702 marker
    for r, adm, g in ((1, 1, 2), (902, 100, 2), (100, 1, 2), (3, 0, 0), (800, 100, 2), (200, 100, 2)):
        mcalls[S["getRoleAdmin"] + word(r)] = "0x" + word(adm)
        mcalls[S["getRoleGuardian"] + word(r)] = "0x" + word(g)
        mcalls[S["getRoleGrantDelay"] + word(r)] = "0x" + word(0)
    sels = {"0xdaf635de": 902, "0x11111111": 1, "0x22222222": 0, "0x33333333": PUBLIC_ROLE, "0x55555555": 100}
    for s_, r_ in sels.items():
        mcalls[S["getTargetFunctionRole"] + pad_addr(tgt) + s_[2:] + "0" * 56] = "0x" + word(r_)
    mcalls[S["isTargetClosed"] + pad_addr(tgt)] = "0x" + word(0)
    mcalls[S["getTargetAdminDelay"] + pad_addr(tgt)] = "0x" + word(0)
    chain[mgr] = {"code": "0x60" + "00" * 40, "calls": mcalls}
    chain[tgt] = {"code": "0x60" + "00" * 40}

    def lg(topic, role, who, blk, idx=0):
        return {"topics": [topic, "0x" + word(role), "0x" + word(int(who, 16))], "blockNumber": hex(blk), "logIndex": hex(idx)}
    logs = [lg(T_GRANT, 1, safe, 10), lg(T_GRANT, 902, eoa[3], 11), lg(T_GRANT, 100, eoa[4], 12), lg(T_REVOKE, 100, eoa[4], 13),
            lg(T_GRANT, 3, tgt, 14), lg(T_GRANT, 800, eoa[7], 15), lg(T_GRANT, 200, eoa[6], 16),
            {"topics": ["0x" + "ab" * 32, "0x" + word(1)], "blockNumber": "0x1"}]
    cfg = {"name": "test", "manager": mgr, "logs": logs, "functions": [
        {"label": "setFee", "contract": tgt, "selector": "0xdaf635de"}, {"label": "ownerOnly", "contract": tgt, "selector": "0x11111111"},
        {"label": "unset", "contract": tgt, "selector": "0x22222222"}, {"label": "open", "contract": tgt, "selector": "0x33333333"},
        {"label": "atomistOnly", "contract": tgt, "selector": "0x55555555"}]}
    res = inspect(Fake(chain), cfg)
    rows = {r["role"]: r for r in res["roles"]}
    assert res["logs_complete"] and res["pairs_checked"] == 6, res
    o = rows[1]["members"][0]
    assert o["delay"] == 259200 and o["who"]["keys"] == 2 and o["who"]["kind"] == "Safe 2-of-3" and o["who"]["owners"] == owners, o
    f = rows[902]["members"][0]
    assert f["delay"] == 0 and f["who"]["keys"] == 1 and f["who"]["kind"].startswith("plain key"), f
    assert rows[100]["members"] == [] and any(g["role"] == 100 for g in res["revoked_or_gone"])
    assert rows[3]["members"][0]["who"]["kind"] == "system contract"
    assert rows[200]["members"][0]["who"]["kind"] == "key with EIP-7702 delegation" and rows[200]["members"][0]["who"]["delegate"] == "0x" + "ab" * 20
    assert rows[902]["meta"]["admin"] == 100 and rows[902]["meta"]["guardian"] == 2
    fn = {x["label"]: x for x in res["functions"]}
    assert fn["setFee"].get("instant_single_key") is True and "delay 0s, 1 key" in fn["setFee"]["verdict"], fn["setFee"]
    assert "259200s" in fn["ownerOnly"]["verdict"] and "2 key" in fn["ownerOnly"]["verdict"] and not fn["ownerOnly"].get("instant_single_key")
    assert "ADMIN/unset" in fn["unset"]["verdict"] and fn["open"]["verdict"].startswith("PUBLIC")
    assert "nobody holds it now" in fn["atomistOnly"]["verdict"], fn["atomistOnly"]
    txt = render(res)
    assert "SINGLE KEY, NO DELAY" in txt and "OWNER (1)" in txt and "Safe 2-of-3" in txt and "nobody" in txt
    # no log source: holders_hint keeps the state read alive and the gap is reported
    res3 = inspect(Fake(chain), {"name": "hint", "manager": mgr, "rpc_logs": False, "holders_hint": [[902, eoa[3]]]})
    assert not res3["logs_complete"] and "holders_hint" in res3["log_note"] and res3["roles"][0]["members"][0]["delay"] == 0
    assert "MAY BE INCOMPLETE" in render(res3)
    # rpc getLogs refused -> reported, not hidden
    chain[A(0x3001)] = {"code": "0x60", "logs": "fail"}
    res4 = inspect(Fake(chain), {"name": "refused", "manager": A(0x3001)})
    assert not res4["logs_complete"] and "refused" in res4["log_note"], res4
    # explorer-shaped logs parse the same
    ex = [{"topics": [T_GRANT, "0x" + word(902), "0x" + word(int(eoa[3], 16))], "block_number": 7, "index": 2}]
    assert parse_events(ex) == [("grant", 902, eoa[3])]
    # Etherscan source: both topics queried, errors handled, the key never appears in a note
    global http_json
    real_http, os.environ["ETHERSCAN_API_KEY"] = http_json, "SECRETKEY123"
    calls = []

    def fake_http(url, tries=4):
        calls.append(url)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        if q["address"][0] == A(0x3002):
            return {"status": "0", "message": "NOTOK", "result": "Free API access is not supported for this chain SECRETKEY123"}
        if q["topic0"][0] == T_GRANT:
            return {"status": "1", "message": "OK", "result": [lg(T_GRANT, 902, eoa[3], 5), lg(T_GRANT, 1, safe, 6)]}
        return {"status": "0", "message": "No records found", "result": []}
    http_json = fake_http
    try:
        res5 = inspect(Fake(chain), {"name": "ether", "manager": mgr, "etherscan_chainid": 8453, "rpc_logs": False})
        assert res5["logs_complete"] and "etherscan v2 (2 role events)" in res5["log_note"] and res5["pairs_checked"] == 2, res5["log_note"]
        assert len(calls) == 2
        res6 = inspect(Fake(chain), {"name": "bad", "manager": A(0x3002), "etherscan_chainid": 8453, "rpc_logs": False})
        assert not res6["logs_complete"] and "SECRETKEY123" not in json.dumps(res6, default=str) and "etherscan failed" in res6["log_note"]
    finally:
        http_json = real_http
        os.environ.pop("ETHERSCAN_API_KEY", None)
    print("selftest ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
