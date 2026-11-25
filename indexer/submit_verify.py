#!/usr/bin/env python3
"""Submit both testnet contracts to Etherscan V2 API (chainid=97) via standard-json input."""
import json, os, urllib.request, urllib.parse

ROOT = "/root/agent-passport"
KEY = [l.split("=", 1)[1].strip() for l in open("/root/.secrets/bscscan.env") if l.startswith("BSCSCAN_API_KEY")][0]

sources = {}
# resolved-path keys matching foundry's build unit IDs exactly
sources["src/PassportRegistry.sol"] = open(f"{ROOT}/src/PassportRegistry.sol").read()
sources["test/PassportRegistry.t.sol"] = open(f"{ROOT}/test/PassportRegistry.t.sol").read()
std = f"{ROOT}/lib/forge-std/src"
for dirpath, _, files in os.walk(std):
    for f in files:
        if f.endswith(".sol"):
            full = os.path.join(dirpath, f)
            rel = "lib/forge-std/src/" + os.path.relpath(full, std)
            sources[rel] = open(full).read()

solc_input = {
    "language": "Solidity",
    "sources": {k: {"content": v} for k, v in sources.items()},
    "settings": {
        "optimizer": {"enabled": False, "runs": 200},
        "evmVersion": "osaka",
        "remappings": ["forge-std/=lib/forge-std/src/"],
        "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
    },
}

CTOR = ("00000000000000000000000064033d308a098e1fAE80904Ee28604906D5DcF2d"
        "0000000000000000000000006CCd682f852FF61b1AC1fa88C291C3b44fDE609a")
JOBS = [
    ("0x64033d308a098e1fAE80904Ee28604906D5DcF2d", "test/PassportRegistry.t.sol:MockAgentID", ""),
    ("0x007618dCaD3d47D6C5c183c9A3FE29053dE47d13", "src/PassportRegistry.sol:PassportRegistry", CTOR),
]

guids = []
for addr, name, ctor in JOBS:
    payload = {
        "apikey": KEY, "module": "contract", "action": "verifysourcecode",
        "contractaddress": addr, "sourceCode": json.dumps(solc_input),
        "codeformat": "solidity-standard-json-input", "contractname": name,
        "compilerversion": "v0.8.37+commit.f401782d",
        "constructorArguements": ctor,  # etherscan's historical typo param
    }
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request("https://api.etherscan.io/v2/api?chainid=97", data=data,
                                 headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.loads(r.read())
    print(name, "->", out)
    if out.get("status") == "1":
        guids.append((name, out["result"]))

with open("/tmp/pp_verify_guids.txt", "w") as f:
    for name, g in guids:
        f.write(f"{name} {g}\n")
print("guids saved:", len(guids))
