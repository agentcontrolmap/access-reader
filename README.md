# access_reader

A small read-only script that answers one question for systems built on OpenZeppelin's `AccessManager`
(for example IPOR Fusion vaults): **who can do what, and how fast?**

For each manager it prints, from the chain:

- which roles exist and who holds each role right now (`hasRole`, not only history);
- the execution delay of each holder (0 = can act immediately, N = must schedule and wait N seconds);
- each role's admin role, guardian role and grant delay;
- what the holder is: a plain key, a key with an EIP-7702 delegation marker, a Safe (threshold and owners), or another contract;
- for functions you list: which role gates them and who can call them fastest.

It uses only `eth_call`, `eth_getCode` and public log APIs. It holds no keys and sends no transactions.

## Run

```
python3 access_reader.py --selftest                      # offline checks, no network
RPC_URL=https://your-rpc python3 access_reader.py targets.json
```

`targets.example.json` shows the format. Holders come from `RoleGranted` logs (an AccessManager cannot be enumerated from state).
Log sources, first that works: a saved JSON file, the Etherscan v2 API (free key in `ETHERSCAN_API_KEY`), a public Blockscout API,
or `eth_getLogs` on the RPC. You can also add candidates by hand with `holders_hint`. If the log list may be incomplete, the report says so.

### Log sources: what to expect

Public endpoints often refuse this kind of query. In a test run from a cloud runner, on Base: a free Etherscan v2 key was refused for that chain,
a public Blockscout instance answered 403, and a public RPC refused `eth_getLogs` from block 0. The script did not hide this. It printed
"log list MAY BE INCOMPLETE" and read the holders you gave in `holders_hint` (current state is still read from the chain with `eth_call`).
For a complete list of holders, use one of:

- a paid Etherscan v2 plan, or an RPC that serves `eth_getLogs` from block 0, or your own Blockscout instance;
- a JSON file of `RoleGranted`/`RoleRevoked` logs saved from an explorer or your node (`logs_file`);
- `holders_hint` with every account you already know about.

## What the report does not tell you

- "Plain key" means there is no code at the address. MPC, hardware wallets or an off-chain multisig behind a key are not visible.
- A Safe is read one level deep: its owners are listed, nested Safes are not expanded.
- A delay of 0 is the delay stored for that holder in the manager. A target can also have an admin delay or be closed; both are shown.
- Role names are the IPOR Fusion names unless you give your own in `role_names`; for other systems you see numbers.
- The report is a map of who can act and how fast. It is not a statement that anything is wrong.

## License

MIT, see `LICENSE`. Please keep the copyright notice when you copy or modify the code.
