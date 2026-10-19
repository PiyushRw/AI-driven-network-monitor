"""MOCK data with the CICIDS2017 column layout, ONLY to smoke-test the code. Numbers are meaningless."""
import numpy as np, pandas as pd
from evaluate_cicids import BASE
rng = np.random.default_rng(1)

def block(n, attack):
    d = {c: rng.lognormal(4, 1, n) for c in BASE}
    if attack:
        d["Total Fwd Packets"] = rng.lognormal(2, .5, n); d["Total Backward Packets"] = rng.lognormal(.5, .5, n)
        d["Flow Packets/s"] = rng.lognormal(9, 1, n); d["SYN Flag Count"] = rng.integers(1, 3, n)
    else:
        d["SYN Flag Count"] = rng.integers(0, 2, n)
    df = pd.DataFrame(d); df.columns = [" " + c for c in df.columns]   # real files have leading spaces
    df[" Label"] = "DDoS" if attack else "BENIGN"
    return df

block(6000, False).to_csv("mock_monday.csv", index=False)
pd.concat([block(3000, False), block(1500, True)]).to_csv("mock_friday_ddos.csv", index=False)
print("wrote mock_monday.csv, mock_friday_ddos.csv")
