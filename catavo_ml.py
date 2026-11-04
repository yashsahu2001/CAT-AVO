"""CAT-AVO autoencoder (4-3-2-3-4). Run:  python catavo_ml.py   to train.
Other scripts can `from catavo_ml import load_model, score`."""
import argparse, json, os
import numpy as np
import pandas as pd
import torch
from torch import nn

DATA = r"C:\catavo-ml\data"
# login_hour is still logged but NOT used by the model: with only two time-of-day windows of lab data it caused
# false alarms on normal daytime logins (holdout FPR 6.1% vs 0%) without improving attack detection.
FEATURES = ["session_duration", "failed_before_login", "new_ip", "login_gap"]
N = len(FEATURES)


def prep(df):
    x = df[FEATURES].astype(float).copy()
    x["login_gap"] = np.log1p(x["login_gap"])      # tame the rare very long gap
    return x.values


class AE(nn.Module):
    def __init__(self):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(N, 3), nn.Tanh(), nn.Linear(3, 2), nn.Tanh())
        self.dec = nn.Sequential(nn.Linear(2, 3), nn.Tanh(), nn.Linear(3, N))

    def forward(self, x):
        return self.dec(self.enc(x))


def errors(model, x):
    with torch.no_grad():
        t = torch.tensor(x, dtype=torch.float32)
        return ((model(t) - t) ** 2).mean(dim=1).numpy()


def load_model():
    m = AE()
    m.load_state_dict(torch.load(os.path.join(DATA, "model.pt")))
    m.eval()
    sc = json.load(open(os.path.join(DATA, "scaler.json")))
    th = json.load(open(os.path.join(DATA, "threshold.json")))["threshold"]
    return m, np.array(sc["lo"]), np.array(sc["span"]), th


def score(df):
    """Return reconstruction error for each row of a feature DataFrame."""
    m, lo, span, th = load_model()
    return errors(m, (prep(df) - lo) / span), th


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=500)
    EPOCHS = ap.parse_args().epochs
    torch.manual_seed(42)
    np.random.seed(42)
    df = pd.read_csv(os.path.join(DATA, "features.csv"))
    x = prep(df)
    idx = np.random.permutation(len(x))
    cut = int(0.8 * len(x))
    tr, va = x[idx[:cut]], x[idx[cut:]]

    lo = tr.min(axis=0)
    span = tr.max(axis=0) - lo
    span[span == 0] = 1.0                           # constant feature (new_ip = 0)
    tr_s, va_s = (tr - lo) / span, (va - lo) / span

    model = AE()
    opt = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.MSELoss()
    xt = torch.tensor(tr_s, dtype=torch.float32)
    xv = torch.tensor(va_s, dtype=torch.float32)
    hist = []
    for ep in range(1, EPOCHS + 1):
        opt.zero_grad()
        loss = loss_fn(model(xt), xt)
        loss.backward()
        opt.step()
        with torch.no_grad():
            vloss = loss_fn(model(xv), xv).item()
        hist.append((ep, loss.item(), vloss))
        if ep == 1 or ep % (EPOCHS // 10) == 0:
            print(f"epoch {ep:3d}  train {loss.item():.5f}  val {vloss:.5f}")
    model.eval()

    e_tr, e_va = errors(model, tr_s), errors(model, va_s)
    thr = float(np.percentile(e_tr, 99))
    print(f"threshold (99th pct of training error) = {thr:.5f}")
    print(f"validation false-positive rate = {(e_va > thr).mean() * 100:.1f}%  ({(e_va > thr).sum()} of {len(e_va)})")
    print(f"error mean {e_tr.mean():.5f}  max {e_tr.max():.5f}")

    torch.save(model.state_dict(), os.path.join(DATA, "model.pt"))
    json.dump({"lo": lo.tolist(), "span": span.tolist()}, open(os.path.join(DATA, "scaler.json"), "w"))
    json.dump({"threshold": thr}, open(os.path.join(DATA, "threshold.json"), "w"))
    pd.DataFrame(hist, columns=["epoch", "train_loss", "val_loss"]).to_csv(os.path.join(DATA, "loss_history.csv"), index=False)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    h = pd.DataFrame(hist, columns=["epoch", "train", "val"])
    plt.plot(h.epoch, h.train, label="train")
    plt.plot(h.epoch, h.val, label="validation")
    plt.yscale("log")
    plt.xlabel("epoch")
    plt.ylabel("MSE loss")
    plt.title("Autoencoder training (4-3-2-3-4)")
    plt.legend()
    plt.savefig(os.path.join(DATA, "training_loss.png"), dpi=150, bbox_inches="tight")
    print("saved model.pt, scaler.json, threshold.json, training_loss.png in", DATA)
