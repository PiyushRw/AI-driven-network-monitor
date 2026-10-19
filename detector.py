"""Ensemble anomaly detector: IsolationForest + One-Class SVM + LOF, majority vote."""
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
import config


class EnsembleDetector:
    def __init__(self):
        c = config.CONTAMINATION
        self.scaler = StandardScaler()
        self.models = {
            "iforest": IsolationForest(n_estimators=200, contamination=c, random_state=0),
            "ocsvm": OneClassSVM(kernel="rbf", gamma="scale", nu=max(c, 0.01)),
            "lof": LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=c),
        }
        self.fitted = False

    def fit(self, X):
        Xs = self.scaler.fit_transform(np.asarray(X, float))
        for m in self.models.values():
            m.fit(Xs)
        self.fitted = True

    def votes(self, x):
        xs = self.scaler.transform(np.asarray(x, float).reshape(1, -1))
        return {k: int(m.predict(xs)[0] == -1) for k, m in self.models.items()}  # 1 = anomalous

    def is_attack(self, x):
        v = self.votes(x)
        return sum(v.values()) >= config.VOTES_NEEDED, v

    def save(self, path=config.MODEL_PATH):
        joblib.dump(self, path)

    @staticmethod
    def load(path=config.MODEL_PATH):
        return joblib.load(path)
