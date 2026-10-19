# CICIDS2017 evaluation

1. Download the **MachineLearningCVE** CSVs from the official CIC page (University of New Brunswick,
   "IDS 2017" dataset; check the page for the current link and terms). You need two files:
   - `Monday-WorkingHours.pcap_ISCX.csv`            (benign only -> training + calibration)
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (benign + DDoS -> test)
2. `pip install pandas scikit-learn joblib numpy`
3. `python evaluate_cicids.py --train Monday-WorkingHours.pcap_ISCX.csv --test Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --fpr 0.05 --baseline`

Outputs: `results.csv` (AUC, precision, recall, F1, FPR per model), per-label flagged share, `flow_detector.joblib`.
`make_mock_cicids.py` writes MOCK files only to smoke-test the code; never quote numbers from them.
