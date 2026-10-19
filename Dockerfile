# =============================================================================
# AI-Driven Network Monitor — Docker image (headless / evaluation mode)
#
# Builds a slim image that can:
#   1. Run the headless self-test  (python test_detector.py)
#   2. Run the CICIDS2017 benchmark (python flow_eval/evaluate_cicids.py ...)
#   3. Run the engine in background / API mode (no GUI)
#
# NOTE: The PyQt5 GUI (gui.py) requires a display and is NOT included here.
#       To run the dashboard locally, install from requirements.txt on the host.
# =============================================================================

# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

# Keeps Python from buffering stdout/stderr (essential for Docker logs)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ── System dependencies ───────────────────────────────────────────────────────
# procps  → psutil needs /proc on Linux
# gcc     → some scikit-learn wheels need a C compiler as fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
        procps \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
COPY requirements-eval.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements-eval.txt

# ── Application code ──────────────────────────────────────────────────────────
COPY config.py collector.py detector.py simulator.py \
     engine.py mitigation.py storage.py test_detector.py ./
COPY flow_eval/ ./flow_eval/

# ── Default command: headless self-test ───────────────────────────────────────
# Override at runtime:
#   docker run --rm ai-network-monitor python flow_eval/evaluate_cicids.py --help
CMD ["python", "test_detector.py"]

# =============================================================================
# Build & run examples
# =============================================================================
# Build:
#   docker build -t ai-network-monitor .
#
# Headless self-test:
#   docker run --rm ai-network-monitor
#
# CICIDS2017 evaluation (mount your CSV directory):
#   docker run --rm \
#     -v "%cd%\flow_eval":/app/flow_eval \
#     -w /app/flow_eval \
#     ai-network-monitor \
#     python evaluate_cicids.py \
#       --train Monday-WorkingHours.pcap_ISCX.csv \
#       --test  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
#       --fpr 0.05 --baseline
#
# Interactive shell:
#   docker run --rm -it ai-network-monitor bash
# =============================================================================
