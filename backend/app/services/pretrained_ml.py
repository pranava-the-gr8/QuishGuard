from pathlib import Path

import numpy as np
import onnxruntime as ort
from huggingface_hub import hf_hub_download


REPO_ID = "pirocheto/phishing-url-detection"
MODEL_FILE = "model.onnx"

_model_session = None


def get_model():
    global _model_session

    if _model_session is None:
        model_path = hf_hub_download(
            repo_id=REPO_ID,
            filename=MODEL_FILE
        )

        _model_session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"]
        )

    return _model_session


def analyze_pretrained_ml(url: str) -> dict:
    try:
        session = get_model()

        inputs = np.array([url], dtype="str")

        results = session.run(
            None,
            {"inputs": inputs}
        )

        probabilities = results[1][0]

        legitimate_probability = float(probabilities[0])
        phishing_probability = float(probabilities[1])

        prediction = 1 if phishing_probability >= legitimate_probability else 0

        return {
            "ml_score": round(phishing_probability * 100, 2),
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "phishing_probability": round(phishing_probability * 100, 2),
            "legitimate_probability": round(
                legitimate_probability * 100, 2
            ),
            "warning": (
                "Pretrained ML model detected phishing characteristics"
                if prediction == 1
                else None
            )
        }

    except Exception as error:
        return {
            "ml_score": None,
            "prediction": None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "warning": f"Pretrained ML analysis failed: {str(error)}"
        }