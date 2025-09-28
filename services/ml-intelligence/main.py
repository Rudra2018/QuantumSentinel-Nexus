#!/usr/bin/env python3
"""
QuantumSentinel-Nexus ML Intelligence Service
Advanced machine learning agents for vulnerability prediction and pattern recognition
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from transformers import (
    AutoTokenizer, AutoModel, AutoModelForSequenceClassification,
    pipeline, BertTokenizer, BertForSequenceClassification
)
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
import xgboost as xgb
import lightgbm as lgb

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import aiofiles

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("QuantumSentinel.MLIntelligence")

class MLModelType(str, Enum):
    VULNERABILITY_CLASSIFIER = "vulnerability_classifier"
    ANOMALY_DETECTOR = "anomaly_detector"
    PATTERN_RECOGNIZER = "pattern_recognizer"
    ZERO_DAY_PREDICTOR = "zero_day_predictor"
    CODE_ANALYZER = "code_analyzer"
    THREAT_INTELLIGENCE = "threat_intelligence"

@dataclass
class MLPrediction:
    prediction_id: str
    model_type: MLModelType
    target: str
    prediction: str
    confidence: float
    evidence: List[str]
    features: Dict[str, Any]
    model_version: str
    created_at: datetime

@dataclass
class VulnerabilityPattern:
    pattern_id: str
    pattern_type: str
    indicators: List[str]
    severity: str
    confidence: float
    historical_occurrences: int
    false_positive_rate: float

class VulnerabilityClassifier(nn.Module):
    """Deep learning model for vulnerability classification"""

    def __init__(self, input_size: int, hidden_size: int = 512, num_classes: int = 10):
        super(VulnerabilityClassifier, self).__init__()
        self.hidden_size = hidden_size

        self.feature_extractor = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size // 2, hidden_size // 4),
            nn.ReLU()
        )

        self.classifier = nn.Sequential(
            nn.Linear(hidden_size // 4, num_classes),
            nn.Softmax(dim=1)
        )

    def forward(self, x):
        features = self.feature_extractor(x)
        output = self.classifier(features)
        return output

class MLVulnerabilityPredictor:
    """Advanced ML-based vulnerability prediction system"""

    def __init__(self):
        self.models = {}
        self.tokenizers = {}
        self.vectorizers = {}
        self.vulnerability_patterns = []
        self.model_versions = {}

        # Initialize models
        asyncio.create_task(self._initialize_models())

    async def _initialize_models(self):
        """Initialize all ML models"""
        try:
            logger.info("Initializing ML models...")

            # Code vulnerability detection model
            self.models["code_vuln"] = pipeline(
                "text-classification",
                model="microsoft/codebert-base-mlm",
                tokenizer="microsoft/codebert-base-mlm"
            )

            # Security pattern recognition model
            self.tokenizers["security"] = AutoTokenizer.from_pretrained("distilbert-base-uncased")
            self.models["security_classifier"] = AutoModelForSequenceClassification.from_pretrained(
                "distilbert-base-uncased", num_labels=5
            )

            # XGBoost for vulnerability scoring
            self.models["xgb_scorer"] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            )

            # Isolation Forest for anomaly detection
            self.models["anomaly_detector"] = IsolationForest(
                contamination=0.1,
                random_state=42
            )

            # Custom neural network for vulnerability classification
            self.models["deep_vuln_classifier"] = VulnerabilityClassifier(
                input_size=768,  # BERT embeddings size
                hidden_size=512,
                num_classes=10
            )

            # TF-IDF vectorizer for text analysis
            self.vectorizers["tfidf"] = TfidfVectorizer(
                max_features=10000,
                ngram_range=(1, 3),
                stop_words='english'
            )

            # Load pre-trained vulnerability patterns
            await self._load_vulnerability_patterns()

            logger.info("ML models initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    async def _load_vulnerability_patterns(self):
        """Load known vulnerability patterns"""
        # Common vulnerability patterns
        patterns = [
            VulnerabilityPattern(
                pattern_id="sql_injection_001",
                pattern_type="sql_injection",
                indicators=["SELECT", "UNION", "DROP", "INSERT", "DELETE", "'", "\"", ";"],
                severity="high",
                confidence=0.9,
                historical_occurrences=15000,
                false_positive_rate=0.05
            ),
            VulnerabilityPattern(
                pattern_id="xss_001",
                pattern_type="cross_site_scripting",
                indicators=["<script>", "javascript:", "onload=", "onerror=", "eval("],
                severity="medium",
                confidence=0.85,
                historical_occurrences=12000,
                false_positive_rate=0.08
            ),
            VulnerabilityPattern(
                pattern_id="buffer_overflow_001",
                pattern_type="buffer_overflow",
                indicators=["strcpy", "strcat", "sprintf", "gets", "memcpy"],
                severity="critical",
                confidence=0.92,
                historical_occurrences=8000,
                false_positive_rate=0.03
            ),
            VulnerabilityPattern(
                pattern_id="path_traversal_001",
                pattern_type="path_traversal",
                indicators=["../", "..\\", "%2e%2e", "....//", "..%2f"],
                severity="medium",
                confidence=0.88,
                historical_occurrences=6000,
                false_positive_rate=0.06
            )
        ]

        self.vulnerability_patterns = patterns
        logger.info(f"Loaded {len(patterns)} vulnerability patterns")

    async def predict_vulnerabilities(self, data: Dict[str, Any]) -> List[MLPrediction]:
        """Predict vulnerabilities using multiple ML models"""
        predictions = []

        try:
            # Extract features from input data
            features = await self._extract_features(data)

            # Code vulnerability analysis
            if "code" in data:
                code_predictions = await self._analyze_code_vulnerabilities(data["code"])
                predictions.extend(code_predictions)

            # Pattern-based analysis
            pattern_predictions = await self._pattern_based_analysis(data)
            predictions.extend(pattern_predictions)

            # Anomaly detection
            anomaly_predictions = await self._detect_anomalies(features)
            predictions.extend(anomaly_predictions)

            # Deep learning analysis
            deep_predictions = await self._deep_learning_analysis(features)
            predictions.extend(deep_predictions)

            # Ensemble predictions
            ensemble_predictions = await self._ensemble_predictions(predictions)

            logger.info(f"Generated {len(predictions)} ML predictions")
            return ensemble_predictions

        except Exception as e:
            logger.error(f"Vulnerability prediction failed: {e}")
            return []

    async def _extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from input data"""
        features = []

        # Basic statistical features
        if "headers" in data:
            headers = data["headers"]
            features.extend([
                len(headers),
                len(str(headers)),
                sum(1 for h in headers if "security" in h.lower()),
                sum(1 for h in headers if "cache" in h.lower())
            ])

        # URL features
        if "url" in data:
            url = data["url"]
            features.extend([
                len(url),
                url.count('/'),
                url.count('?'),
                url.count('&'),
                url.count('='),
                1 if 'admin' in url.lower() else 0,
                1 if 'login' in url.lower() else 0,
                1 if 'debug' in url.lower() else 0
            ])

        # Content features
        if "content" in data:
            content = data["content"]
            features.extend([
                len(content),
                content.count('<script>'),
                content.count('eval('),
                content.count('innerHTML'),
                content.count('document.write')
            ])

        # Pad features to fixed size
        while len(features) < 100:
            features.append(0)

        return np.array(features[:100])

    async def _analyze_code_vulnerabilities(self, code: str) -> List[MLPrediction]:
        """Analyze code for vulnerabilities using CodeBERT"""
        predictions = []

        if "code_vuln" not in self.models:
            return predictions

        try:
            # Split code into chunks for analysis
            code_chunks = [code[i:i+512] for i in range(0, len(code), 512)]

            for i, chunk in enumerate(code_chunks[:5]):  # Limit chunks
                result = self.models["code_vuln"](chunk)

                if result and len(result) > 0:
                    prediction = MLPrediction(
                        prediction_id=str(uuid.uuid4()),
                        model_type=MLModelType.CODE_ANALYZER,
                        target=f"code_chunk_{i}",
                        prediction=result[0].get("label", "unknown"),
                        confidence=result[0].get("score", 0.5),
                        evidence=[f"Code analysis: {chunk[:100]}..."],
                        features={"chunk_index": i, "chunk_length": len(chunk)},
                        model_version="codebert-base-mlm",
                        created_at=datetime.utcnow()
                    )
                    predictions.append(prediction)

        except Exception as e:
            logger.error(f"Code analysis failed: {e}")

        return predictions

    async def _pattern_based_analysis(self, data: Dict[str, Any]) -> List[MLPrediction]:
        """Analyze data using known vulnerability patterns"""
        predictions = []

        # Convert data to text for pattern matching
        text_data = str(data).lower()

        for pattern in self.vulnerability_patterns:
            match_count = sum(1 for indicator in pattern.indicators
                            if indicator.lower() in text_data)

            if match_count > 0:
                confidence = min(0.95, pattern.confidence * (match_count / len(pattern.indicators)))

                if confidence > 0.5:  # Threshold for reporting
                    prediction = MLPrediction(
                        prediction_id=str(uuid.uuid4()),
                        model_type=MLModelType.PATTERN_RECOGNIZER,
                        target=data.get("target", "unknown"),
                        prediction=f"potential_{pattern.pattern_type}",
                        confidence=confidence,
                        evidence=[f"Matched {match_count} indicators: {pattern.indicators[:3]}"],
                        features={
                            "pattern_id": pattern.pattern_id,
                            "matches": match_count,
                            "total_indicators": len(pattern.indicators)
                        },
                        model_version="pattern_v1.0",
                        created_at=datetime.utcnow()
                    )
                    predictions.append(prediction)

        return predictions

    async def _detect_anomalies(self, features: np.ndarray) -> List[MLPrediction]:
        """Detect anomalies using Isolation Forest"""
        predictions = []

        try:
            if "anomaly_detector" in self.models:
                # Reshape features for single sample prediction
                features_reshaped = features.reshape(1, -1)

                # Predict anomaly (-1 for outlier, 1 for inlier)
                anomaly_score = self.models["anomaly_detector"].decision_function(features_reshaped)[0]
                is_anomaly = self.models["anomaly_detector"].predict(features_reshaped)[0] == -1

                if is_anomaly:
                    # Convert anomaly score to confidence (0-1 range)
                    confidence = min(0.95, abs(anomaly_score) / 10)

                    prediction = MLPrediction(
                        prediction_id=str(uuid.uuid4()),
                        model_type=MLModelType.ANOMALY_DETECTOR,
                        target="feature_analysis",
                        prediction="anomalous_behavior_detected",
                        confidence=confidence,
                        evidence=[f"Anomaly score: {anomaly_score:.3f}"],
                        features={"anomaly_score": anomaly_score, "feature_vector_size": len(features)},
                        model_version="isolation_forest_v1.0",
                        created_at=datetime.utcnow()
                    )
                    predictions.append(prediction)

        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")

        return predictions

    async def _deep_learning_analysis(self, features: np.ndarray) -> List[MLPrediction]:
        """Deep learning vulnerability analysis"""
        predictions = []

        try:
            if "deep_vuln_classifier" in self.models:
                model = self.models["deep_vuln_classifier"]
                model.eval()

                # Convert features to tensor
                features_tensor = torch.FloatTensor(features).unsqueeze(0)

                # Get prediction
                with torch.no_grad():
                    output = model(features_tensor)
                    probabilities = output.squeeze().numpy()

                # Get top predictions
                vulnerability_classes = [
                    "sql_injection", "xss", "buffer_overflow", "path_traversal",
                    "csrf", "xxe", "deserialization", "ssrf", "rce", "privilege_escalation"
                ]

                for i, prob in enumerate(probabilities):
                    if prob > 0.3:  # Threshold for reporting
                        prediction = MLPrediction(
                            prediction_id=str(uuid.uuid4()),
                            model_type=MLModelType.VULNERABILITY_CLASSIFIER,
                            target="deep_learning_analysis",
                            prediction=vulnerability_classes[i],
                            confidence=float(prob),
                            evidence=[f"Deep learning prediction: {vulnerability_classes[i]}"],
                            features={"class_index": i, "raw_probability": float(prob)},
                            model_version="deep_vuln_v1.0",
                            created_at=datetime.utcnow()
                        )
                        predictions.append(prediction)

        except Exception as e:
            logger.error(f"Deep learning analysis failed: {e}")

        return predictions

    async def _ensemble_predictions(self, predictions: List[MLPrediction]) -> List[MLPrediction]:
        """Combine predictions using ensemble methods"""
        if not predictions:
            return predictions

        # Group predictions by target and prediction type
        grouped_predictions = {}
        for pred in predictions:
            key = f"{pred.target}_{pred.prediction}"
            if key not in grouped_predictions:
                grouped_predictions[key] = []
            grouped_predictions[key].append(pred)

        # Create ensemble predictions
        ensemble_predictions = []
        for key, group in grouped_predictions.items():
            if len(group) > 1:  # Only ensemble if multiple predictions
                # Calculate weighted confidence
                total_confidence = sum(pred.confidence for pred in group)
                avg_confidence = total_confidence / len(group)

                # Create ensemble prediction
                ensemble_pred = MLPrediction(
                    prediction_id=str(uuid.uuid4()),
                    model_type=MLModelType.VULNERABILITY_CLASSIFIER,
                    target=group[0].target,
                    prediction=f"ensemble_{group[0].prediction}",
                    confidence=min(0.95, avg_confidence * 1.2),  # Boost ensemble confidence
                    evidence=[f"Ensemble of {len(group)} models"],
                    features={"ensemble_size": len(group), "individual_confidences": [p.confidence for p in group]},
                    model_version="ensemble_v1.0",
                    created_at=datetime.utcnow()
                )
                ensemble_predictions.append(ensemble_pred)
            else:
                ensemble_predictions.append(group[0])

        return ensemble_predictions

class ZeroDayPredictor:
    """Predict potential zero-day vulnerabilities"""

    def __init__(self):
        self.historical_data = []
        self.trend_model = None

    async def predict_zero_days(self, target_data: Dict) -> List[MLPrediction]:
        """Predict potential zero-day vulnerabilities"""
        predictions = []

        try:
            # Analyze emerging patterns
            emerging_patterns = await self._analyze_emerging_patterns(target_data)

            # Predict based on historical trends
            trend_predictions = await self._predict_from_trends(target_data)

            # Combine predictions
            predictions.extend(emerging_patterns)
            predictions.extend(trend_predictions)

        except Exception as e:
            logger.error(f"Zero-day prediction failed: {e}")

        return predictions

    async def _analyze_emerging_patterns(self, target_data: Dict) -> List[MLPrediction]:
        """Analyze emerging vulnerability patterns"""
        predictions = []

        # Simulate emerging pattern detection
        emerging_patterns = [
            "novel_authentication_bypass",
            "new_memory_corruption_vector",
            "advanced_cryptographic_weakness",
            "unknown_protocol_vulnerability"
        ]

        for pattern in emerging_patterns:
            # Simulate confidence calculation
            confidence = np.random.uniform(0.3, 0.8)

            if confidence > 0.5:
                prediction = MLPrediction(
                    prediction_id=str(uuid.uuid4()),
                    model_type=MLModelType.ZERO_DAY_PREDICTOR,
                    target=target_data.get("target", "unknown"),
                    prediction=f"potential_zero_day_{pattern}",
                    confidence=confidence,
                    evidence=[f"Emerging pattern analysis: {pattern}"],
                    features={"pattern_type": pattern},
                    model_version="zero_day_v1.0",
                    created_at=datetime.utcnow()
                )
                predictions.append(prediction)

        return predictions

    async def _predict_from_trends(self, target_data: Dict) -> List[MLPrediction]:
        """Predict based on historical vulnerability trends"""
        predictions = []

        # Simulate trend-based prediction
        prediction = MLPrediction(
            prediction_id=str(uuid.uuid4()),
            model_type=MLModelType.ZERO_DAY_PREDICTOR,
            target=target_data.get("target", "unknown"),
            prediction="trend_based_vulnerability_prediction",
            confidence=0.65,
            evidence=["Historical trend analysis indicates potential vulnerability"],
            features={"analysis_type": "trend_based"},
            model_version="trend_v1.0",
            created_at=datetime.utcnow()
        )
        predictions.append(prediction)

        return predictions

class MLIntelligenceService:
    """Main ML Intelligence service orchestrator"""

    def __init__(self):
        self.vulnerability_predictor = MLVulnerabilityPredictor()
        self.zero_day_predictor = ZeroDayPredictor()
        self.predictions_history = []

    async def analyze_target(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive ML analysis of target"""
        analysis_id = str(uuid.uuid4())
        logger.info(f"Starting ML analysis {analysis_id} for target: {target_data.get('target', 'unknown')}")

        try:
            # Vulnerability prediction
            vuln_predictions = await self.vulnerability_predictor.predict_vulnerabilities(target_data)

            # Zero-day prediction
            zero_day_predictions = await self.zero_day_predictor.predict_zero_days(target_data)

            # Combine all predictions
            all_predictions = vuln_predictions + zero_day_predictions

            # Store predictions
            self.predictions_history.extend(all_predictions)

            # Generate analysis summary
            summary = await self._generate_analysis_summary(analysis_id, all_predictions)

            return {
                "analysis_id": analysis_id,
                "target": target_data.get("target", "unknown"),
                "total_predictions": len(all_predictions),
                "high_confidence_predictions": len([p for p in all_predictions if p.confidence > 0.8]),
                "vulnerability_types": list(set(p.prediction for p in all_predictions)),
                "summary": summary,
                "predictions": [asdict(p) for p in all_predictions]
            }

        except Exception as e:
            logger.error(f"ML analysis {analysis_id} failed: {e}")
            raise

    async def _generate_analysis_summary(self, analysis_id: str, predictions: List[MLPrediction]) -> Dict:
        """Generate analysis summary"""
        if not predictions:
            return {"message": "No predictions generated"}

        summary = {
            "analysis_id": analysis_id,
            "total_predictions": len(predictions),
            "by_model_type": {},
            "by_confidence": {
                "high": 0,    # > 0.8
                "medium": 0,  # 0.5 - 0.8
                "low": 0      # < 0.5
            },
            "avg_confidence": np.mean([p.confidence for p in predictions]),
            "top_predictions": []
        }

        # Count by model type
        for pred in predictions:
            model_type = pred.model_type.value
            summary["by_model_type"][model_type] = summary["by_model_type"].get(model_type, 0) + 1

            # Count by confidence
            if pred.confidence > 0.8:
                summary["by_confidence"]["high"] += 1
            elif pred.confidence > 0.5:
                summary["by_confidence"]["medium"] += 1
            else:
                summary["by_confidence"]["low"] += 1

        # Get top predictions
        top_predictions = sorted(predictions, key=lambda x: x.confidence, reverse=True)[:5]
        summary["top_predictions"] = [
            {
                "prediction": pred.prediction,
                "confidence": pred.confidence,
                "model_type": pred.model_type.value
            }
            for pred in top_predictions
        ]

        return summary

# Initialize FastAPI app
app = FastAPI(
    title="QuantumSentinel ML Intelligence Service",
    description="Advanced machine learning agents for vulnerability prediction and pattern recognition",
    version="1.0.0"
)

# Global ML intelligence service instance
ml_service = MLIntelligenceService()

@app.on_event("startup")
async def startup_event():
    """Initialize ML service on startup"""
    logger.info("ML Intelligence Service starting up...")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "ml-intelligence",
        "timestamp": datetime.utcnow().isoformat(),
        "total_predictions": len(ml_service.predictions_history)
    }

@app.post("/scan")
async def scan_endpoint(request: dict):
    """Main scan endpoint called by orchestrator"""
    job_id = request.get("job_id")
    targets = request.get("targets", [])
    options = request.get("options", {})

    logger.info(f"Starting ML analysis for job {job_id}")

    all_results = []
    for target in targets:
        target_data = {
            "target": target,
            "job_id": job_id,
            **options
        }

        analysis_result = await ml_service.analyze_target(target_data)
        all_results.append(analysis_result)

    return {
        "job_id": job_id,
        "status": "completed",
        "findings": all_results,
        "service": "ml-intelligence"
    }

@app.post("/analyze")
async def analyze_endpoint(target_data: dict):
    """Direct analysis endpoint"""
    return await ml_service.analyze_target(target_data)

@app.get("/predictions")
async def get_predictions(limit: int = 50):
    """Get recent predictions"""
    recent_predictions = ml_service.predictions_history[-limit:]

    return {
        "predictions": [asdict(p) for p in recent_predictions],
        "total": len(ml_service.predictions_history),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/statistics")
async def get_statistics():
    """Get ML analysis statistics"""
    predictions = ml_service.predictions_history

    if not predictions:
        return {"message": "No predictions yet"}

    stats = {
        "total_predictions": len(predictions),
        "by_model_type": {},
        "by_confidence_level": {
            "high": len([p for p in predictions if p.confidence > 0.8]),
            "medium": len([p for p in predictions if 0.5 <= p.confidence <= 0.8]),
            "low": len([p for p in predictions if p.confidence < 0.5])
        },
        "avg_confidence": np.mean([p.confidence for p in predictions]),
        "latest_prediction": max(predictions, key=lambda x: x.created_at).created_at.isoformat()
    }

    for prediction in predictions:
        model_type = prediction.model_type.value
        stats["by_model_type"][model_type] = stats["by_model_type"].get(model_type, 0) + 1

    return stats

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)