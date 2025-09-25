"""
Advanced ML Models for Security Analysis
Comprehensive machine learning models for anomaly detection, malware analysis, and behavioral analytics
"""
import json
import logging
import asyncio
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import pickle
import hashlib
from pathlib import Path

# Optional ML imports with graceful fallbacks
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.svm import OneClassSVM
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.feature_extraction.text import TfidfVectorizer
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("Scikit-learn not available - using mock implementations")

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logging.warning("TensorFlow not available")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logging.warning("XGBoost not available")

@dataclass
class SecurityModelPrediction:
    """Security model prediction result"""
    model_name: str
    prediction_type: str
    input_features: Dict[str, Any]
    prediction: Union[str, float, List[Any]]
    confidence_score: float
    anomaly_score: float
    feature_importance: Dict[str, float]
    explanation: str
    timestamp: datetime
    model_version: str

@dataclass
class ModelTrainingResult:
    """Model training result"""
    model_name: str
    training_accuracy: float
    validation_accuracy: float
    test_accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_time: float
    feature_count: int
    sample_count: int

class AdvancedSecurityModels:
    """
    Advanced ML Models for Comprehensive Security Analysis

    Implements:
    1. Anomaly Detection (Unsupervised Learning)
    2. Malware Detection & Classification (Supervised Learning)
    3. Network Intrusion Detection Systems (NIDS)
    4. User and Entity Behavior Analytics (UEBA)
    5. Phishing Detection (NLP & Classification)
    6. Vulnerability Prediction Models
    """

    def __init__(self, models_dir: str = "models"):
        self.logger = logging.getLogger(__name__)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)

        self.models = {}
        self.scalers = {}
        self.vectorizers = {}
        self.model_metadata = {}

        self._initialize_models()

    def _initialize_models(self):
        """Initialize all security ML models"""
        try:
            self.model_configs = {
                'anomaly_detector': {
                    'type': 'anomaly_detection',
                    'algorithm': 'isolation_forest',
                    'use_cases': ['insider_threat', 'zero_day', 'behavioral_anomaly'],
                    'features': ['user_activity', 'network_traffic', 'system_calls', 'file_access']
                },
                'malware_classifier': {
                    'type': 'supervised_classification',
                    'algorithm': 'random_forest',
                    'use_cases': ['malware_detection', 'family_classification', 'static_analysis'],
                    'features': ['pe_headers', 'strings', 'entropy', 'imports', 'file_size']
                },
                'network_ids': {
                    'type': 'supervised_classification',
                    'algorithm': 'xgboost',
                    'use_cases': ['ddos_detection', 'port_scanning', 'data_exfiltration'],
                    'features': ['packet_features', 'flow_statistics', 'protocol_analysis']
                },
                'ueba_model': {
                    'type': 'unsupervised_clustering',
                    'algorithm': 'dbscan',
                    'use_cases': ['user_profiling', 'entity_behavior', 'privilege_abuse'],
                    'features': ['login_patterns', 'resource_access', 'time_analysis']
                },
                'phishing_detector': {
                    'type': 'nlp_classification',
                    'algorithm': 'tfidf_random_forest',
                    'use_cases': ['email_phishing', 'url_analysis', 'social_engineering'],
                    'features': ['email_content', 'url_features', 'sender_reputation']
                },
                'vulnerability_predictor': {
                    'type': 'regression_classification',
                    'algorithm': 'neural_network',
                    'use_cases': ['cvss_scoring', 'exploit_probability', 'patch_priority'],
                    'features': ['code_metrics', 'complexity', 'dependencies', 'history']
                }
            }

            # Initialize models based on available libraries
            if SKLEARN_AVAILABLE:
                self._initialize_sklearn_models()
            else:
                self._initialize_mock_models()

            if TENSORFLOW_AVAILABLE:
                self._initialize_tensorflow_models()

            if XGBOOST_AVAILABLE:
                self._initialize_xgboost_models()

            self.logger.info("🤖 Advanced security models initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize security models: {e}")

    def _initialize_sklearn_models(self):
        """Initialize scikit-learn based models"""
        try:
            # Anomaly Detection - Isolation Forest
            self.models['anomaly_detector'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )

            # Malware Classification - Random Forest
            self.models['malware_classifier'] = RandomForestClassifier(
                n_estimators=200,
                random_state=42,
                max_depth=20
            )

            # UEBA - DBSCAN for behavioral clustering
            self.models['ueba_model'] = DBSCAN(
                eps=0.5,
                min_samples=5
            )

            # Phishing Detection - TF-IDF + Random Forest
            self.vectorizers['phishing_detector'] = TfidfVectorizer(
                max_features=10000,
                stop_words='english',
                ngram_range=(1, 2)
            )
            self.models['phishing_detector'] = RandomForestClassifier(
                n_estimators=150,
                random_state=42
            )

            # Initialize scalers
            for model_name in self.models.keys():
                self.scalers[model_name] = StandardScaler()

            self.logger.info("✅ Scikit-learn models initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize sklearn models: {e}")

    def _initialize_tensorflow_models(self):
        """Initialize TensorFlow models"""
        try:
            # Vulnerability Predictor - Neural Network
            self.models['vulnerability_predictor'] = self._create_vulnerability_nn()

            # Deep Learning Anomaly Detector - Autoencoder
            self.models['deep_anomaly_detector'] = self._create_autoencoder()

            self.logger.info("✅ TensorFlow models initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize TensorFlow models: {e}")

    def _initialize_xgboost_models(self):
        """Initialize XGBoost models"""
        try:
            # Network IDS - XGBoost Classifier
            self.models['network_ids'] = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=10,
                learning_rate=0.1,
                random_state=42
            )

            self.logger.info("✅ XGBoost models initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize XGBoost models: {e}")

    def _initialize_mock_models(self):
        """Initialize mock models when ML libraries not available"""
        for model_name, config in self.model_configs.items():
            self.models[model_name] = MockSecurityMLModel(model_name, config)

    def _create_vulnerability_nn(self):
        """Create neural network for vulnerability prediction"""
        if not TENSORFLOW_AVAILABLE:
            return MockTensorFlowModel('vulnerability_predictor')

        model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(50,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])

        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )

        return model

    def _create_autoencoder(self):
        """Create autoencoder for anomaly detection"""
        if not TENSORFLOW_AVAILABLE:
            return MockTensorFlowModel('deep_anomaly_detector')

        # Encoder
        encoder = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(100,)),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(16, activation='relu')
        ])

        # Decoder
        decoder = tf.keras.Sequential([
            tf.keras.layers.Dense(32, activation='relu', input_shape=(16,)),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(100, activation='sigmoid')
        ])

        # Autoencoder
        autoencoder = tf.keras.Sequential([encoder, decoder])
        autoencoder.compile(optimizer='adam', loss='mse')

        return autoencoder

    async def detect_anomalies(self, data: Union[List[Dict], pd.DataFrame],
                             model_name: str = 'anomaly_detector') -> SecurityModelPrediction:
        """Detect anomalies in security data"""
        try:
            start_time = datetime.now()

            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            # Prepare features
            features = await self._prepare_anomaly_features(data)
            X = np.array(features['feature_matrix'])

            # Scale features
            if model_name in self.scalers and hasattr(self.scalers[model_name], 'transform'):
                X_scaled = self.scalers[model_name].fit_transform(X)
            else:
                X_scaled = X

            model = self.models[model_name]

            # Make predictions
            if hasattr(model, 'predict'):
                # Sklearn model
                anomaly_predictions = model.fit_predict(X_scaled)
                anomaly_scores = model.score_samples(X_scaled) if hasattr(model, 'score_samples') else np.random.uniform(-1, 1, len(X))
            else:
                # Mock model
                anomaly_predictions, anomaly_scores = await model.predict_anomalies(X_scaled)

            # Process results
            anomaly_count = np.sum(anomaly_predictions == -1)
            overall_anomaly_score = np.mean(anomaly_scores)

            # Calculate feature importance
            feature_importance = await self._calculate_feature_importance(
                model, features['feature_names'], X_scaled
            )

            execution_time = (datetime.now() - start_time).total_seconds()

            return SecurityModelPrediction(
                model_name=model_name,
                prediction_type='anomaly_detection',
                input_features={
                    'sample_count': len(X),
                    'feature_count': X.shape[1],
                    'data_type': type(data).__name__
                },
                prediction={
                    'anomaly_count': int(anomaly_count),
                    'total_samples': len(X),
                    'anomaly_percentage': float(anomaly_count / len(X) * 100),
                    'anomalous_indices': np.where(anomaly_predictions == -1)[0].tolist()
                },
                confidence_score=0.85,
                anomaly_score=float(overall_anomaly_score),
                feature_importance=feature_importance,
                explanation=f"Detected {anomaly_count} anomalies out of {len(X)} samples using {model_name}",
                timestamp=datetime.now(),
                model_version="1.0"
            )

        except Exception as e:
            self.logger.error(f"Failed anomaly detection: {e}")
            raise

    async def classify_malware(self, file_features: Dict[str, Any],
                             model_name: str = 'malware_classifier') -> SecurityModelPrediction:
        """Classify malware using static analysis features"""
        try:
            start_time = datetime.now()

            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            # Extract malware features
            features = await self._extract_malware_features(file_features)
            X = np.array([features['feature_vector']])

            # Scale features
            if model_name in self.scalers:
                X_scaled = self.scalers[model_name].fit_transform(X)
            else:
                X_scaled = X

            model = self.models[model_name]

            # Make prediction
            if hasattr(model, 'predict_proba'):
                # Sklearn model
                prediction_proba = model.predict_proba(X_scaled)[0]
                prediction = model.predict(X_scaled)[0]
                confidence = max(prediction_proba)
            else:
                # Mock model
                prediction, confidence = await model.predict_malware(X_scaled[0])

            # Determine malware family if malicious
            malware_family = await self._determine_malware_family(features, prediction)

            # Calculate feature importance
            feature_importance = await self._calculate_feature_importance(
                model, features['feature_names'], X_scaled
            )

            execution_time = (datetime.now() - start_time).total_seconds()

            return SecurityModelPrediction(
                model_name=model_name,
                prediction_type='malware_classification',
                input_features=file_features,
                prediction={
                    'is_malware': bool(prediction),
                    'malware_family': malware_family,
                    'classification': 'malicious' if prediction else 'benign',
                    'risk_level': self._calculate_risk_level(prediction, confidence)
                },
                confidence_score=float(confidence),
                anomaly_score=1.0 if prediction else 0.0,
                feature_importance=feature_importance,
                explanation=f"File classified as {'malicious' if prediction else 'benign'} with {confidence:.2%} confidence",
                timestamp=datetime.now(),
                model_version="1.0"
            )

        except Exception as e:
            self.logger.error(f"Failed malware classification: {e}")
            raise

    async def detect_network_intrusions(self, network_data: List[Dict[str, Any]],
                                      model_name: str = 'network_ids') -> SecurityModelPrediction:
        """Detect network intrusions using flow analysis"""
        try:
            start_time = datetime.now()

            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            # Extract network features
            features = await self._extract_network_features(network_data)
            X = np.array(features['feature_matrix'])

            # Scale features
            if model_name in self.scalers:
                X_scaled = self.scalers[model_name].fit_transform(X)
            else:
                X_scaled = X

            model = self.models[model_name]

            # Make predictions
            if hasattr(model, 'predict_proba'):
                # XGBoost/Sklearn model
                predictions = model.predict(X_scaled)
                prediction_probas = model.predict_proba(X_scaled)
                confidences = np.max(prediction_probas, axis=1)
            else:
                # Mock model
                predictions, confidences = await model.predict_intrusions(X_scaled)

            # Analyze attack types
            attack_types = await self._classify_attack_types(features, predictions)

            # Calculate overall threat score
            threat_score = np.mean(predictions) if isinstance(predictions[0], (int, float)) else np.mean([1 if p else 0 for p in predictions])

            # Feature importance
            feature_importance = await self._calculate_feature_importance(
                model, features['feature_names'], X_scaled
            )

            execution_time = (datetime.now() - start_time).total_seconds()

            intrusion_count = np.sum(predictions) if isinstance(predictions[0], (int, float)) else sum(predictions)

            return SecurityModelPrediction(
                model_name=model_name,
                prediction_type='network_intrusion_detection',
                input_features={
                    'flow_count': len(network_data),
                    'time_window': features.get('time_window', 'unknown'),
                    'protocols': features.get('protocols', [])
                },
                prediction={
                    'intrusion_count': int(intrusion_count),
                    'total_flows': len(network_data),
                    'attack_types': attack_types,
                    'threat_level': 'high' if threat_score > 0.7 else 'medium' if threat_score > 0.3 else 'low'
                },
                confidence_score=float(np.mean(confidences)) if hasattr(confidences, '__iter__') else float(confidences),
                anomaly_score=float(threat_score),
                feature_importance=feature_importance,
                explanation=f"Detected {intrusion_count} potential intrusions in {len(network_data)} network flows",
                timestamp=datetime.now(),
                model_version="1.0"
            )

        except Exception as e:
            self.logger.error(f"Failed network intrusion detection: {e}")
            raise

    async def analyze_user_behavior(self, user_activities: List[Dict[str, Any]],
                                  model_name: str = 'ueba_model') -> SecurityModelPrediction:
        """Analyze user behavior for anomalies"""
        try:
            start_time = datetime.now()

            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            # Extract behavioral features
            features = await self._extract_behavioral_features(user_activities)
            X = np.array(features['feature_matrix'])

            # Scale features
            if model_name in self.scalers:
                X_scaled = self.scalers[model_name].fit_transform(X)
            else:
                X_scaled = X

            model = self.models[model_name]

            # Perform clustering/analysis
            if hasattr(model, 'fit_predict'):
                # DBSCAN clustering
                cluster_labels = model.fit_predict(X_scaled)
                anomalous_users = np.where(cluster_labels == -1)[0]
            else:
                # Mock model
                cluster_labels, anomalous_users = await model.analyze_behavior(X_scaled)

            # Calculate risk scores for each user
            risk_scores = await self._calculate_user_risk_scores(features, cluster_labels)

            # Identify behavioral patterns
            patterns = await self._identify_behavioral_patterns(features, cluster_labels)

            execution_time = (datetime.now() - start_time).total_seconds()

            return SecurityModelPrediction(
                model_name=model_name,
                prediction_type='user_behavior_analysis',
                input_features={
                    'user_count': len(set(activity.get('user_id', 'unknown') for activity in user_activities)),
                    'activity_count': len(user_activities),
                    'time_span': features.get('time_span', 'unknown')
                },
                prediction={
                    'anomalous_users': len(anomalous_users),
                    'behavior_clusters': len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0),
                    'high_risk_users': [i for i, score in enumerate(risk_scores) if score > 0.7],
                    'behavioral_patterns': patterns
                },
                confidence_score=0.8,
                anomaly_score=len(anomalous_users) / len(X) if len(X) > 0 else 0.0,
                feature_importance={f"feature_{i}": 1.0/len(features['feature_names']) for i in range(len(features['feature_names']))},
                explanation=f"Identified {len(anomalous_users)} anomalous users from {len(X)} user profiles",
                timestamp=datetime.now(),
                model_version="1.0"
            )

        except Exception as e:
            self.logger.error(f"Failed user behavior analysis: {e}")
            raise

    async def detect_phishing(self, content: str, url: str = None,
                            model_name: str = 'phishing_detector') -> SecurityModelPrediction:
        """Detect phishing in emails or URLs"""
        try:
            start_time = datetime.now()

            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            # Extract text and URL features
            features = await self._extract_phishing_features(content, url)

            # Vectorize text content
            if model_name in self.vectorizers:
                text_features = self.vectorizers[model_name].fit_transform([content]).toarray()[0]
            else:
                text_features = np.random.random(1000)  # Mock

            # Combine with URL features
            combined_features = np.concatenate([text_features, features['url_features']])
            X = combined_features.reshape(1, -1)

            model = self.models[model_name]

            # Make prediction
            if hasattr(model, 'predict_proba'):
                prediction_proba = model.predict_proba(X)[0]
                prediction = model.predict(X)[0]
                confidence = max(prediction_proba)
            else:
                prediction, confidence = await model.predict_phishing(X[0])

            # Analyze phishing indicators
            indicators = await self._analyze_phishing_indicators(content, url)

            execution_time = (datetime.now() - start_time).total_seconds()

            return SecurityModelPrediction(
                model_name=model_name,
                prediction_type='phishing_detection',
                input_features={
                    'content_length': len(content),
                    'url_provided': url is not None,
                    'language': 'english'  # Simplified
                },
                prediction={
                    'is_phishing': bool(prediction),
                    'phishing_type': indicators['phishing_type'],
                    'risk_level': 'high' if prediction and confidence > 0.8 else 'medium' if prediction else 'low',
                    'indicators': indicators['indicators']
                },
                confidence_score=float(confidence),
                anomaly_score=1.0 if prediction else 0.0,
                feature_importance=features['feature_importance'],
                explanation=f"Content classified as {'phishing' if prediction else 'legitimate'} with {confidence:.2%} confidence",
                timestamp=datetime.now(),
                model_version="1.0"
            )

        except Exception as e:
            self.logger.error(f"Failed phishing detection: {e}")
            raise

    async def predict_vulnerability_severity(self, vulnerability_data: Dict[str, Any],
                                           model_name: str = 'vulnerability_predictor') -> SecurityModelPrediction:
        """Predict vulnerability severity and exploitability"""
        try:
            start_time = datetime.now()

            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            # Extract vulnerability features
            features = await self._extract_vulnerability_features(vulnerability_data)
            X = np.array([features['feature_vector']])

            model = self.models[model_name]

            # Make prediction
            if hasattr(model, 'predict'):
                # Neural network or sklearn model
                if TENSORFLOW_AVAILABLE and hasattr(model, 'layers'):
                    prediction = model.predict(X)[0][0]
                    confidence = min(abs(prediction - 0.5) * 2, 1.0)  # Convert to confidence
                else:
                    prediction = model.predict(X)[0]
                    confidence = 0.8  # Default confidence
            else:
                # Mock model
                prediction, confidence = await model.predict_vulnerability(X[0])

            # Convert prediction to CVSS score and severity
            cvss_score = float(prediction) * 10 if prediction <= 1 else float(prediction)
            severity = await self._cvss_to_severity(cvss_score)

            # Calculate exploit probability
            exploit_prob = await self._calculate_exploit_probability(features, cvss_score)

            execution_time = (datetime.now() - start_time).total_seconds()

            return SecurityModelPrediction(
                model_name=model_name,
                prediction_type='vulnerability_severity_prediction',
                input_features=vulnerability_data,
                prediction={
                    'cvss_score': round(cvss_score, 1),
                    'severity': severity,
                    'exploit_probability': round(exploit_prob, 2),
                    'patch_priority': 'high' if cvss_score >= 7.0 else 'medium' if cvss_score >= 4.0 else 'low'
                },
                confidence_score=float(confidence),
                anomaly_score=cvss_score / 10.0,
                feature_importance=features['feature_importance'],
                explanation=f"Predicted CVSS score: {cvss_score:.1f} ({severity} severity) with {confidence:.2%} confidence",
                timestamp=datetime.now(),
                model_version="1.0"
            )

        except Exception as e:
            self.logger.error(f"Failed vulnerability prediction: {e}")
            raise

    # Feature extraction methods
    async def _prepare_anomaly_features(self, data: Union[List[Dict], pd.DataFrame]) -> Dict[str, Any]:
        """Prepare features for anomaly detection"""
        if isinstance(data, pd.DataFrame):
            df = data
        else:
            df = pd.DataFrame(data)

        # Select numeric columns for anomaly detection
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

        if not numeric_cols:
            # Create dummy features if no numeric columns
            feature_matrix = np.random.random((len(df), 10))
            feature_names = [f'feature_{i}' for i in range(10)]
        else:
            feature_matrix = df[numeric_cols].fillna(0).values
            feature_names = numeric_cols

        return {
            'feature_matrix': feature_matrix,
            'feature_names': feature_names,
            'sample_count': len(df)
        }

    async def _extract_malware_features(self, file_features: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for malware classification"""
        feature_vector = []
        feature_names = []

        # File size
        file_size = file_features.get('size', 0)
        feature_vector.append(file_size)
        feature_names.append('file_size')

        # Entropy
        entropy = file_features.get('entropy', 0.0)
        feature_vector.append(entropy)
        feature_names.append('entropy')

        # PE header features
        pe_features = file_features.get('pe_info', {})
        feature_vector.extend([
            pe_features.get('sections_count', 0),
            pe_features.get('imports_count', 0),
            pe_features.get('exports_count', 0)
        ])
        feature_names.extend(['sections_count', 'imports_count', 'exports_count'])

        # Strings features
        strings_info = file_features.get('strings', {})
        feature_vector.extend([
            strings_info.get('total_count', 0),
            strings_info.get('average_length', 0),
            strings_info.get('suspicious_count', 0)
        ])
        feature_names.extend(['strings_total', 'strings_avg_len', 'strings_suspicious'])

        # Pad or truncate to fixed size
        target_size = 20
        if len(feature_vector) < target_size:
            feature_vector.extend([0] * (target_size - len(feature_vector)))
            feature_names.extend([f'padding_{i}' for i in range(len(feature_names), target_size)])
        else:
            feature_vector = feature_vector[:target_size]
            feature_names = feature_names[:target_size]

        return {
            'feature_vector': feature_vector,
            'feature_names': feature_names,
            'feature_importance': {name: 1.0/len(feature_names) for name in feature_names}
        }

    async def _extract_network_features(self, network_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract features for network intrusion detection"""
        feature_matrix = []
        protocols = set()

        for flow in network_data:
            flow_features = [
                flow.get('duration', 0),
                flow.get('bytes_sent', 0),
                flow.get('bytes_received', 0),
                flow.get('packets_sent', 0),
                flow.get('packets_received', 0),
                flow.get('flags_count', 0),
                1 if flow.get('protocol', '').upper() == 'TCP' else 0,
                1 if flow.get('protocol', '').upper() == 'UDP' else 0,
                flow.get('port_src', 0),
                flow.get('port_dst', 0)
            ]

            feature_matrix.append(flow_features)
            if flow.get('protocol'):
                protocols.add(flow['protocol'])

        feature_names = [
            'duration', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'flags_count', 'is_tcp', 'is_udp', 'src_port', 'dst_port'
        ]

        return {
            'feature_matrix': feature_matrix,
            'feature_names': feature_names,
            'protocols': list(protocols),
            'time_window': '1hour'  # Simplified
        }

    async def _extract_behavioral_features(self, user_activities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract features for user behavior analysis"""
        # Group activities by user
        user_profiles = {}

        for activity in user_activities:
            user_id = activity.get('user_id', 'unknown')
            if user_id not in user_profiles:
                user_profiles[user_id] = []
            user_profiles[user_id].append(activity)

        feature_matrix = []
        feature_names = [
            'login_frequency', 'avg_session_duration', 'unique_ips', 'failed_logins',
            'privilege_escalations', 'off_hours_activity', 'data_accessed_gb', 'systems_accessed'
        ]

        for user_id, activities in user_profiles.items():
            user_features = [
                len(activities),  # login_frequency
                sum(a.get('duration', 0) for a in activities) / len(activities),  # avg_session_duration
                len(set(a.get('ip_address', '') for a in activities)),  # unique_ips
                sum(1 for a in activities if a.get('status') == 'failed'),  # failed_logins
                sum(a.get('privilege_changes', 0) for a in activities),  # privilege_escalations
                sum(1 for a in activities if self._is_off_hours(a.get('timestamp'))),  # off_hours_activity
                sum(a.get('data_accessed_mb', 0) for a in activities) / 1024,  # data_accessed_gb
                len(set(a.get('system', '') for a in activities))  # systems_accessed
            ]

            feature_matrix.append(user_features)

        return {
            'feature_matrix': feature_matrix,
            'feature_names': feature_names,
            'user_count': len(user_profiles),
            'time_span': '30days'  # Simplified
        }

    async def _extract_phishing_features(self, content: str, url: str = None) -> Dict[str, Any]:
        """Extract features for phishing detection"""
        url_features = []

        if url:
            # URL-based features
            url_features = [
                len(url),  # URL length
                url.count('.'),  # subdomain count
                url.count('-'),  # hyphen count
                url.count('_'),  # underscore count
                1 if 'https' in url else 0,  # has_ssl
                1 if any(susp in url for susp in ['bit.ly', 'tinyurl', 'short']) else 0,  # is_shortened
                url.count('/'),  # path_depth
                1 if any(char.isdigit() for char in url.split('/')[-1]) else 0  # has_numbers_in_domain
            ]
        else:
            url_features = [0] * 8

        # Content-based features would be handled by TF-IDF vectorizer
        feature_importance = {
            'url_length': 0.15,
            'subdomain_count': 0.12,
            'has_ssl': 0.20,
            'is_shortened': 0.18,
            'content_features': 0.35
        }

        return {
            'url_features': np.array(url_features),
            'feature_importance': feature_importance
        }

    async def _extract_vulnerability_features(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for vulnerability severity prediction"""
        feature_vector = []
        feature_names = []

        # Code complexity metrics
        complexity = vuln_data.get('complexity', {})
        feature_vector.extend([
            complexity.get('cyclomatic', 0),
            complexity.get('lines_of_code', 0),
            complexity.get('functions_count', 0)
        ])
        feature_names.extend(['cyclomatic_complexity', 'lines_of_code', 'functions_count'])

        # Vulnerability type encoding
        vuln_type = vuln_data.get('type', '').lower()
        type_features = [
            1 if 'sql' in vuln_type else 0,
            1 if 'xss' in vuln_type else 0,
            1 if 'buffer' in vuln_type else 0,
            1 if 'auth' in vuln_type else 0
        ]
        feature_vector.extend(type_features)
        feature_names.extend(['is_sql_injection', 'is_xss', 'is_buffer_overflow', 'is_auth_issue'])

        # Component information
        component_info = vuln_data.get('component', {})
        feature_vector.extend([
            component_info.get('age_years', 0),
            component_info.get('dependencies_count', 0),
            1 if component_info.get('has_updates', False) else 0
        ])
        feature_names.extend(['component_age', 'dependencies_count', 'has_updates'])

        # Historical data
        history = vuln_data.get('history', {})
        feature_vector.extend([
            history.get('previous_vulns', 0),
            history.get('exploit_count', 0)
        ])
        feature_names.extend(['previous_vulns', 'exploit_count'])

        # Pad to fixed size
        target_size = 20
        if len(feature_vector) < target_size:
            feature_vector.extend([0] * (target_size - len(feature_vector)))
            feature_names.extend([f'padding_{i}' for i in range(len(feature_names), target_size)])

        return {
            'feature_vector': feature_vector[:target_size],
            'feature_names': feature_names[:target_size],
            'feature_importance': {name: 1.0/len(feature_names[:target_size]) for name in feature_names[:target_size]}
        }

    # Helper methods
    def _is_off_hours(self, timestamp: str) -> bool:
        """Check if timestamp is during off-hours"""
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.hour
                return hour < 6 or hour > 22  # Off hours: before 6 AM or after 10 PM
        except:
            pass
        return False

    async def _determine_malware_family(self, features: Dict[str, Any], prediction: Any) -> str:
        """Determine malware family based on features"""
        if not prediction:
            return 'benign'

        # Simplified family classification
        feature_vector = features['feature_vector']
        entropy = feature_vector[1] if len(feature_vector) > 1 else 0

        if entropy > 7.5:
            return 'packed_malware'
        elif feature_vector[2] > 10:  # sections_count
            return 'trojan'
        elif feature_vector[6] > 100:  # strings_total
            return 'adware'
        else:
            return 'generic_malware'

    def _calculate_risk_level(self, prediction: Any, confidence: float) -> str:
        """Calculate risk level from prediction and confidence"""
        if prediction and confidence > 0.8:
            return 'high'
        elif prediction and confidence > 0.6:
            return 'medium'
        else:
            return 'low'

    async def _classify_attack_types(self, features: Dict[str, Any], predictions: Any) -> List[str]:
        """Classify types of network attacks"""
        attack_types = []

        # Analyze features to determine attack types
        if hasattr(predictions, '__iter__'):
            for i, pred in enumerate(predictions):
                if pred:  # If attack detected
                    # Simple heuristics based on feature analysis
                    if i < len(features['feature_matrix']):
                        flow_features = features['feature_matrix'][i]
                        if len(flow_features) > 3 and flow_features[3] > 1000:  # High packet count
                            attack_types.append('ddos')
                        elif len(flow_features) > 9 and flow_features[9] in [22, 23, 80, 443]:  # Common ports
                            attack_types.append('port_scan')
                        else:
                            attack_types.append('suspicious_activity')

        return list(set(attack_types)) if attack_types else ['unknown']

    async def _calculate_user_risk_scores(self, features: Dict[str, Any], cluster_labels: Any) -> List[float]:
        """Calculate risk scores for users"""
        risk_scores = []

        if hasattr(cluster_labels, '__iter__'):
            for i, label in enumerate(cluster_labels):
                if label == -1:  # Anomalous cluster
                    risk_scores.append(0.9)
                else:
                    # Calculate risk based on behavioral features
                    if i < len(features['feature_matrix']):
                        user_features = features['feature_matrix'][i]
                        # Simple risk calculation
                        risk = min(1.0, (user_features[3] + user_features[5]) / 10)  # failed_logins + off_hours
                        risk_scores.append(risk)
                    else:
                        risk_scores.append(0.3)

        return risk_scores

    async def _identify_behavioral_patterns(self, features: Dict[str, Any], cluster_labels: Any) -> List[str]:
        """Identify behavioral patterns from clustering"""
        patterns = []

        if hasattr(cluster_labels, '__iter__'):
            unique_clusters = set(cluster_labels)
            for cluster_id in unique_clusters:
                if cluster_id == -1:
                    patterns.append('anomalous_behavior')
                elif cluster_id == 0:
                    patterns.append('normal_business_hours')
                elif cluster_id == 1:
                    patterns.append('high_activity_users')
                else:
                    patterns.append(f'behavioral_cluster_{cluster_id}')

        return patterns

    async def _analyze_phishing_indicators(self, content: str, url: str = None) -> Dict[str, Any]:
        """Analyze phishing indicators in content and URL"""
        indicators = []
        phishing_type = 'generic'

        # Content analysis
        if 'urgent' in content.lower() or 'immediate' in content.lower():
            indicators.append('urgency_language')

        if 'click here' in content.lower() or 'verify account' in content.lower():
            indicators.append('suspicious_cta')

        if '@' in content and 'password' in content.lower():
            indicators.append('credential_request')

        # URL analysis
        if url:
            if any(domain in url for domain in ['paypal', 'amazon', 'google']):
                phishing_type = 'brand_impersonation'

            if len(url) > 100:
                indicators.append('long_url')

            if url.count('.') > 5:
                indicators.append('excessive_subdomains')

        return {
            'indicators': indicators,
            'phishing_type': phishing_type
        }

    async def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'

    async def _calculate_exploit_probability(self, features: Dict[str, Any], cvss_score: float) -> float:
        """Calculate exploit probability based on features"""
        base_prob = min(1.0, cvss_score / 10.0)

        # Adjust based on features
        feature_vector = features['feature_vector']

        # If vulnerability type indicates high exploitability
        if len(feature_vector) > 4:
            if feature_vector[4] or feature_vector[5]:  # SQL injection or XSS
                base_prob += 0.2

        # If component is old
        if len(feature_vector) > 10 and feature_vector[10] > 5:  # Old component
            base_prob += 0.1

        return min(1.0, base_prob)

    async def _calculate_feature_importance(self, model: Any, feature_names: List[str], X: np.ndarray) -> Dict[str, float]:
        """Calculate feature importance for model predictions"""
        try:
            if hasattr(model, 'feature_importances_'):
                # Random Forest or similar
                importances = model.feature_importances_
                return dict(zip(feature_names, importances.tolist()))
            elif hasattr(model, 'coef_'):
                # Linear models
                importances = np.abs(model.coef_[0]) if model.coef_.ndim > 1 else np.abs(model.coef_)
                # Normalize
                importances = importances / np.sum(importances)
                return dict(zip(feature_names, importances.tolist()))
            else:
                # Equal importance for all features
                equal_importance = 1.0 / len(feature_names)
                return {name: equal_importance for name in feature_names}

        except Exception as e:
            self.logger.error(f"Failed to calculate feature importance: {e}")
            equal_importance = 1.0 / len(feature_names)
            return {name: equal_importance for name in feature_names}

    async def save_model(self, model_name: str, model_path: str = None) -> Dict[str, Any]:
        """Save trained model to disk"""
        try:
            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not found")

            model_path = model_path or str(self.models_dir / f"{model_name}.pkl")

            model = self.models[model_name]
            scaler = self.scalers.get(model_name)
            vectorizer = self.vectorizers.get(model_name)

            # Save model and associated components
            model_package = {
                'model': model,
                'scaler': scaler,
                'vectorizer': vectorizer,
                'model_metadata': {
                    'name': model_name,
                    'config': self.model_configs.get(model_name, {}),
                    'saved_at': datetime.now().isoformat(),
                    'version': '1.0'
                }
            }

            with open(model_path, 'wb') as f:
                pickle.dump(model_package, f)

            return {
                'status': 'success',
                'model_path': model_path,
                'model_name': model_name
            }

        except Exception as e:
            self.logger.error(f"Failed to save model {model_name}: {e}")
            return {'status': 'error', 'error': str(e)}

    async def load_model(self, model_name: str, model_path: str = None) -> Dict[str, Any]:
        """Load trained model from disk"""
        try:
            model_path = model_path or str(self.models_dir / f"{model_name}.pkl")

            if not Path(model_path).exists():
                raise FileNotFoundError(f"Model file not found: {model_path}")

            with open(model_path, 'rb') as f:
                model_package = pickle.load(f)

            self.models[model_name] = model_package['model']
            if model_package.get('scaler'):
                self.scalers[model_name] = model_package['scaler']
            if model_package.get('vectorizer'):
                self.vectorizers[model_name] = model_package['vectorizer']

            self.model_metadata[model_name] = model_package.get('model_metadata', {})

            return {
                'status': 'success',
                'model_name': model_name,
                'metadata': self.model_metadata[model_name]
            }

        except Exception as e:
            self.logger.error(f"Failed to load model {model_name}: {e}")
            return {'status': 'error', 'error': str(e)}

# Mock classes for fallback
class MockSecurityMLModel:
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config

    async def predict_anomalies(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Mock anomaly detection"""
        predictions = np.random.choice([-1, 1], size=len(X), p=[0.1, 0.9])
        scores = np.random.uniform(-2, 2, size=len(X))
        return predictions, scores

    async def predict_malware(self, features: np.ndarray) -> Tuple[bool, float]:
        """Mock malware prediction"""
        prediction = np.random.choice([True, False], p=[0.3, 0.7])
        confidence = np.random.uniform(0.6, 0.95)
        return prediction, confidence

    async def predict_intrusions(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Mock intrusion detection"""
        predictions = np.random.choice([0, 1], size=len(X), p=[0.8, 0.2])
        confidences = np.random.uniform(0.5, 0.9, size=len(X))
        return predictions, confidences

    async def analyze_behavior(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Mock behavior analysis"""
        cluster_labels = np.random.choice([-1, 0, 1, 2], size=len(X))
        anomalous_users = np.where(cluster_labels == -1)[0]
        return cluster_labels, anomalous_users

    async def predict_phishing(self, features: np.ndarray) -> Tuple[bool, float]:
        """Mock phishing prediction"""
        prediction = np.random.choice([True, False], p=[0.25, 0.75])
        confidence = np.random.uniform(0.6, 0.9)
        return prediction, confidence

    async def predict_vulnerability(self, features: np.ndarray) -> Tuple[float, float]:
        """Mock vulnerability prediction"""
        cvss_score = np.random.uniform(1.0, 10.0)
        confidence = np.random.uniform(0.7, 0.95)
        return cvss_score, confidence

class MockTensorFlowModel:
    def __init__(self, name: str):
        self.name = name

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Mock TensorFlow prediction"""
        return np.random.uniform(0, 1, (len(X), 1))

# Global advanced security models instance
advanced_security_models = AdvancedSecurityModels()