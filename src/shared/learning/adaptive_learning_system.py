"""
Advanced Adaptive Learning System for Security Testing
Integrates machine learning, pattern recognition, and continuous improvement
"""
import asyncio
import json
import sqlite3
import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import pickle
import hashlib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score
import pandas as pd

@dataclass
class LearningEvent:
    """Represents a learning event in the system"""
    event_id: str
    timestamp: datetime
    agent_type: str
    action_type: str
    context: Dict[str, Any]
    outcome: str
    success_score: float
    confidence: float
    metadata: Dict[str, Any]

@dataclass
class PatternInsight:
    """Represents discovered patterns and insights"""
    pattern_id: str
    pattern_type: str
    description: str
    confidence: float
    frequency: int
    success_rate: float
    recommendations: List[str]
    examples: List[str]

class AdaptiveLearningSystem:
    """Advanced learning system for continuous security improvement"""

    def __init__(self, db_path: str = "unified_learning.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.models = {}
        self.scalers = {}
        self.pattern_cache = {}
        self._initialize_database()
        self._load_models()

    def _initialize_database(self):
        """Initialize SQLite database for learning data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Learning events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS learning_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_type TEXT NOT NULL,
                action_type TEXT NOT NULL,
                context TEXT NOT NULL,
                outcome TEXT NOT NULL,
                success_score REAL NOT NULL,
                confidence REAL NOT NULL,
                metadata TEXT NOT NULL
            )
        ''')

        # Pattern insights table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pattern_insights (
                pattern_id TEXT PRIMARY KEY,
                pattern_type TEXT NOT NULL,
                description TEXT NOT NULL,
                confidence REAL NOT NULL,
                frequency INTEGER NOT NULL,
                success_rate REAL NOT NULL,
                recommendations TEXT NOT NULL,
                examples TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                metric_id TEXT PRIMARY KEY,
                agent_type TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                value REAL NOT NULL,
                timestamp TEXT NOT NULL,
                context TEXT NOT NULL
            )
        ''')

        # Adaptation strategies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS adaptation_strategies (
                strategy_id TEXT PRIMARY KEY,
                agent_type TEXT NOT NULL,
                strategy_type TEXT NOT NULL,
                parameters TEXT NOT NULL,
                effectiveness REAL NOT NULL,
                usage_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_used TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def _load_models(self):
        """Load pre-trained ML models"""
        models_dir = Path("unified-security-platform/shared/learning/models")
        models_dir.mkdir(parents=True, exist_ok=True)

        model_files = {
            'vulnerability_predictor': 'vuln_predictor.pkl',
            'pattern_classifier': 'pattern_classifier.pkl',
            'anomaly_detector': 'anomaly_detector.pkl',
            'success_predictor': 'success_predictor.pkl'
        }

        for model_name, filename in model_files.items():
            model_path = models_dir / filename
            if model_path.exists():
                try:
                    with open(model_path, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                    self.logger.info(f"Loaded model: {model_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load model {model_name}: {e}")
                    self._initialize_default_model(model_name)
            else:
                self._initialize_default_model(model_name)

    def _initialize_default_model(self, model_name: str):
        """Initialize default ML models"""
        if model_name == 'vulnerability_predictor':
            self.models[model_name] = RandomForestClassifier(n_estimators=100, random_state=42)
        elif model_name == 'pattern_classifier':
            self.models[model_name] = RandomForestClassifier(n_estimators=50, random_state=42)
        elif model_name == 'anomaly_detector':
            self.models[model_name] = IsolationForest(contamination=0.1, random_state=42)
        elif model_name == 'success_predictor':
            self.models[model_name] = RandomForestClassifier(n_estimators=75, random_state=42)

        self.scalers[model_name] = StandardScaler()

    async def record_learning_event(self, event: LearningEvent):
        """Record a learning event for future analysis"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO learning_events
                (event_id, timestamp, agent_type, action_type, context, outcome,
                 success_score, confidence, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id,
                event.timestamp.isoformat(),
                event.agent_type,
                event.action_type,
                json.dumps(event.context),
                event.outcome,
                event.success_score,
                event.confidence,
                json.dumps(event.metadata)
            ))

            conn.commit()
            conn.close()

            # Trigger pattern analysis if enough events
            await self._trigger_pattern_analysis()

        except Exception as e:
            self.logger.error(f"Failed to record learning event: {e}")

    async def _trigger_pattern_analysis(self):
        """Trigger pattern analysis when conditions are met"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM learning_events')
            event_count = cursor.fetchone()[0]

            conn.close()

            # Trigger analysis every 100 events
            if event_count % 100 == 0:
                await self.analyze_patterns()
                await self.update_adaptation_strategies()

        except Exception as e:
            self.logger.error(f"Failed to trigger pattern analysis: {e}")

    async def analyze_patterns(self) -> List[PatternInsight]:
        """Analyze patterns in learning events"""
        try:
            conn = sqlite3.connect(self.db_path)

            # Get recent events for analysis
            df = pd.read_sql_query('''
                SELECT * FROM learning_events
                WHERE timestamp > datetime('now', '-30 days')
                ORDER BY timestamp DESC
            ''', conn)

            conn.close()

            if df.empty:
                return []

            patterns = []

            # Analyze success patterns by agent type
            success_patterns = await self._analyze_success_patterns(df)
            patterns.extend(success_patterns)

            # Analyze temporal patterns
            temporal_patterns = await self._analyze_temporal_patterns(df)
            patterns.extend(temporal_patterns)

            # Analyze context patterns
            context_patterns = await self._analyze_context_patterns(df)
            patterns.extend(context_patterns)

            # Store patterns in database
            await self._store_patterns(patterns)

            return patterns

        except Exception as e:
            self.logger.error(f"Failed to analyze patterns: {e}")
            return []

    async def _analyze_success_patterns(self, df: pd.DataFrame) -> List[PatternInsight]:
        """Analyze success patterns by agent type and action"""
        patterns = []

        try:
            # Group by agent type and action type
            groups = df.groupby(['agent_type', 'action_type'])

            for (agent_type, action_type), group in groups:
                if len(group) < 5:  # Skip small samples
                    continue

                success_rate = group['success_score'].mean()
                confidence = group['confidence'].mean()
                frequency = len(group)

                if success_rate > 0.8:  # High success pattern
                    pattern = PatternInsight(
                        pattern_id=f"success_{agent_type}_{action_type}_{hash(f'{agent_type}{action_type}')}",
                        pattern_type="high_success",
                        description=f"High success rate ({success_rate:.2f}) for {action_type} in {agent_type}",
                        confidence=confidence,
                        frequency=frequency,
                        success_rate=success_rate,
                        recommendations=[
                            f"Prioritize {action_type} actions in {agent_type}",
                            f"Use similar context parameters for optimal results"
                        ],
                        examples=group['outcome'].head(3).tolist()
                    )
                    patterns.append(pattern)

                elif success_rate < 0.3:  # Low success pattern
                    pattern = PatternInsight(
                        pattern_id=f"failure_{agent_type}_{action_type}_{hash(f'{agent_type}{action_type}')}",
                        pattern_type="low_success",
                        description=f"Low success rate ({success_rate:.2f}) for {action_type} in {agent_type}",
                        confidence=confidence,
                        frequency=frequency,
                        success_rate=success_rate,
                        recommendations=[
                            f"Review and optimize {action_type} in {agent_type}",
                            f"Consider alternative approaches or additional training"
                        ],
                        examples=group['outcome'].head(3).tolist()
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            self.logger.error(f"Failed to analyze success patterns: {e}")
            return []

    async def _analyze_temporal_patterns(self, df: pd.DataFrame) -> List[PatternInsight]:
        """Analyze temporal patterns in agent behavior"""
        patterns = []

        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek

            # Analyze hourly patterns
            hourly_success = df.groupby('hour')['success_score'].mean()

            best_hours = hourly_success.nlargest(3)
            worst_hours = hourly_success.nsmallest(3)

            if len(best_hours) > 0:
                pattern = PatternInsight(
                    pattern_id=f"temporal_best_hours_{hash('best_hours')}",
                    pattern_type="temporal_optimization",
                    description=f"Highest success rates during hours: {list(best_hours.index)}",
                    confidence=0.8,
                    frequency=len(df[df['hour'].isin(best_hours.index)]),
                    success_rate=best_hours.mean(),
                    recommendations=[
                        "Schedule critical assessments during peak performance hours",
                        "Increase agent activity during high-success time windows"
                    ],
                    examples=[f"Hour {h}: {s:.2f} success rate" for h, s in best_hours.items()]
                )
                patterns.append(pattern)

            return patterns

        except Exception as e:
            self.logger.error(f"Failed to analyze temporal patterns: {e}")
            return []

    async def _analyze_context_patterns(self, df: pd.DataFrame) -> List[PatternInsight]:
        """Analyze context patterns for optimization"""
        patterns = []

        try:
            # Extract common context features
            context_features = []
            for _, row in df.iterrows():
                try:
                    context = json.loads(row['context'])
                    features = self._extract_context_features(context)
                    context_features.append(features)
                except:
                    continue

            if len(context_features) < 10:
                return patterns

            # Cluster similar contexts
            feature_matrix = np.array(context_features)

            if feature_matrix.shape[1] > 0:
                scaler = StandardScaler()
                scaled_features = scaler.fit_transform(feature_matrix)

                clusterer = DBSCAN(eps=0.5, min_samples=3)
                clusters = clusterer.fit_predict(scaled_features)

                df['cluster'] = clusters

                # Analyze cluster performance
                cluster_performance = df.groupby('cluster').agg({
                    'success_score': ['mean', 'count'],
                    'confidence': 'mean'
                }).round(3)

                for cluster_id, stats in cluster_performance.iterrows():
                    if cluster_id == -1 or stats[('success_score', 'count')] < 5:
                        continue

                    success_rate = stats[('success_score', 'mean')]
                    count = int(stats[('success_score', 'count')])
                    confidence = stats[('confidence', 'mean')]

                    if success_rate > 0.7:
                        pattern = PatternInsight(
                            pattern_id=f"context_cluster_{cluster_id}_{hash(str(cluster_id))}",
                            pattern_type="context_optimization",
                            description=f"Context cluster {cluster_id} shows high performance",
                            confidence=confidence,
                            frequency=count,
                            success_rate=success_rate,
                            recommendations=[
                                f"Replicate context patterns from cluster {cluster_id}",
                                "Apply similar parameter combinations for better results"
                            ],
                            examples=df[df['cluster'] == cluster_id]['outcome'].head(3).tolist()
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            self.logger.error(f"Failed to analyze context patterns: {e}")
            return []

    def _extract_context_features(self, context: Dict[str, Any]) -> List[float]:
        """Extract numerical features from context"""
        features = []

        # Extract common numerical features
        numeric_keys = ['timeout', 'threads', 'depth', 'iterations', 'confidence_threshold']
        for key in numeric_keys:
            if key in context:
                features.append(float(context[key]))
            else:
                features.append(0.0)

        # Extract boolean features
        bool_keys = ['aggressive', 'stealth', 'comprehensive', 'fast_mode']
        for key in bool_keys:
            if key in context:
                features.append(1.0 if context[key] else 0.0)
            else:
                features.append(0.0)

        # Extract categorical features (one-hot encoded)
        if 'mode' in context:
            modes = ['passive', 'active', 'comprehensive', 'targeted']
            for mode in modes:
                features.append(1.0 if context.get('mode') == mode else 0.0)
        else:
            features.extend([0.0] * 4)

        return features

    async def _store_patterns(self, patterns: List[PatternInsight]):
        """Store discovered patterns in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for pattern in patterns:
                cursor.execute('''
                    INSERT OR REPLACE INTO pattern_insights
                    (pattern_id, pattern_type, description, confidence, frequency,
                     success_rate, recommendations, examples, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.pattern_id,
                    pattern.pattern_type,
                    pattern.description,
                    pattern.confidence,
                    pattern.frequency,
                    pattern.success_rate,
                    json.dumps(pattern.recommendations),
                    json.dumps(pattern.examples),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store patterns: {e}")

    async def get_recommendations(self, agent_type: str, context: Dict[str, Any]) -> List[str]:
        """Get personalized recommendations based on learning"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get relevant patterns
            cursor.execute('''
                SELECT recommendations, confidence, success_rate FROM pattern_insights
                WHERE pattern_type IN ('high_success', 'context_optimization', 'temporal_optimization')
                AND confidence > 0.6
                ORDER BY success_rate DESC, confidence DESC
                LIMIT 10
            ''')

            results = cursor.fetchall()
            conn.close()

            recommendations = []
            for rec_json, confidence, success_rate in results:
                recs = json.loads(rec_json)
                for rec in recs:
                    if agent_type.lower() in rec.lower():
                        recommendations.append(f"[{success_rate:.2f}] {rec}")

            # Add general recommendations
            if not recommendations:
                recommendations = [
                    "Consider increasing scan depth for better coverage",
                    "Enable comprehensive mode for thorough analysis",
                    "Use parallel processing to improve performance",
                    "Implement result caching for repeated assessments"
                ]

            return recommendations[:5]  # Return top 5

        except Exception as e:
            self.logger.error(f"Failed to get recommendations: {e}")
            return ["Enable detailed logging for better learning"]

    async def predict_success(self, agent_type: str, action_type: str,
                            context: Dict[str, Any]) -> float:
        """Predict success probability for a given action"""
        try:
            # Use ML model if available and trained
            if 'success_predictor' in self.models and hasattr(self.models['success_predictor'], 'predict_proba'):
                features = self._extract_prediction_features(agent_type, action_type, context)
                if features:
                    scaled_features = self.scalers['success_predictor'].transform([features])
                    probability = self.models['success_predictor'].predict_proba(scaled_features)[0][1]
                    return float(probability)

            # Fallback to historical analysis
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT AVG(success_score) FROM learning_events
                WHERE agent_type = ? AND action_type = ?
                AND timestamp > datetime('now', '-7 days')
            ''', (agent_type, action_type))

            result = cursor.fetchone()
            conn.close()

            if result and result[0] is not None:
                return float(result[0])

            return 0.5  # Default neutral prediction

        except Exception as e:
            self.logger.error(f"Failed to predict success: {e}")
            return 0.5

    def _extract_prediction_features(self, agent_type: str, action_type: str,
                                   context: Dict[str, Any]) -> Optional[List[float]]:
        """Extract features for ML prediction"""
        try:
            features = []

            # Agent type encoding
            agent_types = ['reconnaissance', 'analysis', 'binary_security', 'reporting']
            for at in agent_types:
                features.append(1.0 if at in agent_type.lower() else 0.0)

            # Action type encoding
            action_types = ['scan', 'analyze', 'exploit', 'report', 'test']
            for act in action_types:
                features.append(1.0 if act in action_type.lower() else 0.0)

            # Context features
            context_features = self._extract_context_features(context)
            features.extend(context_features)

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract prediction features: {e}")
            return None

    async def update_adaptation_strategies(self):
        """Update adaptation strategies based on learning"""
        try:
            patterns = await self.get_recent_patterns()

            strategies = []

            for pattern in patterns:
                if pattern.pattern_type == "high_success" and pattern.success_rate > 0.8:
                    strategy = {
                        'strategy_type': 'parameter_optimization',
                        'parameters': {
                            'boost_priority': True,
                            'success_threshold': pattern.success_rate,
                            'context_hints': pattern.examples[:2]
                        },
                        'effectiveness': pattern.success_rate
                    }
                    strategies.append(strategy)

                elif pattern.pattern_type == "low_success" and pattern.success_rate < 0.3:
                    strategy = {
                        'strategy_type': 'approach_modification',
                        'parameters': {
                            'alternative_methods': True,
                            'additional_validation': True,
                            'timeout_increase': 1.5
                        },
                        'effectiveness': 1.0 - pattern.success_rate
                    }
                    strategies.append(strategy)

            # Store strategies
            await self._store_adaptation_strategies(strategies)

        except Exception as e:
            self.logger.error(f"Failed to update adaptation strategies: {e}")

    async def get_recent_patterns(self) -> List[PatternInsight]:
        """Get recent pattern insights"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM pattern_insights
                WHERE updated_at > datetime('now', '-7 days')
                ORDER BY success_rate DESC, confidence DESC
            ''')

            results = cursor.fetchall()
            conn.close()

            patterns = []
            for row in results:
                pattern = PatternInsight(
                    pattern_id=row[0],
                    pattern_type=row[1],
                    description=row[2],
                    confidence=row[3],
                    frequency=row[4],
                    success_rate=row[5],
                    recommendations=json.loads(row[6]),
                    examples=json.loads(row[7])
                )
                patterns.append(pattern)

            return patterns

        except Exception as e:
            self.logger.error(f"Failed to get recent patterns: {e}")
            return []

    async def _store_adaptation_strategies(self, strategies: List[Dict[str, Any]]):
        """Store adaptation strategies"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for strategy in strategies:
                strategy_id = hashlib.md5(
                    json.dumps(strategy, sort_keys=True).encode()
                ).hexdigest()

                cursor.execute('''
                    INSERT OR REPLACE INTO adaptation_strategies
                    (strategy_id, agent_type, strategy_type, parameters, effectiveness, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    strategy_id,
                    strategy.get('agent_type', 'general'),
                    strategy['strategy_type'],
                    json.dumps(strategy['parameters']),
                    strategy['effectiveness'],
                    datetime.now().isoformat()
                ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store adaptation strategies: {e}")

    async def generate_learning_report(self) -> Dict[str, Any]:
        """Generate comprehensive learning report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': {},
                'patterns': [],
                'recommendations': [],
                'performance_trends': {},
                'adaptation_strategies': []
            }

            conn = sqlite3.connect(self.db_path)

            # Summary statistics
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM learning_events')
            total_events = cursor.fetchone()[0]

            cursor.execute('''
                SELECT AVG(success_score), AVG(confidence) FROM learning_events
                WHERE timestamp > datetime('now', '-7 days')
            ''')
            recent_stats = cursor.fetchone()

            report['summary'] = {
                'total_learning_events': total_events,
                'recent_avg_success': recent_stats[0] or 0,
                'recent_avg_confidence': recent_stats[1] or 0
            }

            # Get patterns
            patterns = await self.get_recent_patterns()
            report['patterns'] = [asdict(p) for p in patterns[:10]]

            # Get recommendations
            recommendations = await self.get_recommendations('general', {})
            report['recommendations'] = recommendations

            # Performance trends
            cursor.execute('''
                SELECT agent_type, AVG(success_score) FROM learning_events
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY agent_type
            ''')

            trends = dict(cursor.fetchall())
            report['performance_trends'] = trends

            conn.close()

            return report

        except Exception as e:
            self.logger.error(f"Failed to generate learning report: {e}")
            return {'error': str(e)}

# Global learning system instance
learning_system = AdaptiveLearningSystem()